// ssh2 has no client-side OpenSSH certificate authentication: authPK writes a
// single algorithm name for both the public-key field and the signature field,
// but OpenSSH expects pkalg=<cert type> and sigalg=<underlying key type>.
// We patch the per-connection Protocol instance's authPK with an equivalent
// that separates the two. Only engaged when a credential supplies a
// certificate; plain key auth is untouched.
const { MESSAGE } = require('ssh2/lib/protocol/constants.js');
const {
  sendPacket,
  convertSignature,
  writeUInt32BE,
} = require('ssh2/lib/protocol/utils.js');
const { parseKey } = require('ssh2/lib/protocol/keyParser.js');

const CERT_SUFFIX = '-cert-v01@openssh.com';

// cert type -> signature algorithm to advertise inside the signature blob
function plainSigAlg(certType) {
  const base = certType.endsWith(CERT_SUFFIX)
    ? certType.slice(0, -CERT_SUFFIX.length)
    : certType;
  // modern servers disable ssh-rsa/sha1; rsa certs should advertise sha2
  return base === 'ssh-rsa' ? 'rsa-sha2-512' : base;
}

function sigHashFor(sigAlg) {
  if (sigAlg === 'rsa-sha2-512') return 'sha512';
  if (sigAlg === 'rsa-sha2-256') return 'sha256';
  return undefined;
}

// Wraps a parsed private key so ssh2 presents the certificate blob.
// certLine: "<type> <base64> [comment]" e.g. the contents of *-cert.pub
function makeCertKey(privateKeyParsed, certLine) {
  const parts = String(certLine).trim().split(/\s+/);
  if (parts.length < 2 || !parts[0].endsWith(CERT_SUFFIX))
    throw new Error('invalid certificate line (expected <type>-cert-v01@openssh.com <base64>)');
  const certType = parts[0];
  const certBlob = Buffer.from(parts[1], 'base64');
  // sanity: cert key type should match the private key's type
  const keyBase = certType.slice(0, -CERT_SUFFIX.length);
  if (privateKeyParsed.type !== keyBase)
    throw new Error(`certificate type ${certType} does not match private key type ${privateKeyParsed.type}`);
  privateKeyParsed.type = certType;
  privateKeyParsed.getPublicSSH = () => certBlob;
  // pin the sign() hash to the signature algorithm we will advertise —
  // ssh2 would otherwise sign RSA with sha1 while we claim rsa-sha2-512
  const sigAlg = plainSigAlg(certType);
  const hashAlgo = sigHashFor(sigAlg);
  const origSign = privateKeyParsed.sign.bind(privateKeyParsed);
  privateKeyParsed.sign = (buf) => origSign(buf, hashAlgo);
  privateKeyParsed.__sigAlg = sigAlg;
  return privateKeyParsed;
}

function authPKCert(proto, username, pubKey, keyAlgo, cbSign) {
  pubKey = parseKey(pubKey);
  if (pubKey instanceof Error)
    throw new Error('Invalid key');

  const keyType = pubKey.type;                    // e.g. ssh-ed25519-cert-v01@openssh.com
  const plainType = keyType.endsWith(CERT_SUFFIX)
    ? keyType.slice(0, -CERT_SUFFIX.length)
    : keyType;
  pubKey = pubKey.getPublicSSH();                 // full cert wire blob

  if (typeof keyAlgo === 'function') {
    cbSign = keyAlgo;
    keyAlgo = undefined;
  }
  if (!keyAlgo)
    keyAlgo = keyType;
  // The signature's algorithm name must be the *underlying* key type (or an
  // rsa-sha2 variant), not the certificate type.
  const sigAlg = plainSigAlg(keyAlgo);

  const userLen = Buffer.byteLength(username);
  const algoLen = Buffer.byteLength(keyAlgo);
  const pubKeyLen = pubKey.length;
  const sessionID = proto._kex.sessionID;
  const sesLen = sessionID.length;
  const payloadLen =
    (cbSign ? 4 + sesLen : 0)
      + 1 + 4 + userLen + 4 + 14 + 4 + 9 + 1 + 4 + algoLen + 4 + pubKeyLen;
  let packet;
  let p;
  if (cbSign) {
    packet = Buffer.allocUnsafe(payloadLen);
    p = 0;
    writeUInt32BE(packet, sesLen, p);
    packet.set(sessionID, p += 4);
    p += sesLen;
  } else {
    packet = proto._packetRW.write.alloc(payloadLen);
    p = proto._packetRW.write.allocStart;
  }

  packet[p] = MESSAGE.USERAUTH_REQUEST;

  writeUInt32BE(packet, userLen, ++p);
  packet.utf8Write(username, p += 4, userLen);

  writeUInt32BE(packet, 14, p += userLen);
  packet.utf8Write('ssh-connection', p += 4, 14);

  writeUInt32BE(packet, 9, p += 14);
  packet.utf8Write('publickey', p += 4, 9);

  packet[p += 9] = (cbSign ? 1 : 0);

  writeUInt32BE(packet, algoLen, ++p);
  packet.utf8Write(keyAlgo, p += 4, algoLen);

  writeUInt32BE(packet, pubKeyLen, p += algoLen);
  packet.set(pubKey, p += 4);

  if (!cbSign) {
    proto._authsQueue.push('publickey');
    proto._debug && proto._debug(
      'Outbound: Sending USERAUTH_REQUEST (publickey -- check)');
    sendPacket(proto, proto._packetRW.write.finalize(packet));
    return;
  }

  cbSign(packet, (signature) => {
    signature = convertSignature(signature, plainType);
    if (signature === false)
      throw new Error('Error while converting handshake signature');

    const sigAlgoLen = Buffer.byteLength(sigAlg);
    const sigLen = signature.length;
    p = proto._packetRW.write.allocStart;
    packet = proto._packetRW.write.alloc(
      1 + 4 + userLen + 4 + 14 + 4 + 9 + 1 + 4 + algoLen + 4 + pubKeyLen + 4
        + 4 + sigAlgoLen + 4 + sigLen
    );

    packet[p] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(packet, userLen, ++p);
    packet.utf8Write(username, p += 4, userLen);

    writeUInt32BE(packet, 14, p += userLen);
    packet.utf8Write('ssh-connection', p += 4, 14);

    writeUInt32BE(packet, 9, p += 14);
    packet.utf8Write('publickey', p += 4, 9);

    packet[p += 9] = 1;

    writeUInt32BE(packet, algoLen, ++p);
    packet.utf8Write(keyAlgo, p += 4, algoLen);

    writeUInt32BE(packet, pubKeyLen, p += algoLen);
    packet.set(pubKey, p += 4);

    writeUInt32BE(packet, 4 + sigAlgoLen + 4 + sigLen, p += pubKeyLen);

    writeUInt32BE(packet, sigAlgoLen, p += 4);
    packet.utf8Write(sigAlg, p += 4, sigAlgoLen);

    writeUInt32BE(packet, sigLen, p += sigAlgoLen);
    packet.set(signature, p += 4);

    proto._authsQueue.push('publickey');

    proto._debug && proto._debug('Outbound: Sending USERAUTH_REQUEST (publickey)');
    sendPacket(proto, proto._packetRW.write.finalize(packet));
  });
}

// Patch the protocol instance (created synchronously by conn.connect()).
function enableCertAuth(conn) {
  const proto = conn._protocol;
  if (!proto || proto.__sslothCertPatched) return;
  proto.__sslothCertPatched = true;
  proto.authPK = function (username, pubKey, keyAlgo, cbSign) {
    return authPKCert(proto, username, pubKey, keyAlgo, cbSign);
  };
}

module.exports = { makeCertKey, enableCertAuth };
