#!/usr/bin/with-contenv bash
# Enable TCP forwarding so tunnels and ProxyJump/bastion tests work.
CFG=/config/sshd/sshd_config
if ! grep -q '^AllowTcpForwarding' "$CFG" 2>/dev/null; then
  echo 'AllowTcpForwarding yes' >> "$CFG"
else
  sed -i 's/^AllowTcpForwarding.*/AllowTcpForwarding yes/' "$CFG"
fi
