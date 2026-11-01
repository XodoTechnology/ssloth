use bmc_core::families::ilo4;
use bmc_core::ws;
use std::time::Duration;

fn main() {
    let host = "10.51.0.36";
    let sess = ilo4::login(host, "cloudie", "test@pass1").expect("login");
    for (chan, opencmd, tag) in [(0u8, 1u8, "KVM v5"), (1u8, 1u8, "CMD v5"), (0u8, 0u8, "KVM oc0")] {
        let sock = ws::connect(host, 443, "/wss/ircport", Some(&sess.key));
        let mut sock = match sock { Ok(s) => s, Err(e) => { println!("{tag}: ws fail {e}"); continue; } };
        let mut hello = [0u8; 54];
        hello[16] = opencmd;
        hello[17] = chan;
        hello[22..54].copy_from_slice(sess.key.as_bytes());
        let _ = sock.send_binary(&hello);
        match sock.recv(Duration::from_secs(8)) {
            Ok(m) => {
                let st = m.get(16).copied().unwrap_or(0);
                println!("{tag}: {}B status@16={st}", m.len());
                if st == 0 {
                    println!("{tag}: AUTHENTICATED — v5 console opens!");
                    for i in 0..3 {
                        match sock.recv(Duration::from_secs(5)) {
                            Ok(f) => println!("  f{i}: {}B", f.len()),
                            Err(e) => { println!("  f{i}: {e}"); break; }
                        }
                    }
                }
            }
            Err(e) => println!("{tag}: recv fail {e}"),
        }
    }
}
