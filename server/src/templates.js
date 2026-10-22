'use strict';

// Curated playbook templates — the "just set this up" catalog. Each is a
// playbook preset: name, description, and ordered steps (command + optional
// per-step timeout_s). Destructive/lockout-risk steps are opted into by
// including a 'confirm' note in the description so the UI can warn.
const TEMPLATES = [
  {
    key: 'sysreport',
    name: 'System report',
    description: 'uname, uptime, load, memory, disk — a quick health snapshot.',
    steps: [
      { command: 'uname -a; uptime', description: 'kernel + uptime', timeout_s: 15 },
      { command: 'free -h; df -h /', description: 'memory + disk', timeout_s: 15 },
      { command: 'last -n 5 -a 2>/dev/null | head -5', description: 'recent logins', timeout_s: 15 },
    ],
  },
  {
    key: 'updates',
    name: 'Apply system updates',
    description: 'apt/dnf/pacman update + upgrade (auto-detects the package manager).',
    steps: [
      {
        command:
          'if command -v apt-get >/dev/null; then sudo -n apt-get update && sudo -n apt-get -y upgrade; ' +
          'elif command -v dnf >/dev/null; then sudo -n dnf -y update; ' +
          'elif command -v pacman >/dev/null; then sudo -n pacman -Syu --noconfirm; ' +
          'else echo "no supported package manager"; exit 1; fi',
        description: 'update + upgrade',
        timeout_s: 600,
      },
      { command: 'command -v apt-get >/dev/null && sudo -n apt-get -y autoremove || true', description: 'autoremove', timeout_s: 120 },
    ],
  },
  {
    key: 'docker',
    name: 'Install Docker',
    description: 'Official convenience script + compose plugin + user group add.',
    steps: [
      { command: 'curl -fsSL https://get.docker.com | sudo -n sh', description: 'docker install script', timeout_s: 300 },
      { command: 'sudo -n usermod -aG docker $USER 2>/dev/null || true', description: 'add user to docker group', timeout_s: 15 },
      { command: 'docker --version && docker compose version 2>/dev/null || true', description: 'verify', timeout_s: 15 },
    ],
  },
  {
    key: 'newuser',
    name: 'Create deploy user',
    description: 'useradd + sudo + .ssh/authorized_keys scaffold (paste the pubkey in after, or edit the step).',
    steps: [
      { command: 'sudo -n useradd -m -s /bin/bash deploy 2>/dev/null || true', description: 'create user', timeout_s: 15 },
      { command: 'echo "deploy ALL=(ALL) NOPASSWD:ALL" | sudo -n tee /etc/sudoers.d/deploy', description: 'sudo rule', timeout_s: 15 },
      { command: 'sudo -n -u deploy mkdir -p ~deploy/.ssh && sudo -n -u deploy chmod 700 ~deploy/.ssh && sudo -n -u deploy touch ~deploy/.ssh/authorized_keys && sudo -n -u deploy chmod 600 ~deploy/.ssh/authorized_keys', description: 'ssh dir', timeout_s: 15 },
    ],
  },
  {
    key: 'harden',
    name: 'Harden SSH',
    description: 'Disable root login + password auth, install fail2ban. CONFIRM key auth works first — this edits sshd_config.',
    steps: [
      { command: 'sudo -n cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)', description: 'backup config', timeout_s: 15 },
      { command: 'sudo -n sed -i -E "s/^#?PermitRootLogin.*/PermitRootLogin no/; s/^#?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config', description: 'edit sshd_config', timeout_s: 15 },
      { command: 'sudo -n sshd -t && sudo -n systemctl reload ssh 2>/dev/null || sudo -n systemctl reload sshd', description: 'validate + reload', timeout_s: 30 },
      { command: 'command -v apt-get >/dev/null && sudo -n apt-get install -y fail2ban || true', description: 'fail2ban', timeout_s: 120 },
    ],
  },
  {
    key: 'diskclean',
    name: 'Disk cleanup',
    description: 'journald vacuum + package cache + dangling docker images.',
    steps: [
      { command: 'sudo -n journalctl --vacuum-time=7d 2>/dev/null || true', description: 'journal vacuum', timeout_s: 60 },
      { command: 'command -v apt-get >/dev/null && sudo -n apt-get clean && sudo -n apt-get -y autoremove || true', description: 'apt clean', timeout_s: 120 },
      { command: 'command -v docker >/dev/null && docker system prune -f || true', description: 'docker prune', timeout_s: 120 },
      { command: 'df -h /', description: 'report', timeout_s: 10 },
    ],
  },
  {
    key: 'node',
    name: 'Install Node.js LTS',
    description: 'NodeSource setup + install (Debian/Ubuntu) or dnf module (RHEL-likes).',
    steps: [
      {
        command:
          'if command -v apt-get >/dev/null; then curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -n bash - && sudo -n apt-get install -y nodejs; ' +
          'elif command -v dnf >/dev/null; then sudo -n dnf module install -y nodejs:22/common || sudo -n dnf install -y nodejs; ' +
          'else echo "unsupported distro"; exit 1; fi',
        description: 'install node',
        timeout_s: 300,
      },
      { command: 'node --version && npm --version', description: 'verify', timeout_s: 15 },
    ],
  },
  {
    key: 'backup',
    name: 'Tarball a directory',
    description: 'tar a directory to /tmp/backups with a timestamped name. Edit DIR first.',
    steps: [
      { command: 'mkdir -p /tmp/ssloth-backups', description: 'ensure target', timeout_s: 10 },
      { command: 'DIR=/var/www; sudo -n tar czf /tmp/ssloth-backups/$(basename $DIR)-$(date +%Y%m%d-%H%M).tar.gz -C $(dirname $DIR) $(basename $DIR) 2>/dev/null || tar czf /tmp/ssloth-backups/$(basename $DIR)-$(date +%Y%m%d-%H%M).tar.gz -C $(dirname $DIR) $(basename $DIR)', description: 'tar', timeout_s: 600 },
      { command: 'ls -lh /tmp/ssloth-backups/', description: 'list backups', timeout_s: 10 },
    ],
  },
];

module.exports = { TEMPLATES };
