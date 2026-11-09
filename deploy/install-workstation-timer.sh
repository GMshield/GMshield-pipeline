#!/usr/bin/env bash
# Run on the workstation (WSL) to sync every 2 minutes while WSL is running:
# copies CI/CD reports into docs/artifacts and fast-forwards local develop/main.
#   bash deploy/install-workstation-timer.sh            # install and start
#   systemctl --user disable --now gmshield-sync.timer  # stop it later
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
install -D -m 755 "$HERE/workstation-sync.sh" "$HOME/.local/bin/gmshield-workstation-sync"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/gmshield-sync.service" <<'UNIT'
[Unit]
Description=GMshield: copy CI/CD reports to docs/artifacts and fast-forward local develop/main

[Service]
Type=oneshot
ExecStart=%h/.local/bin/gmshield-workstation-sync
TimeoutStartSec=10min
UNIT
cat > "$HOME/.config/systemd/user/gmshield-sync.timer" <<'UNIT'
[Unit]
Description=Run GMshield workstation sync every 2 minutes

[Timer]
OnCalendar=*:0/2
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now gmshield-sync.timer
systemctl --user list-timers gmshield-sync.timer --no-pager | head -2
