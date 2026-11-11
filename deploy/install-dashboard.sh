#!/usr/bin/env bash
# GMshield CI/CD dashboard on roberto-server's own screen (tty1). Read-only: it only reads
# ~/gmshield-ci/state and ~/gmshield-ci/artifacts. The login prompt moves to tty2 (Ctrl+Alt+F2).
# Install:   sudo bash /home/roberto/install-dashboard.sh
# Remove:    sudo bash /home/roberto/install-dashboard.sh --remove
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
CI_USER=roberto
CI_HOME=/home/$CI_USER/gmshield-ci
DASH_TZ=${DASH_TZ:-America/Sao_Paulo}     # times on screen; the server itself stays on UTC
UNIT=/etc/systemd/system/gmshield-dashboard.service

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now gmshield-dashboard.service 2>/dev/null || true
  rm -f "$UNIT"
  systemctl unmask getty@tty1.service autovt@tty1.service
  systemctl daemon-reload
  systemctl start getty@tty1.service
  echo "REMOVED: tty1 shows the login prompt again"
  exit 0
fi

[ -f "/usr/share/zoneinfo/$DASH_TZ" ] || { echo "Unknown time zone $DASH_TZ"; exit 1; }

echo "==> 1/3 Service: draws the dashboard on tty1, restarts if it ever stops"
cat > "$UNIT" <<UNIT
[Unit]
Description=GMshield CI/CD dashboard on tty1 (read-only)
After=systemd-user-sessions.service getty@tty1.service
Conflicts=getty@tty1.service autovt@tty1.service
ConditionPathExists=$CI_HOME/runner/gmshield_ci/dashboard.py

[Service]
User=$CI_USER
Group=$CI_USER
Slice=ci.slice
WorkingDirectory=$CI_HOME/runner
Environment=PYTHONUNBUFFERED=1 TERM=linux TZ=$DASH_TZ
ExecStart=/usr/bin/python3 -m gmshield_ci dashboard
StandardInput=tty
StandardOutput=tty
StandardError=journal
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
Restart=always
RestartSec=5
MemoryMax=128M
CPUQuota=20%
Nice=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

echo "==> 2/3 Free tty1 (login stays available on tty2-tty6)"
systemctl stop getty@tty1.service 2>/dev/null || true
systemctl mask getty@tty1.service autovt@tty1.service

echo "==> 3/3 Enable and start"
systemctl daemon-reload
systemctl enable --now gmshield-dashboard.service
chvt 1 || true
sleep 2
systemctl is-active gmshield-dashboard.service
echo "DONE: the dashboard is on the laptop screen. Logs: journalctl -u gmshield-dashboard"
