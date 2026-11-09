#!/usr/bin/env bash
# GMshield CI/CD on roberto-server: one-time system setup.
# Run: sudo bash /home/roberto/install-ci.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
CI_USER=roberto
CI_HOME=/home/$CI_USER/gmshield-ci

echo "==> 1/4 Docker BuildKit (buildx): multi-stage builds, test stages, report export"
DEBIAN_FRONTEND=noninteractive apt-get -y -qq install docker-buildx >/dev/null
docker buildx version

echo "==> 2/4 ci.slice: CI jobs capped at 3 threads / 40% RAM, lower priority than the apps"
cat > /etc/systemd/system/ci.slice <<'UNIT'
[Unit]
Description=GMshield CI/CD jobs: builds, scanners, staging containers

[Slice]
CPUQuota=300%
CPUWeight=50
MemoryHigh=36%
MemoryMax=40%
UNIT

echo "==> 3/4 Poller: checks develop and main every minute"
cat > /etc/systemd/system/gmshield-ci.service <<UNIT
[Unit]
Description=GMshield CI/CD poller (develop and main)
After=network-online.target docker.service
Wants=network-online.target
# Skipped (not failed) until the runner is installed, or while CI is paused:
#   touch $CI_HOME/PAUSED   /   rm $CI_HOME/PAUSED
ConditionPathExists=$CI_HOME/runner/gmshield_ci/__main__.py
ConditionPathExists=!$CI_HOME/PAUSED

[Service]
Type=oneshot
User=$CI_USER
Group=$CI_USER
Slice=ci.slice
WorkingDirectory=$CI_HOME/runner
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m gmshield_ci poll
TimeoutStartSec=3h
Nice=5
UNIT
cat > /etc/systemd/system/gmshield-ci.timer <<'UNIT'
[Unit]
Description=Poll GitHub for develop/main changes every minute

[Timer]
# A poll that runs longer than a minute simply delays the next one (oneshot never overlaps).
OnCalendar=minutely
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT

echo "==> 4/4 Enable"
install -d -o "$CI_USER" -g "$CI_USER" "$CI_HOME"
systemctl daemon-reload
systemctl enable --now gmshield-ci.timer
systemctl list-timers gmshield-ci.timer --no-pager | head -3
echo "DONE"
