#!/usr/bin/env bash
# End-to-end test of the pipeline on roberto-server, using a throwaway local repository
# (file:// remote). Nothing is pushed to GitHub. Takes roughly 20-40 minutes on the laptop.
#   1. clean commit         -> develop PASSES, main deploys, passive DAST, release
#   2. vulnerable commit    -> develop is BLOCKED (secret + SAST + vulnerable dependency)
#   3. merge it into main   -> main is BLOCKED by the promotion check, production untouched
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER=$(dirname "$HERE")
T=${E2E_HOME:-$HOME/gmshield-ci-e2e}
rm -rf "$T"; mkdir -p "$T"
UP=$T/upstream.git; WC=$T/checkout
git init -q --bare -b main "$UP"
git clone -q "$UP" "$WC" 2>/dev/null
cp -r "$HERE/fixtures/sample-app/." "$WC/"
G() { git -C "$WC" -c user.name=e2e -c user.email=e2e@localhost "$@"; }
G add -A; G commit -qm "sample app"; G push -q origin HEAD:main HEAD:develop

cat > "$T/repos.toml" <<EOF
org = "local-e2e"
branches = ["develop", "main"]
registry = "localhost:5000"
prod_network = "rpg_default"
ci_slice = "ci.slice"
[[repo]]
name = "GMshield-sample"
url = "file://$UP"
EOF
export GMSHIELD_HOME=$T/home GMSHIELD_REPOS=$T/repos.toml
cd "$RUNNER"
result() { python3 -c "import json,sys;print(json.load(open('$T/home/state/state.json'))['GMshield-sample']['$1']['result'])"; }
check() { local got; got=$(result "$1"); if [ "$got" = "$2" ]; then echo "  OK   $1 = $got"; else echo "  FAIL $1 = $got (expected $2)"; FAILED=1; fi; }
FAILED=0

echo "== 1. clean commit"
python3 -m gmshield_ci poll
check develop passed
check main passed
curl -fsS http://127.0.0.1:18080/health >/dev/null && echo "  OK   production answers on 127.0.0.1:18080" || { echo "  FAIL production not reachable"; FAILED=1; }

echo "== 2. vulnerable commit on develop"
# Fake AWS-style credentials, generated at run time so no secret-looking literal lives in this repo.
KEY="AKIA$(head -c 64 /dev/urandom | tr -dc 'A-Z2-7' | head -c 16)"
SECRET="$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
printf 'AWS_ACCESS_KEY_ID = "%s"\nAWS_SECRET_ACCESS_KEY = "%s"\n' "$KEY" "$SECRET" > "$WC/settings.py"
printf 'import subprocess\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n' > "$WC/tools.py"
printf 'requests==2.19.0\nurllib3==1.24.1\n' > "$WC/requirements.txt"
G add -A; G commit -qm "vulnerable change"; G push -q origin HEAD:develop
python3 -m gmshield_ci poll
check develop failed

echo "== 3. merge the vulnerable code into main"
G push -q origin HEAD:main
python3 -m gmshield_ci poll
check main blocked
curl -fsS http://127.0.0.1:18080/health >/dev/null && echo "  OK   production still serves the previous release" || { echo "  FAIL production down"; FAILED=1; }

echo "== artifacts"
find "$T/home/artifacts" -maxdepth 3 -mindepth 3 | sort
docker rm -f gmshield-sample >/dev/null 2>&1 || true
[ "$FAILED" = 0 ] && echo "E2E PASSED" || { echo "E2E FAILED"; exit 1; }
