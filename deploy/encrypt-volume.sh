#!/usr/bin/env bash
# GMshield on roberto-server: put everything persistent on one TPM-unlocked encrypted volume
# (AD-24, Story 1.5). A removed disk then exposes nothing: the stores, the secrets, the certificates,
# the CI home, Docker's and containerd's data and swap are all encrypted.
#
#   bash deploy/encrypt-volume.sh plan          changes nothing: the space it needs and each step's state
#   sudo bash deploy/encrypt-volume.sh setup    creates the volume, copies every store onto it, encrypted swap
#   (reboot)
#   sudo bash deploy/encrypt-volume.sh finish   proves the new layout, then deletes the plain-text copies
#   sudo bash deploy/encrypt-volume.sh status   the state of every step and check
#
# Add --dry-run to setup or finish to print each command that would change something instead of
# running it. Every step checks first whether it is already done, so a rerun resumes where a failed
# run stopped. Until finish succeeds the plain-text originals stay intact under <path>.plain.
# Do not pipe setup through tee or a logger: it prints the recovery key once.
set -euo pipefail
umask 022

# GMSHIELD_ROOT exists for the tests only: every file path below is taken relative to it.
R=${GMSHIELD_ROOT:-}
p() { printf '%s%s' "$R" "$1"; }

VOL=gmshield
CONTAINER=/var/lib/gmshield/volume.luks
VOL_GIB=150
MNT=/srv/gmshield
MAPPER=/dev/mapper/$VOL
VG=ubuntu-vg
SWAP_LV=gmshield_swap
SWAP=cryptswap
SWAP_GIB=4
OLD_SWAP=/swap.img
STATE=/var/lib/gmshield/encrypt-volume
SETUP_KEY=/run/gmshield-setup.key
MIN_FREE_GIB=60
CI_USER=roberto
UHOME=/home/$CI_USER
GIB=1073741824
# <subfolder on the volume>:<path it is bind-mounted back onto>
STORES=("docker:/var/lib/docker" "containerd:/var/lib/containerd" "gmshield-ci:$UHOME/gmshield-ci"
        "stack:$UHOME/stack" "config-gmshield:$UHOME/.config/gmshield")
DROPIN_UNITS=(docker.service containerd.service gmshield-ci.service gmshield-dashboard.service)
# Units stopped for the copy, in this order, and started again afterwards (only those that were active).
STOP_UNITS=(gmshield-ci.timer ai-healthcheck.timer gmshield-ci.service ai-healthcheck.service
            gmshield-dashboard.service docker.socket docker.service containerd.service)
HEALTHY=(postgres redis)      # must report (healthy)
RUNNING=(qdrant registry)     # must be up
TOOLS=(cryptsetup systemd-cryptenroll rsync fallocate lvcreate lvs vgs swapon swapoff findmnt mount
       mkfs.ext4 blkid systemctl journalctl docker du df stat shred fstrim awk)

CRYPTTAB_VOL="$VOL $(p "$CONTAINER") none luks,tpm2-device=auto,headless=true,nofail"
CRYPTTAB_SWAP="$SWAP /dev/$VG/$SWAP_LV /dev/urandom swap,plain,cipher=aes-xts-plain64,size=512,nofail"
FSTAB_VOL="$MAPPER $(p "$MNT") ext4 defaults,nofail 0 2"
FSTAB_SWAP="/dev/mapper/$SWAP none swap sw,nofail 0 0"

DRY=0
CMD=""
for arg in "$@"; do
  case $arg in
    --dry-run) DRY=1 ;;
    plan|setup|finish|status) CMD=$arg ;;
    *) echo "Usage: $0 {plan|setup|finish|status} [--dry-run]" >&2; exit 2 ;;
  esac
done
[ -n "$CMD" ] || { echo "Usage: $0 {plan|setup|finish|status} [--dry-run]" >&2; exit 2; }

# ---------- helpers ----------
CUR=""; CUR_NAME=""; TOTAL=0; SERVICES_STOPPED=0

die() { echo "    $*" >&2; exit 1; }
run() { if [ "$DRY" = 1 ]; then printf '    + %s\n' "$*"; else "$@"; fi; }
gib() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1073741824 }'; }
is_root() { [ "$(id -u)" -eq 0 ]; }

backup_once() {   # keep the file as it was before this script first touched it
  local f; f=$(p "$1")
  [ -e "$f.before-gmshield" ] || run cp -a "$f" "$f.before-gmshield"
}
has_line() { grep -qxF -- "$2" "$(p "$1")" 2>/dev/null; }
ensure_line() {   # ensure_line /etc/fstab "<line>"
  local f; f=$(p "$1")
  has_line "$1" "$2" && return 0
  backup_once "$1"
  if [ "$DRY" = 1 ]; then printf '    + append to %s: %s\n' "$f" "$2"; return 0; fi
  if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
  printf '%s\n' "$2" >> "$f"
}
write_file() {    # write_file <path> < content (mode 644)
  local f content; f=$(p "$1"); content=$(cat)
  if [ "$DRY" = 1 ]; then printf '    + write %s:\n' "$f"; printf '%s\n' "$content" | sed 's/^/        /'; return 0; fi
  mkdir -p "$(dirname "$f")"
  printf '%s\n' "$content" > "$f.tmp"; chmod 644 "$f.tmp"; mv "$f.tmp" "$f"
}
active() { systemctl is-active --quiet "$1"; }
boot_id() { cat "$(p /proc/sys/kernel/random/boot_id)"; }

slot_types() {    # the key slot types of the container (password, tpm2, recovery, ...); needs root
  local out; out=$(systemd-cryptenroll "$(p "$CONTAINER")" 2>/dev/null) || return 1
  awk 'NR > 1 { print $2 }' <<<"$out" | sort -u
}
has_slot() { local t; t=$(slot_types) || return 1; grep -qx "$1" <<<"$t"; }

store_sub() { printf '%s' "${1%%:*}"; }
store_path() { printf '%s' "${1#*:}"; }
store_switched() {  # store_switched <sub> <path>: the path is the bind mount of the volume's subfolder
  [ "$(findmnt -n -o SOURCE --mountpoint "$(p "$2")" 2>/dev/null)" = "$MAPPER[/$1]" ]
}
all_switched() {
  local s; for s in "${STORES[@]}"; do store_switched "$(store_sub "$s")" "$(store_path "$s")" || return 1; done
}
store_src() {       # where the plain-text data of a store is now
  local path; path=$(p "$1")
  if [ -e "$path.plain" ]; then printf '%s' "$path.plain"; else printf '%s' "$path"; fi
}
half_switched() {   # a store moved to .plain whose bind mount is not active: services must stay down
  local s path
  for s in "${STORES[@]}"; do
    path=$(store_path "$s")
    if [ -e "$(p "$path").plain" ] && ! store_switched "$(store_sub "$s")" "$path"; then echo "$path"; fi
  done
}
volume_mounted() { [ "$(findmnt -n -o SOURCE --mountpoint "$(p "$MNT")" 2>/dev/null)" = "$MAPPER" ]; }
swap_active() {
  local dev; dev=$(readlink -m "/dev/mapper/$SWAP")
  swapon --show=NAME --noheadings --raw 2>/dev/null | grep -qxF -e "$dev" -e "/dev/mapper/$SWAP"
}
old_swap_active() { swapon --show=NAME --noheadings --raw 2>/dev/null | grep -qxF "$(p "$OLD_SWAP")"; }
fstab_active_entry() { awk -v t="$1" '$1 == t { f = 1 } END { exit !f }' "$(p /etc/fstab)" 2>/dev/null; }
lv_exists() { lvs --noheadings -o lv_name "$VG" 2>/dev/null | awk '{ print $1 }' | grep -qx "$SWAP_LV"; }

dropin_file() { printf '/etc/systemd/system/%s.d/gmshield-volume.conf' "$1"; }
dropin_content() {
  local paths="" x
  case $1 in
    docker.service) set -- "$MNT" /var/lib/docker "$UHOME/stack" "$UHOME/gmshield-ci" ;;
    containerd.service) set -- "$MNT" /var/lib/containerd ;;
    gmshield-ci.service) set -- "$MNT" "$UHOME/gmshield-ci" "$UHOME/.config/gmshield" "$UHOME/stack" ;;
    gmshield-dashboard.service) set -- "$MNT" "$UHOME/gmshield-ci" ;;
  esac
  for x in "$@"; do paths="$paths $(p "$x")"; done
  printf '%s\n' "# Written by GMshield-pipeline deploy/encrypt-volume.sh (Story 1.5)." \
    "# Never start on empty folders: wait for the encrypted volume and its bind mounts." \
    "[Unit]" "RequiresMountsFor=${paths# }"
}

stack_problems() {  # prints what is wrong with the data stack; nothing when it is healthy
  local ps n; ps=$(docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null) || { echo "docker does not answer"; return; }
  for n in "${HEALTHY[@]}"; do grep -qE "^$n Up .*\(healthy\)" <<<"$ps" || echo "$n is not healthy"; done
  for n in "${RUNNING[@]}"; do grep -qE "^$n Up" <<<"$ps" || echo "$n is not up"; done
}

# ---------- services ----------
services_down() {
  local u; for u in docker.socket docker.service containerd.service gmshield-dashboard.service gmshield-ci.timer; do
    if active "$u"; then return 1; fi
  done
}
stop_services() {
  local st u ids waited=0
  st=$(p "$STATE")
  run mkdir -p "$st"
  if [ ! -s "$st/units" ]; then                # a rerun never overwrites what the first stop recorded
    local up=""; for u in "${STOP_UNITS[@]}"; do if active "$u"; then up="$up$u"$'\n'; fi; done
    if [ "$DRY" = 1 ]; then echo "    + record active units: $(echo "$up" | xargs)"; else printf '%s' "$up" > "$st/units"; fi
  fi
  [ "$DRY" = 1 ] || SERVICES_STOPPED=1
  run rm -f "$st/copied"
  run systemctl stop gmshield-ci.timer ai-healthcheck.timer
  if [ "$DRY" = 0 ]; then                      # let a pipeline run in progress finish (up to 15 minutes)
    while active gmshield-ci.service && [ "$waited" -lt 900 ]; do
      [ "$waited" -eq 0 ] && echo "    waiting for the running pipeline poll to finish"
      sleep 5; waited=$((waited + 5))
    done
  fi
  run systemctl stop gmshield-ci.service ai-healthcheck.service gmshield-dashboard.service
  if active docker.service; then
    ids=$(docker ps -q)
    if [ ! -s "$st/containers" ] && [ -n "$ids" ]; then
      if [ "$DRY" = 1 ]; then echo "    + record running containers: $(echo "$ids" | xargs)"; else printf '%s\n' "$ids" > "$st/containers"; fi
    fi
    # live-restore would keep containers running without Docker, so they are stopped one by one
    # shellcheck disable=SC2086
    if [ -n "$ids" ]; then run docker stop -t 60 $ids; fi
  fi
  run systemctl stop docker.socket docker.service containerd.service
}
start_services() {
  local st u units=""
  st=$(p "$STATE")
  run systemctl daemon-reload
  run systemctl start containerd.service docker.socket docker.service
  if [ -s "$st/containers" ]; then
    # shellcheck disable=SC2046
    run docker start $(cat "$st/containers")
  fi
  if [ -s "$st/units" ]; then
    while read -r u; do
      case $u in docker.*|containerd.service|gmshield-ci.service|ai-healthcheck.service|"") ;; *) units="$units $u" ;; esac
    done < "$st/units"
  else
    for u in gmshield-dashboard.service ai-healthcheck.timer gmshield-ci.timer; do
      if systemctl cat "$u" >/dev/null 2>&1; then units="$units $u"; fi
    done
  fi
  # shellcheck disable=SC2086
  if [ -n "$units" ]; then run systemctl start $units; fi
  SERVICES_STOPPED=0
}
wait_healthy() {
  local i problems=""
  [ "$DRY" = 1 ] && { echo "    + wait until postgres and redis are healthy, qdrant and registry up"; return 0; }
  for i in $(seq 1 36); do
    problems=$(stack_problems)
    [ -z "$problems" ] && { echo "    data stack healthy"; return 0; }
    if [ "$i" -lt 36 ]; then sleep 5; fi
  done
  die "data stack not healthy after 3 minutes: $(echo "$problems" | xargs)"
}

on_exit() {
  local rc=$? half
  trap - EXIT
  [ "$rc" -eq 0 ] && exit 0
  [ -n "$CUR" ] && echo "FAILED at step $CUR: $CUR_NAME" >&2
  if [ "$SERVICES_STOPPED" = 1 ]; then
    set +e
    half=$(half_switched)
    if [ -n "$half" ]; then
      echo "Services stay stopped: $(echo "$half" | xargs) is between its original and the volume." >&2
      echo "Rerun setup to finish the switch (the original is intact under <path>.plain)." >&2
    else
      echo "Starting the services again on the current data..." >&2
      rm -f "$(p "$STATE")/copied"
      start_services >&2
      wait_healthy >&2
    fi
  fi
  exit "$rc"
}
trap on_exit EXIT

# step <n> <name> <check> <action>: skip when the check passes, otherwise act and check again.
step() {
  CUR=$1; CUR_NAME=$2
  echo "==> $1/$TOTAL $2"
  if $3; then echo "    already done"; return 0; fi
  $4
  if [ "$DRY" = 0 ] && ! $3; then die "the step ran but its check still fails"; fi
}

# ---------- preconditions (step 0) ----------
REASONS=()
STORES_BYTES=""; ROOT_AVAIL=""; VG_FREE=""
measure() {
  local s b total=0 known=1
  ROOT_AVAIL=$(df -B1 --output=avail "$(p /)" 2>/dev/null | tail -1 | tr -d ' ') || ROOT_AVAIL=""
  VG_FREE=$(vgs --noheadings --units b --nosuffix -o vg_free "$VG" 2>/dev/null | tr -d ' ') || VG_FREE=""
  for s in "${STORES[@]}"; do
    store_switched "$(store_sub "$s")" "$(store_path "$s")" && continue
    b=$(du -sxB1 "$(store_src "$(store_path "$s")")" 2>/dev/null | awk '{ print $1 }') || b=""
    if [ -n "$b" ]; then total=$((total + b)); else known=0; fi
  done
  if [ "$known" = 1 ]; then STORES_BYTES=$total; else STORES_BYTES=""; fi
}
container_need() { if c_container; then echo 0; else echo $((VOL_GIB * GIB)); fi; }
preconditions() {   # fills REASONS; $1 = setup|finish|report
  local t s path
  REASONS=()
  if ! is_root; then
    if [ "$1" != report ] && [ "$DRY" = 0 ]; then REASONS+=("not root: run it with sudo"); fi
  fi
  for t in "${TOOLS[@]}"; do command -v "$t" >/dev/null 2>&1 || REASONS+=("missing tool: $t"); done
  [ -e "$(p /dev/tpmrm0)" ] || REASONS+=("no TPM: /dev/tpmrm0 is missing")
  if is_root && command -v systemd-cryptenroll >/dev/null 2>&1; then
    [ "$(systemd-cryptenroll --tpm2-device=list 2>/dev/null | awk 'NR > 1' | wc -l)" -gt 0 ] ||
      REASONS+=("no TPM: systemd-cryptenroll lists no TPM2 device")
  fi
  [ "$1" = finish ] && return 0
  for s in "${STORES[@]}"; do
    path=$(store_path "$s")
    store_switched "$(store_sub "$s")" "$path" || [ -d "$(store_src "$path")" ] || REASONS+=("missing store: $path")
  done
  measure
  if ! lv_exists && [ -n "$VG_FREE" ] && [ "$VG_FREE" -lt $((SWAP_GIB * GIB)) ]; then
    REASONS+=("volume group $VG has $(gib "$VG_FREE") GiB free, the encrypted swap needs $SWAP_GIB GiB")
  fi
  if [ -n "$ROOT_AVAIL" ] && [ -n "$STORES_BYTES" ]; then
    local after=$((ROOT_AVAIL - $(container_need) - STORES_BYTES))
    [ "$after" -ge $((MIN_FREE_GIB * GIB)) ] ||
      REASONS+=("the root filesystem would have $(gib "$after") GiB free after the container plus a copy of the stores (minimum $MIN_FREE_GIB GiB)")
    [ "$STORES_BYTES" -le $((VOL_GIB * GIB * 9 / 10)) ] ||
      REASONS+=("the stores ($(gib "$STORES_BYTES") GiB) do not fit in 90% of the $VOL_GIB GiB volume")
  elif [ "$1" = setup ]; then
    REASONS+=("cannot measure the free space or the stores (run it with sudo)")
  fi
}
step0() {           # $1 = setup|finish
  CUR=0; CUR_NAME="Preconditions"
  echo "==> 0/$TOTAL Preconditions"
  preconditions "$1"
  if [ "${#REASONS[@]}" -gt 0 ]; then
    local r; for r in "${REASONS[@]}"; do echo "    refused: $r" >&2; done
    exit 1
  fi
  is_root || echo "    not root: dry run only, checks that need root read as not done"
  echo "    ok"
}

# ---------- setup steps ----------
c_container() { local f; f=$(p "$CONTAINER"); [ -f "$f" ] && [ "$(stat -c %s "$f")" -ge $((VOL_GIB * GIB)) ]; }
a_container() {
  run install -d -m 700 "$(dirname "$(p "$CONTAINER")")"
  run fallocate -l "${VOL_GIB}G" "$(p "$CONTAINER")"
  run chmod 600 "$(p "$CONTAINER")"
}

c_luks() { cryptsetup isLuks "$(p "$CONTAINER")" 2>/dev/null; }
a_luks() {
  local k; k=$(p "$SETUP_KEY")
  if [ ! -s "$k" ]; then
    if [ "$DRY" = 1 ]; then echo "    + create a random 64-byte setup key in $k (mode 600)"
    else (umask 077; head -c 64 /dev/urandom > "$k.tmp" && mv "$k.tmp" "$k"); fi
  fi
  run cryptsetup luksFormat --type luks2 --batch-mode --label "$VOL" --key-file "$k" "$(p "$CONTAINER")"
}

need_setup_key() {
  [ "$DRY" = 1 ] && return 0
  [ -s "$(p "$SETUP_KEY")" ] || die "the temporary setup key $SETUP_KEY is gone (a reboot?) before the key slots were \
enrolled. Nothing has been copied yet: delete $CONTAINER and rerun setup."
}
c_tpm() { has_slot tpm2; }
a_tpm() {
  need_setup_key
  # No PCR binding: the server boots in legacy BIOS, so PCRs add breakage without protection (AD-24).
  run systemd-cryptenroll --unlock-key-file="$(p "$SETUP_KEY")" --tpm2-device=auto --tpm2-pcrs= "$(p "$CONTAINER")"
}

c_recovery() { has_slot recovery && [ -f "$(p "$STATE")/recovery-saved" ]; }
a_recovery() {
  local ans
  need_setup_key
  if has_slot recovery; then   # enrolled but never confirmed: replace it with a fresh one
    run systemd-cryptenroll --wipe-slot=recovery "$(p "$CONTAINER")"
  fi
  echo "    The recovery key below is shown ONCE. It unlocks the volume if the TPM ever cannot."
  echo "    Write it down and keep it off this server."
  run systemd-cryptenroll --unlock-key-file="$(p "$SETUP_KEY")" --recovery-key "$(p "$CONTAINER")"
  if [ "$DRY" = 1 ]; then echo "    + ask for the word saved"; return 0; fi
  printf 'Type saved once the recovery key is written down: '
  read -r ans || ans=""
  [ "$ans" = saved ] || die "the recovery key was not confirmed; rerun setup to get a new one"
  mkdir -p "$(p "$STATE")"
  touch "$(p "$STATE")/recovery-saved"
}

c_open() { has_line /etc/crypttab "$CRYPTTAB_VOL" && active "systemd-cryptsetup@$VOL.service"; }
a_open() {
  ensure_line /etc/crypttab "$CRYPTTAB_VOL"
  run systemctl daemon-reload
  # The same unit that unlocks it at boot, headless: it succeeds only if the TPM unlocks the volume.
  run systemctl start "systemd-cryptsetup@$VOL.service"
}

c_nokey() { local t; t=$(slot_types) || return 1; ! grep -qx password <<<"$t" && [ ! -e "$(p "$SETUP_KEY")" ]; }
a_nokey() {
  if [ "$DRY" = 0 ]; then
    c_open && has_slot tpm2 && c_recovery || die "the TPM slot, the confirmed recovery key and a TPM unlock come first"
  fi
  if has_slot password || [ "$DRY" = 1 ]; then run systemd-cryptenroll --wipe-slot=password "$(p "$CONTAINER")"; fi
  if [ -e "$(p "$SETUP_KEY")" ] || [ "$DRY" = 1 ]; then run shred -u "$(p "$SETUP_KEY")"; fi
}

c_fs() { [ "$(blkid -o value -s TYPE "$MAPPER" 2>/dev/null)" = ext4 ]; }
a_fs() {
  local t; t=$(blkid -o value -s TYPE "$MAPPER" 2>/dev/null || true)
  [ -z "$t" ] || die "$MAPPER already holds a $t file system; not formatting it"
  run mkfs.ext4 -q -L "$VOL" -m 1 "$MAPPER"
}

c_mounted() { has_line /etc/fstab "$FSTAB_VOL" && volume_mounted; }
a_mounted() {
  volume_mounted || run install -d -m 700 "$(p "$MNT")"
  ensure_line /etc/fstab "$FSTAB_VOL"
  run systemctl daemon-reload
  volume_mounted || run mount "$(p "$MNT")"
  run chmod 700 "$(p "$MNT")"
}

c_dropins() {
  local u; for u in "${DROPIN_UNITS[@]}"; do
    [ "$(cat "$(p "$(dropin_file "$u")")" 2>/dev/null)" = "$(dropin_content "$u")" ] || return 1
  done
}
a_dropins() {
  local u; for u in "${DROPIN_UNITS[@]}"; do dropin_content "$u" | write_file "$(dropin_file "$u")"; done
  run systemctl daemon-reload
}

c_stopped() { all_switched || services_down; }
a_stopped() { stop_services; }

c_copied() { all_switched || { [ -f "$(p "$STATE")/copied" ] && services_down; }; }
a_copied() {
  local s sub path src dst out
  if [ "$DRY" = 0 ]; then services_down || die "the services are not stopped"; fi
  for s in "${STORES[@]}"; do
    sub=$(store_sub "$s"); path=$(store_path "$s")
    store_switched "$sub" "$path" && continue
    src=$(store_src "$path"); dst="$(p "$MNT")/$sub"
    if findmnt -rn -o TARGET 2>/dev/null | grep -q "^$src/"; then die "something is still mounted below $src"; fi
    echo "    $src -> $dst"
    run rsync -aHAXS --numeric-ids --delete "$src/" "$dst/"
    if [ "$DRY" = 0 ]; then
      out=$(rsync -aHAXn --numeric-ids --delete --out-format='%i %n' "$src/" "$dst/")
      [ -z "$out" ] || die "the copy of $src differs from the original: $(echo "$out" | head -3 | xargs)"
    fi
  done
  run touch "$(p "$STATE")/copied"
}

c_switched() { all_switched; }
a_switched() {
  local s sub path live plain own
  if [ "$DRY" = 0 ]; then c_copied || die "the copy is not complete"; fi
  for s in "${STORES[@]}"; do
    sub=$(store_sub "$s"); path=$(store_path "$s")
    store_switched "$sub" "$path" && continue
    live=$(p "$path"); plain="$live.plain"
    if [ -e "$plain" ]; then own=$(stat -c '%u %g %a' "$plain")
    else own=$(stat -c '%u %g %a' "$live"); run mv "$live" "$plain"; fi
    if [ "$DRY" = 0 ] && [ -d "$live" ]; then   # a rerun: the empty mount point is already there
      [ -z "$(ls -A "$live")" ] || die "$live is not empty although its original is in $plain; move its content aside and rerun"
    else
      run install -d -o "${own%% *}" -g "$(cut -d' ' -f2 <<<"$own")" -m "${own##* }" "$live"
    fi
    ensure_line /etc/fstab "$(p "$MNT")/$sub $live none bind,nofail,x-systemd.requires-mounts-for=$(p "$MNT") 0 0"
    run systemctl daemon-reload
    run mount "$live"
    echo "    $path is now the volume's $sub"
  done
}

c_swap() { lv_exists && has_line /etc/crypttab "$CRYPTTAB_SWAP" && has_line /etc/fstab "$FSTAB_SWAP" && swap_active; }
a_swap() {
  lv_exists || run lvcreate --yes -n "$SWAP_LV" -L "${SWAP_GIB}G" "$VG"
  ensure_line /etc/crypttab "$CRYPTTAB_SWAP"
  ensure_line /etc/fstab "$FSTAB_SWAP"
  run systemctl daemon-reload
  run systemctl start "systemd-cryptsetup@$SWAP.service"   # keyed from /dev/urandom, mkswap on each start
  swap_active || run swapon "/dev/mapper/$SWAP"
}

c_oldswap() { ! old_swap_active && ! fstab_active_entry "$(p "$OLD_SWAP")"; }
a_oldswap() {
  local f tmp
  if [ "$DRY" = 0 ]; then swap_active || die "the encrypted swap is not active"; fi
  if old_swap_active; then run swapoff "$(p "$OLD_SWAP")"; fi
  if fstab_active_entry "$(p "$OLD_SWAP")"; then
    backup_once /etc/fstab
    f=$(p /etc/fstab)
    if [ "$DRY" = 1 ]; then echo "    + comment out the $OLD_SWAP line in $f"; return 0; fi
    tmp=$(awk -v t="$(p "$OLD_SWAP")" '$1 == t { print "# gmshield encrypt-volume: replaced by encrypted swap: " $0; next } { print }' "$f")
    printf '%s\n' "$tmp" > "$f"
  fi
}

c_started() {
  local u
  all_switched && active docker.service || return 1
  if [ -s "$(p "$STATE")/units" ]; then
    while read -r u; do
      case $u in gmshield-ci.service|ai-healthcheck.service|"") continue ;; esac
      active "$u" || return 1
    done < "$(p "$STATE")/units"
  fi
  [ -z "$(stack_problems)" ]
}
a_started() {
  local half; half=$(half_switched)
  [ -z "$half" ] || die "not starting: $(echo "$half" | xargs) is between its original and the volume"
  start_services
  wait_healthy
  run rm -f "$(p "$STATE")/units" "$(p "$STATE")/containers"
}

SETUP_STEPS=(
  "Create the ${VOL_GIB} GiB container file $CONTAINER|c_container|a_container"
  "Format it as LUKS2 with a temporary setup key in /run|c_luks|a_luks"
  "Enroll the TPM2 key slot (no PCR binding)|c_tpm|a_tpm"
  "Enroll the recovery key|c_recovery|a_recovery"
  "Unlock at boot through the TPM (crypttab) and open the volume now|c_open|a_open"
  "Wipe the temporary setup key|c_nokey|a_nokey"
  "Create the ext4 file system|c_fs|a_fs"
  "Mount the volume at $MNT|c_mounted|a_mounted"
  "Hold Docker, containerd, the CI and the dashboard until the volume is mounted|c_dropins|a_dropins"
  "Stop the CI, the health check, the dashboard, every container, Docker and containerd|c_stopped|a_stopped"
  "Copy every store onto the volume|c_copied|a_copied"
  "Move the originals to <path>.plain and bind-mount the copies in their place|c_switched|a_switched"
  "Create the encrypted swap ($SWAP_GIB GiB logical volume keyed from /dev/urandom)|c_swap|a_swap"
  "Switch off $OLD_SWAP|c_oldswap|a_oldswap"
  "Start the services again and check the data stack|c_started|a_started"
)

# ---------- finish ----------
CHECK_FAILURES=()
finish_checks() {   # fills CHECK_FAILURES
  local st s sub path t journal
  CHECK_FAILURES=()
  st=$(p "$STATE")
  if [ ! -f "$st/setup-boot-id" ]; then CHECK_FAILURES+=("setup has not completed")
  elif [ "$(cat "$st/setup-boot-id")" = "$(boot_id)" ]; then CHECK_FAILURES+=("no reboot since setup")
  fi
  if ! has_line /etc/crypttab "$CRYPTTAB_VOL"; then
    CHECK_FAILURES+=("the volume's crypttab line is missing (it must be headless, with no key file)")
  elif ! active "systemd-cryptsetup@$VOL.service"; then
    CHECK_FAILURES+=("the volume was not unlocked at this boot (systemd-cryptsetup@$VOL is not active)")
  else
    journal=$(journalctl -b -q --no-pager -u "systemd-cryptsetup@$VOL.service" 2>/dev/null || true)
    if grep -qi "falling back to traditional unlocking" <<<"$journal"; then
      CHECK_FAILURES+=("the volume was not unlocked by the TPM at this boot")
    fi
  fi
  if t=$(slot_types); then
    grep -qx tpm2 <<<"$t" || CHECK_FAILURES+=("no TPM2 key slot")
    grep -qx recovery <<<"$t" || CHECK_FAILURES+=("no recovery key slot")
    ! grep -qx password <<<"$t" || CHECK_FAILURES+=("a password key slot is still enrolled")
  else
    CHECK_FAILURES+=("cannot read the key slots")
  fi
  volume_mounted || CHECK_FAILURES+=("the volume is not mounted at $MNT")
  for s in "${STORES[@]}"; do
    sub=$(store_sub "$s"); path=$(store_path "$s")
    store_switched "$sub" "$path" || CHECK_FAILURES+=("bind mount not active: $path")
  done
  swap_active || CHECK_FAILURES+=("the encrypted swap is not active")
  ! old_swap_active || CHECK_FAILURES+=("$OLD_SWAP is still in use")
  while read -r t; do if [ -n "$t" ]; then CHECK_FAILURES+=("data stack: $t"); fi; done <<<"$(stack_problems)"
}

CHECKS_PASSED=0
c_checks() { [ "$CHECKS_PASSED" = 1 ] || [ -f "$(p "$STATE")/finished" ]; }
a_checks() {
  local f
  finish_checks
  if [ "${#CHECK_FAILURES[@]}" -gt 0 ]; then
    for f in "${CHECK_FAILURES[@]}"; do echo "    check failed: $f" >&2; done
    die "nothing was deleted"
  fi
  CHECKS_PASSED=1
  echo "    every check passed"
}
c_noplain() {
  local s; all_switched || return 1
  for s in "${STORES[@]}"; do [ ! -e "$(p "$(store_path "$s")").plain" ] || return 1; done
}
a_noplain() {
  local s sub path plain
  for s in "${STORES[@]}"; do
    sub=$(store_sub "$s"); path=$(store_path "$s"); plain="$(p "$path").plain"
    [ -e "$plain" ] || continue
    store_switched "$sub" "$path" || die "$path is not bind-mounted; keeping $plain"
    if findmnt -n --mountpoint "$plain" >/dev/null 2>&1; then die "$plain is a mount point; not deleting it"; fi
    run rm -rf --one-file-system -- "$plain"
    echo "    deleted $plain"
  done
}
c_nooldswap() { [ ! -e "$(p "$OLD_SWAP")" ]; }
a_nooldswap() {
  if [ "$DRY" = 0 ]; then ! old_swap_active || die "$OLD_SWAP is in use"; fi
  run rm -f "$(p "$OLD_SWAP")"
}
c_trimmed() { [ -f "$(p "$STATE")/finished" ]; }
a_trimmed() {
  # Tell the SSD which blocks are free. Plain-text blocks may still remain in the SSD's spare area.
  run fstrim -v "$(p /)"
  run touch "$(p "$STATE")/finished"
}
FINISH_STEPS=(
  "Check the new layout (reboot, TPM unlock, bind mounts, swap, data stack)|c_checks|a_checks"
  "Delete the plain-text originals (<path>.plain)|c_noplain|a_noplain"
  "Delete $OLD_SWAP|c_nooldswap|a_nooldswap"
  "Trim the root filesystem's free blocks|c_trimmed|a_trimmed"
)

# ---------- reports ----------
report_steps() {    # report_steps <title> <array name>
  local -n steps=$2
  local i=0 e name check mark
  echo "$1"
  for e in "${steps[@]}"; do
    i=$((i + 1)); name=${e%%|*}; check=${e#*|}; check=${check%%|*}
    if $check 2>/dev/null; then mark="done"; else mark="  --"; fi
    printf '  [%s] %2d %s\n' "$mark" "$i" "$name"
  done
}
report_layout() {
  local t s sub path
  echo "Volume"
  if active "systemd-cryptsetup@$VOL.service"; then echo "  open: $MAPPER (systemd-cryptsetup@$VOL active)"; else echo "  not open"; fi
  if t=$(slot_types); then echo "  key slots: $(echo "$t" | xargs)"; else echo "  key slots: unknown (needs sudo)"; fi
  if volume_mounted; then echo "  mounted at $MNT"; else echo "  not mounted at $MNT"; fi
  for s in "${STORES[@]}"; do
    sub=$(store_sub "$s"); path=$(store_path "$s")
    if store_switched "$sub" "$path"; then echo "  bind mount active: $path"; else echo "  bind mount NOT active: $path"; fi
    if [ -e "$(p "$path").plain" ]; then echo "    plain-text original still at $path.plain"; fi
  done
  if swap_active; then echo "  encrypted swap active (/dev/mapper/$SWAP)"; else echo "  encrypted swap NOT active"; fi
  if old_swap_active; then echo "  $OLD_SWAP still in use"; fi
  t=$(stack_problems)
  if [ -z "$t" ]; then echo "  data stack: postgres and redis healthy, qdrant and registry up"
  else echo "  data stack: $(echo "$t" | paste -sd ';' | sed 's/;/; /g')"; fi
}

cmd_plan() {
  local r
  preconditions report
  echo "Plan: put everything persistent on one encrypted volume (nothing is changed by this command)"
  echo "  volume: $CONTAINER, a $VOL_GIB GiB LUKS2 file on the root filesystem, mounted at $MNT"
  echo "  unlock: TPM2 key slot without PCR binding, plus one recovery key shown once"
  local s; for s in "${STORES[@]}"; do echo "  store:  $(store_path "$s") -> $MNT/$(store_sub "$s") (bind mount)"; done
  echo "  swap:   $OLD_SWAP replaced by a $SWAP_GIB GiB logical volume in $VG, keyed from /dev/urandom at each boot"
  if [ -n "$VG_FREE" ]; then echo "  volume group $VG: $(gib "$VG_FREE") GiB free"; fi
  if [ -n "$ROOT_AVAIL" ]; then echo "  root filesystem: $(gib "$ROOT_AVAIL") GiB free"; fi
  if [ -n "$STORES_BYTES" ]; then echo "  stores still to copy: $(gib "$STORES_BYTES") GiB"
  else echo "  stores still to copy: size unknown (du needs sudo)"; fi
  if [ "${#REASONS[@]}" -gt 0 ]; then for r in "${REASONS[@]}"; do echo "  setup would refuse: $r"; done; fi
  is_root || echo "  (not root: checks that need root read as not done)"
  report_steps "Setup steps" SETUP_STEPS
  echo "Then reboot and run: sudo bash $0 finish"
}

cmd_status() {
  local f
  is_root || echo "(not root: checks that need root read as not done)"
  report_steps "Setup steps" SETUP_STEPS
  report_layout
  finish_checks
  if [ "${#CHECK_FAILURES[@]}" -eq 0 ]; then echo "Finish checks: all pass"
  else echo "Finish checks:"; for f in "${CHECK_FAILURES[@]}"; do echo "  failing: $f"; done; fi
  report_steps "Finish steps" FINISH_STEPS
}

cmd_setup() {
  local e i=0 ans name rest
  TOTAL=${#SETUP_STEPS[@]}
  step0 setup
  [ "$DRY" = 1 ] && echo "DRY RUN: commands that change something are printed, not run"
  echo
  echo "Volume:          $CONTAINER, $VOL_GIB GiB LUKS2 file, mounted at $MNT"
  echo "Volume group:    $VG has $(gib "${VG_FREE:-0}") GiB free; this uses $SWAP_GIB GiB for encrypted swap and leaves the rest for snapshots"
  echo "Root filesystem: $(gib "${ROOT_AVAIL:-0}") GiB free; the container takes $(gib "$(container_need)") GiB more"
  echo "                 and the stores to copy hold $(gib "${STORES_BYTES:-0}") GiB; at least $MIN_FREE_GIB GiB must stay free"
  echo "Services:        the CI, the dashboard, every container, Docker and containerd stop during the copy"
  if [ "$DRY" = 0 ]; then
    printf 'Type yes to continue: '
    read -r ans || ans=""
    if [ "$ans" != yes ]; then echo "Nothing changed."; exit 0; fi
  fi
  for e in "${SETUP_STEPS[@]}"; do
    i=$((i + 1)); name=${e%%|*}; rest=${e#*|}
    step "$i" "$name" "${rest%%|*}" "${rest#*|}"
  done
  CUR=""
  if [ "$DRY" = 0 ] && [ ! -f "$(p "$STATE")/setup-boot-id" ]; then boot_id > "$(p "$STATE")/setup-boot-id"; fi
  echo "DONE: reboot, then run: sudo bash $0 status, and sudo bash $0 finish"
}

cmd_finish() {
  local e i=0 name rest
  TOTAL=${#FINISH_STEPS[@]}
  step0 finish
  [ "$DRY" = 1 ] && echo "DRY RUN: commands that change something are printed, not run"
  for e in "${FINISH_STEPS[@]}"; do
    i=$((i + 1)); name=${e%%|*}; rest=${e#*|}
    step "$i" "$name" "${rest%%|*}" "${rest#*|}"
  done
  CUR=""
  echo "DONE: only the encrypted volume holds the stores. Plain-text blocks may remain in the SSD's spare area."
}

case $CMD in
  plan) cmd_plan ;;
  status) cmd_status ;;
  setup) cmd_setup ;;
  finish) cmd_finish ;;
esac
