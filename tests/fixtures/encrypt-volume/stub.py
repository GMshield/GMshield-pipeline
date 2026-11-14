#!/usr/bin/env python3
"""A fake roberto-server for tests/test_encrypt_volume.py.

Linked under the name of every system tool deploy/encrypt-volume.sh calls. Each call is appended to
$STUB_LOG and acts on a small JSON state ($STUB_STATE): LUKS key slots, open volumes, mounts, swap,
units and containers. A tool named in $STUB_FAIL (comma-separated) logs its call and exits 23.
Paths in the state are the ones the script passes, already under $GMSHIELD_ROOT.
"""
import json
import os
import shutil
import sys
from pathlib import Path

GIB = 1024 ** 3
NAME = Path(sys.argv[0]).name
ARGS = sys.argv[1:]
ROOT = os.environ.get("GMSHIELD_ROOT", "")
STATE = Path(os.environ["STUB_STATE"])
NAMES = {"c1": "postgres", "c2": "redis", "c3": "qdrant", "c4": "registry"}


def load() -> dict:
    return json.loads(STATE.read_text())


def save(st: dict) -> None:
    STATE.write_text(json.dumps(st, indent=1))


def out(text: str) -> None:
    if text:
        print(text)


def fstab_source(target: str) -> str | None:
    for line in Path(ROOT, "etc/fstab").read_text().splitlines():
        f = line.split()
        if len(f) >= 2 and not f[0].startswith("#") and f[1] == target:
            return f[0]
    return None


def main() -> int:
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write(" ".join([NAME, *ARGS]) + "\n")
    if NAME in os.environ.get("STUB_FAIL", "").split(","):
        print(f"{NAME}: injected failure", file=sys.stderr)
        return 23
    st = load()
    active = set(st["active"])
    rc = 0

    if NAME == "id":
        out(os.environ.get("STUB_UID", "0"))
    elif NAME == "df":
        out("Avail\n" + os.environ.get("STUB_DF_AVAIL", str(320 * GIB)))
    elif NAME == "du":
        out(f"{GIB}\t{ARGS[-1]}")
    elif NAME == "vgs":
        out(str(45 * GIB))
    elif NAME == "lvs":
        out("\n".join(f"  {lv}" for lv in ["ubuntu-lv", *st["lvs"]]))
    elif NAME == "lvcreate":
        st["lvs"].append(ARGS[ARGS.index("-n") + 1])
    elif NAME == "fallocate":
        size = ARGS[ARGS.index("-l") + 1]
        with open(ARGS[-1], "wb") as fh:
            fh.truncate(int(size.rstrip("G")) * GIB)
    elif NAME == "cryptsetup":
        if ARGS[0] == "isLuks":
            rc = 0 if st["luks"] else 1
        elif ARGS[0] == "luksFormat":
            st["luks"], st["slots"] = True, ["password"]
        else:
            rc = 1
    elif NAME == "systemd-cryptenroll":
        if "--tpm2-device=list" in ARGS:
            out("PATH        DEVICE     DRIVER\n/dev/tpmrm0 MSFT0101:00 tpm_crb")
        elif len(ARGS) == 1:
            if not st["luks"]:
                return 1
            out("SLOT TYPE\n" + "\n".join(f"   {i} {t}" for i, t in enumerate(st["slots"])))
        else:
            for a in ARGS:
                if a.startswith("--wipe-slot="):
                    st["slots"] = [s for s in st["slots"] if s != a.split("=", 1)[1]]
            if "--tpm2-device=auto" in ARGS:
                st["slots"].append("tpm2")
            if "--recovery-key" in ARGS:
                st["slots"].append("recovery")
                out("A secret recovery key has been generated for this volume:\n\n    fake-recovery-key\n")
    elif NAME == "systemctl":
        verb, units = ARGS[0], [a for a in ARGS[1:] if not a.startswith("-")]
        if verb == "is-active":
            rc = 0 if units[0] in active else 3
            if "--quiet" not in ARGS:
                out("active" if rc == 0 else "inactive")
        elif verb == "start":
            for u in units:
                if u == "systemd-cryptsetup@gmshield.service" and ("tpm2" not in st["slots"]
                                                                    or os.environ.get("STUB_TPM_BROKEN")):
                    return 1
                active.add(u)
        elif verb == "stop":
            active -= set(units)
        elif verb == "cat":
            rc = 0
    elif NAME == "docker":
        if "docker.service" not in active:
            print("Cannot connect to the Docker daemon", file=sys.stderr)
            return 1
        running = st["running"]
        if ARGS[:2] == ["ps", "-q"]:
            out("\n".join(running))
        elif ARGS[0] == "ps":
            out("\n".join(f"{NAMES[c]} Up 2 minutes" + (" (healthy)" if NAMES[c] in ("postgres", "redis") else "")
                          for c in running))
        elif ARGS[0] == "stop":
            st["running"] = [c for c in running if c not in ARGS]
        elif ARGS[0] == "start":
            st["running"] = sorted(set(running) | {a for a in ARGS if a in NAMES})
    elif NAME == "blkid":
        if st["mkfs"]:
            out("ext4")
        else:
            rc = 2
    elif NAME == "mkfs.ext4":
        st["mkfs"] = True
    elif NAME == "findmnt":
        if "--mountpoint" in ARGS:
            src = st["mounts"].get(ARGS[ARGS.index("--mountpoint") + 1])
            if src is None:
                return 1
            if "SOURCE" in ARGS:
                out(src)
        else:
            out("\n".join(st["mounts"]))
    elif NAME == "mount":
        target = ARGS[-1]
        src = fstab_source(target)
        if src is None:
            return 32
        vol = ROOT + "/srv/gmshield/"
        st["mounts"][target] = (f"/dev/mapper/gmshield[/{src[len(vol):]}]" if src.startswith(vol) else src)
    elif NAME == "swapon":
        if any(a.startswith("--show") for a in ARGS):
            out("\n".join(st["swaps"]))
        else:
            st["swaps"].append(ARGS[-1])
    elif NAME == "swapoff":
        st["swaps"] = [s for s in st["swaps"] if s != ARGS[-1]]
    elif NAME == "rsync":
        flags = "".join(a for a in ARGS if a.startswith("-") and not a.startswith("--"))
        if "n" not in flags:
            src, dst = [a for a in ARGS if not a.startswith("-")][-2:]
            shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
    elif NAME == "journalctl":
        out(os.environ.get("STUB_JOURNAL", ""))
    # fstrim, mkswap and anything else: logged only

    st["active"] = sorted(active)
    save(st)
    return rc


if __name__ == "__main__":
    sys.exit(main())
