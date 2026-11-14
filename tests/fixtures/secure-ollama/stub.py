#!/usr/bin/env python3
"""A fake roberto-server for tests/test_secure_ollama.py.

Linked under the name of every tool deploy/secure-ollama.sh calls. Each call is appended to $STUB_LOG
and acts on a small JSON state ($STUB_STATE): ufw rules, Ollama's models and listening addresses, and
whether the gmshield-model network exists. Ollama's environment is computed like systemd does: the
unit's own values, then every drop-in under $GMSHIELD_ROOT in name order (the last assignment wins).
A tool named in $STUB_FAIL (comma-separated) logs its call and exits 23.
"""
import json
import os
import re
import sys
from pathlib import Path

NAME = Path(sys.argv[0]).name
ARGS = sys.argv[1:]
ROOT = os.environ.get("GMSHIELD_ROOT", "")
STATE = Path(os.environ["STUB_STATE"])
BASE_ENV = {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_MAX_LOADED_MODELS": "1", "OLLAMA_NUM_PARALLEL": "1"}


def unit_env() -> dict:
    env = dict(BASE_ENV)
    d = Path(ROOT, "etc/systemd/system/ollama.service.d")
    for f in sorted(d.glob("*.conf")) if d.is_dir() else []:
        for m in re.finditer(r'^Environment="([A-Z_]+)=([^"]*)"', f.read_text(), re.M):
            env[m.group(1)] = m.group(2)
    return env


def ufw_status(st: dict, numbered: bool) -> str:
    head = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"
    lines = []
    for i, r in enumerate(st["rules"], 1):
        rule = r if numbered else r.replace("ALLOW IN", "ALLOW").replace("DENY IN", "DENY")
        lines.append(f"[{i:2d}] {rule}" if numbered else rule)
    return head + "\n".join(lines)


def answers(st: dict, host: str) -> bool:
    addr = host.rsplit(":", 1)[0]
    return any(l.startswith(("0.0.0.0", "*")) or l.rsplit(":", 1)[0] == addr for l in st["listening"])


def main() -> int:
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write(" ".join([NAME, *ARGS]) + "\n")
    if NAME in os.environ.get("STUB_FAIL", "").split(","):
        print(f"{NAME}: injected failure", file=sys.stderr)
        return 23
    st = json.loads(STATE.read_text())
    rc = 0
    if NAME == "id":
        print(os.environ.get("STUB_UID", "0"))
    elif NAME == "docker":
        if ARGS[:2] == ["network", "inspect"] and st["network"]:
            print("true 172.30.5.0/24 172.30.5.1")
        else:
            rc = 1
    elif NAME == "ip":
        if st["network"] and "gmshield-model" in ARGS:
            print("9: gmshield-model    inet 172.30.5.1/24 brd 172.30.5.255 scope global gmshield-model")
        else:
            rc = 1
    elif NAME == "ss":
        for a in st["listening"]:
            print(f"LISTEN 0      4096   {a}      0.0.0.0:*")
    elif NAME == "systemctl":
        if ARGS[:2] == ["show", "-p"]:
            print("Environment=" + " ".join(f"{k}={v}" for k, v in unit_env().items()))
        elif ARGS[:1] == ["restart"]:
            host = unit_env()["OLLAMA_HOST"]
            st["listening"] = ["*:11434"] if host.startswith("0.0.0.0") else [host]
            st["restarts"] += 1
    elif NAME == "ollama":
        if not answers(st, os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")):
            print("Error: could not connect to ollama server", file=sys.stderr)
            rc = 1
        elif ARGS[0] == "list":
            print("NAME    ID    SIZE    MODIFIED")
            for m in st["models"]:
                print(f"{m}    abc    1 GB    5 days ago")
        elif ARGS[0] == "rm":
            st["models"].remove(ARGS[1])
            print(f"deleted '{ARGS[1]}'")
    elif NAME == "ufw":
        if ARGS == ["status"] or ARGS == ["status", "numbered"]:
            if os.environ.get("STUB_UID", "0") != "0":
                print("ERROR: You need to be root to run this script", file=sys.stderr)
                rc = 1
            else:
                print(ufw_status(st, ARGS == ["status", "numbered"]))
        elif ARGS[:2] == ["insert", "1"]:
            a = ARGS[2:]
            # allow in on IF proto tcp from SRC to DST port P comment C
            iface, src, dst, port, comment = a[3], a[7], a[9], a[11], a[13]
            st["rules"].insert(0, f"{dst} {port}/tcp on {iface}  ALLOW IN    {src}                  # {comment}")
        elif ARGS[:2] == ["--force", "delete"]:
            st["rules"].pop(int(ARGS[2]) - 1)
        else:
            rc = 2
    STATE.write_text(json.dumps(st, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main())
