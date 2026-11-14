#!/usr/bin/env python3
"""A fake `docker` for tests/test_stack.py.

Each call is appended to $STUB_LOG (one line, arguments joined by spaces); what psql receives on
stdin is appended to $STUB_LOG.psql. $STUB_NO_QDRANT_VOLUME makes `docker volume inspect` fail;
$STUB_OLD_NETWORK makes rpg_default exist (with $STUB_OLD_NETWORK_USED: a container on it).
"""
import os
import sys

ARGS = sys.argv[1:]
LOG = os.environ["STUB_LOG"]


def main() -> int:
    with open(LOG, "a") as fh:
        fh.write(" ".join(ARGS) + "\n")
    if ARGS[:1] == ["compose"]:
        if "version" in ARGS:
            print("Docker Compose version v2.40.3")
        elif "ps" in ARGS:
            print("healthy")
        elif "exec" in ARGS and "psql" in ARGS:
            with open(LOG + ".psql", "a") as fh:
                fh.write(sys.stdin.read())
        return 0
    if ARGS[:2] == ["volume", "inspect"]:
        return 1 if os.environ.get("STUB_NO_QDRANT_VOLUME") else 0
    if ARGS[:2] == ["network", "inspect"]:
        return 0 if os.environ.get("STUB_OLD_NETWORK") else 1
    if ARGS[:2] == ["ps", "-a"]:
        if os.environ.get("STUB_OLD_NETWORK_USED"):
            print("abc123")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
