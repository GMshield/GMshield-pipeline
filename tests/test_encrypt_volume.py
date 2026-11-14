"""Tests for deploy/encrypt-volume.sh against a fake server (tests/fixtures/encrypt-volume/stub.py).

The system tools are PATH stubs that log their arguments and keep a small state; every file the script
touches lives under a temporary GMSHIELD_ROOT. Run: python3 -m unittest tests.test_encrypt_volume -v
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "encrypt-volume.sh"
STUB = Path(__file__).resolve().parent / "fixtures" / "encrypt-volume" / "stub.py"
TOOLS = ["id", "cryptsetup", "systemd-cryptenroll", "rsync", "fallocate", "lvcreate", "lvs", "vgs", "mkswap",
         "swapon", "swapoff", "findmnt", "mount", "mkfs.ext4", "blkid", "systemctl", "journalctl", "docker",
         "du", "df", "fstrim"]
STORES = ["var/lib/docker", "var/lib/containerd", "home/roberto/gmshield-ci", "home/roberto/stack",
          "home/roberto/.config/gmshield"]
STEPS = 15
OK_INPUT = "yes\nsaved\nfake-recovery-key\n"     # confirm, recovery key saved, recovery key typed back


class EncryptVolumeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root, self.bin = base / "root", base / "bin"
        self.state, self.log = base / "state.json", base / "calls.log"
        self.bin.mkdir()
        for tool in TOOLS:
            (self.bin / tool).symlink_to(STUB)
        r = self.root
        for d in ["etc/systemd/system", "run", "srv", "var/lib", "dev", "proc/sys/kernel/random"]:
            (r / d).mkdir(parents=True)
        for s in STORES:
            (r / s).mkdir(parents=True)
            (r / s / "data.txt").write_text(f"plain text of {s}\n")
        (r / "home/roberto/stack/.env").write_text("POSTGRES_PASSWORD=x\n")
        (r / "dev/tpmrm0").touch()
        (r / "swap.img").write_bytes(b"\0" * 16)
        (r / "proc/sys/kernel/random/boot_id").write_text("boot-1\n")
        (r / "etc/crypttab").write_text("# <target name>\t<source device>\t\t<key file>\t<options>\n")
        (r / "etc/fstab").write_text(f"/dev/disk/by-id/dm-uuid-LVM-x / ext4 defaults 0 1\n{r}/swap.img\tnone\tswap\tsw\t0\t0\n")
        self.state.write_text(json.dumps({
            "active": ["docker.service", "docker.socket", "containerd.service", "gmshield-dashboard.service",
                       "gmshield-ci.timer", "ai-healthcheck.timer"],
            "running": ["c1", "c2", "c3", "c4"], "luks": False, "slots": [], "mkfs": False, "mounts": {},
            "swaps": [f"{r}/swap.img"], "lvs": []}))
        self.log.touch()

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args, stdin="", **env):
        e = {"PATH": f"{self.bin}:/usr/bin:/bin", "GMSHIELD_ROOT": str(self.root), "STUB_STATE": str(self.state),
             "STUB_LOG": str(self.log), "LC_ALL": "C", **env}
        return subprocess.run(["bash", str(SCRIPT), *args], input=stdin, capture_output=True, text=True, env=e,
                              timeout=120)

    def snapshot(self) -> dict:
        files = {}
        for f in sorted(self.root.rglob("*")):
            if f.is_file() and f.stat().st_size > 1 << 20:      # the sparse 150 GiB container
                files[str(f.relative_to(self.root))] = f"size {f.stat().st_size}"
            elif f.is_file():
                files[str(f.relative_to(self.root))] = hashlib.sha256(f.read_bytes()).hexdigest()
            else:
                files[str(f.relative_to(self.root))] = "dir"
        state = json.loads(self.state.read_text())
        state["active"] = sorted(state["active"])
        return {"files": files, "state": state}

    def st(self) -> dict:
        return json.loads(self.state.read_text())

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def setup_ok(self):
        res = self.run_script("setup", stdin=OK_INPUT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    def assert_originals_in_place(self):
        for s in STORES:
            self.assertEqual((self.root / s / "data.txt").read_text(), f"plain text of {s}\n")
            self.assertFalse((self.root / f"{s}.plain").exists())

    # ---------- plan, dry run, declined ----------
    def test_plan_changes_nothing(self):
        before = self.snapshot()
        res = self.run_script("plan")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("nothing is changed", res.stdout)
        self.assertIn("150 GiB LUKS2", res.stdout)
        self.assertIn("volume group ubuntu-vg: 45.0 GiB free", res.stdout)
        self.assertEqual(res.stdout.count("[  --]"), STEPS)
        self.assertEqual(self.snapshot(), before)

    def test_plan_without_root_reports_what_it_can(self):
        res = self.run_script("plan", STUB_UID="1000")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("not root", res.stdout)

    def test_dry_run_prints_commands_and_changes_nothing(self):
        before = self.snapshot()
        res = self.run_script("setup", "--dry-run")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("+ cryptsetup luksFormat --type luks2", res.stdout)
        self.assertIn("--tpm2-pcrs=", res.stdout)
        self.assertIn("+ rsync -aHAXS --numeric-ids --delete", res.stdout)
        self.assertIn("+ lvcreate --yes -n gmshield_swap -L 4G ubuntu-vg", res.stdout)
        self.assertNotIn("FAILED", res.stdout + res.stderr)
        self.assertEqual(self.snapshot(), before)
        mutating = [c for c in self.calls() if c.split()[0] in ("cryptsetup", "fallocate", "lvcreate", "mkfs.ext4",
                                                                 "mount", "swapoff", "rsync")
                    or c.startswith(("systemctl start", "systemctl stop", "docker stop"))]
        self.assertEqual(mutating, [c for c in mutating if c.startswith("cryptsetup isLuks")])

    def test_declined_setup_exits_0_and_changes_nothing(self):
        before = self.snapshot()
        res = self.run_script("setup", stdin="no\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Nothing changed.", res.stdout)
        self.assertEqual(self.snapshot(), before)

    # ---------- preconditions ----------
    def test_refused_at_step_0(self):
        cases = [({"STUB_UID": "1000"}, "not root"),
                 ({"STUB_DF_AVAIL": str(200 * 1024 ** 3)}, "minimum 60 GiB")]
        for env, reason in cases:
            with self.subTest(reason=reason):
                res = self.run_script("setup", stdin="yes\n", **env)
                self.assertEqual(res.returncode, 1)
                self.assertIn(reason, res.stderr)
                self.assertIn("FAILED at step 0: Preconditions", res.stderr)
        (self.bin / "lvcreate").unlink()                     # /usr/sbin is not on the test PATH
        res = self.run_script("setup", stdin="yes\n")
        self.assertIn("missing tool: lvcreate", res.stderr)
        self.assertIn("FAILED at step 0", res.stderr)
        (self.bin / "lvcreate").symlink_to(STUB)
        (self.root / "dev/tpmrm0").unlink()
        res = self.run_script("setup", stdin="yes\n")
        self.assertIn("no TPM", res.stderr)
        self.assertIn("FAILED at step 0", res.stderr)
        self.assertFalse((self.root / "var/lib/gmshield").exists())

    # ---------- the full run, rerun and finish ----------
    def test_setup_then_rerun_then_finish(self):
        res = self.setup_ok()
        self.assertIn("fake-recovery-key", res.stdout)
        st, r = self.st(), self.root
        self.assertEqual(sorted(st["slots"]), ["recovery", "tpm2"])          # the setup key slot is wiped
        self.assertFalse((r / "run/gmshield-setup.key").exists())
        self.assertIn("--tpm2-pcrs=", "\n".join(self.calls()))
        calls = self.calls()
        first_rsync = next(i for i, c in enumerate(calls) if c.startswith("rsync"))
        self.assertLess(calls.index("docker stop -t 60 c1 c2 c3 c4"), first_rsync)
        for s in STORES:
            sub = {"home/roberto/.config/gmshield": "config-gmshield"}.get(s, Path(s).name)
            self.assertEqual(st["mounts"][f"{r}/{s}"], f"/dev/mapper/gmshield[/{sub}]")
            self.assertEqual((r / f"{s}.plain/data.txt").read_text(), f"plain text of {s}\n")
            self.assertEqual((r / f"srv/gmshield/{sub}/data.txt").read_text(), f"plain text of {s}\n")
        self.assertEqual(st["swaps"], ["/dev/mapper/cryptswap"])
        self.assertEqual(st["running"], ["c1", "c2", "c3", "c4"])
        self.assertIn("gmshield-ci.timer", st["active"])
        crypttab, fstab = (r / "etc/crypttab").read_text(), (r / "etc/fstab").read_text()
        self.assertIn(f"gmshield {r}/var/lib/gmshield/volume.luks none luks,tpm2-device=auto,headless=true,nofail",
                      crypttab)
        self.assertIn("cryptswap /dev/ubuntu-vg/gmshield_swap /dev/urandom swap,plain", crypttab)
        self.assertIn(f"# gmshield encrypt-volume: replaced by encrypted swap: {r}/swap.img", fstab)
        self.assertIn(f"{r}/srv/gmshield/docker {r}/var/lib/docker none bind,nofail", fstab)
        dropin = (r / "etc/systemd/system/docker.service.d/gmshield-volume.conf").read_text()
        self.assertIn(f"RequiresMountsFor={r}/srv/gmshield {r}/var/lib/docker", dropin)
        self.assertTrue((r / "etc/fstab.before-gmshield").exists())
        self.assertTrue((r / "swap.img").exists())                               # deleted only by finish

        # a rerun reports every step done and changes nothing
        before = self.snapshot()
        res = self.run_script("setup", stdin="yes\n")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.count("already done"), STEPS)
        self.assertEqual(self.snapshot(), before)

        # finish refuses without a reboot and deletes nothing
        res = self.run_script("finish")
        self.assertEqual(res.returncode, 1)
        self.assertIn("check failed: no reboot since setup", res.stderr)
        self.assertIn("FAILED at step 1", res.stderr)
        self.assertEqual(self.snapshot(), before)

        # after a boot where the TPM did not unlock it, it still refuses
        (r / "proc/sys/kernel/random/boot_id").write_text("boot-2\n")
        before = self.snapshot()
        res = self.run_script("finish", STUB_JOURNAL="TPM2 operation failed, falling back to traditional unlocking")
        self.assertEqual(res.returncode, 1)
        self.assertIn("not unlocked by the TPM", res.stderr)
        self.assertEqual(self.snapshot(), before)

        # after a reboot, an unhealthy postgres or a leftover password slot still blocks finish
        res = self.run_script("finish", STUB_UNHEALTHY="postgres")
        self.assertEqual(res.returncode, 1)
        self.assertIn("check failed: data stack: postgres is not healthy", res.stderr)
        self.assertEqual(self.snapshot(), before)
        st = self.st()
        st["slots"].append("password")
        self.state.write_text(json.dumps(st))
        before = self.snapshot()
        res = self.run_script("finish")
        self.assertEqual(res.returncode, 1)
        self.assertIn("check failed: a password key slot is still enrolled", res.stderr)
        self.assertEqual(self.snapshot(), before)
        st["slots"].remove("password")
        self.state.write_text(json.dumps(st))

        # status after the reboot: every check passes
        res = self.run_script("status")
        self.assertIn("Finish checks: all pass", res.stdout)
        self.assertIn("key slots: recovery tpm2", res.stdout)

        res = self.run_script("finish")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        for s in STORES:
            self.assertFalse((r / f"{s}.plain").exists())
        self.assertFalse((r / "swap.img").exists())
        self.assertIn(f"fstrim -v {r}/", self.calls())
        res = self.run_script("finish")
        self.assertEqual(res.stdout.count("already done"), 4)

    def test_finish_refuses_before_setup(self):
        before = self.snapshot()
        res = self.run_script("finish")
        self.assertEqual(res.returncode, 1)
        self.assertIn("check failed: setup has not completed", res.stderr)
        self.assertEqual(self.snapshot(), before)

    # ---------- failures ----------
    def test_copy_failure_keeps_originals_and_restarts_services(self):
        res = self.run_script("setup", stdin=OK_INPUT, STUB_FAIL="rsync")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAILED at step 11: Copy every store onto the volume", res.stderr)
        self.assert_originals_in_place()
        st = self.st()
        self.assertEqual(st["running"], ["c1", "c2", "c3", "c4"])
        for u in ("docker.service", "containerd.service", "gmshield-ci.timer", "gmshield-dashboard.service"):
            self.assertIn(u, st["active"])
        self.assertEqual(st["mounts"], {f"{self.root}/srv/gmshield": "/dev/mapper/gmshield"})
        self.assertIn(f"{self.root}/swap.img", st["swaps"])

        # the rerun resumes: steps 1-9 are done, the copy is redone, everything completes
        res = self.run_script("setup", stdin="yes\n")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        for n in range(1, 10):
            self.assertRegex(res.stdout, rf"==> {n}/{STEPS} [^\n]*\n    already done")
        self.assertNotRegex(res.stdout, rf"==> 11/{STEPS} [^\n]*\n    already done")
        self.assertEqual(self.st()["running"], ["c1", "c2", "c3", "c4"])

    def test_bind_mount_failure_keeps_services_stopped_then_rerun_completes(self):
        res = self.run_script("setup", stdin=OK_INPUT, STUB_MOUNT_FAIL="var/lib/docker")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAILED at step 12", res.stderr)
        self.assertIn("Services stay stopped", res.stderr)
        st = self.st()
        self.assertNotIn("docker.service", st["active"])
        self.assertNotIn("containerd.service", st["active"])
        self.assertEqual((self.root / "var/lib/docker.plain/data.txt").read_text(), "plain text of var/lib/docker\n")
        res = self.run_script("setup", stdin="yes\n")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.st()["running"], ["c1", "c2", "c3", "c4"])

    def test_copy_that_differs_moves_nothing(self):
        res = self.run_script("setup", stdin=OK_INPUT, STUB_RSYNC_DIFF="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("differs", res.stderr)
        self.assertIn("FAILED at step 11", res.stderr)
        self.assert_originals_in_place()
        self.assertIn("docker.service", self.st()["active"])

    def test_wrong_recovery_key_fails_step_4_then_rerun_passes(self):
        res = self.run_script("setup", stdin="yes\nsaved\nnot-the-key\n")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAILED at step 4", res.stderr)
        self.assertIn("not the recovery key", res.stderr)
        self.assertFalse((self.root / "var/lib/gmshield/encrypt-volume/recovery-saved").exists())
        self.assertIn("password", self.st()["slots"])                         # setup key not wiped
        res = self.run_script("setup", stdin=OK_INPUT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(sorted(self.st()["slots"]), ["recovery", "tpm2"])

    def test_running_pipeline_refuses_and_restarts_services(self):
        st = self.st()
        st["active"].append("gmshield-ci.service")
        self.state.write_text(json.dumps(st))
        res = self.run_script("setup", stdin=OK_INPUT, GMSHIELD_CI_WAIT="0")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("a pipeline run is still going", res.stderr)
        self.assertIn("FAILED at step 10", res.stderr)
        self.assertNotIn("systemctl stop gmshield-ci.service ai-healthcheck.service gmshield-dashboard.service",
                         self.calls())
        st = self.st()
        for u in ("gmshield-ci.timer", "ai-healthcheck.timer", "docker.service", "gmshield-ci.service"):
            self.assertIn(u, st["active"])
        self.assertEqual(st["running"], ["c1", "c2", "c3", "c4"])
        self.assert_originals_in_place()

    def test_tpm_unlock_failure_stops_before_touching_data(self):
        res = self.run_script("setup", stdin=OK_INPUT, STUB_TPM_BROKEN="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAILED at step 5", res.stderr)
        self.assertTrue((self.root / "run/gmshield-setup.key").exists())       # kept until the TPM unlocks
        self.assertIn("password", self.st()["slots"])
        self.assert_originals_in_place()
        self.assertIn("docker.service", self.st()["active"])

    def test_unconfirmed_recovery_key_is_replaced_on_rerun(self):
        res = self.run_script("setup", stdin="yes\nnope\n")
        self.assertEqual(res.returncode, 1)
        self.assertIn("FAILED at step 4: Enroll the recovery key", res.stderr)
        res = self.run_script("setup", stdin=OK_INPUT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("systemd-cryptenroll --wipe-slot=recovery " + str(self.root / "var/lib/gmshield/volume.luks"),
                      self.calls())
        self.assertEqual(sorted(self.st()["slots"]), ["recovery", "tpm2"])

    # ---------- static checks ----------
    def test_bash_syntax_and_shellcheck(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        if shutil.which("shellcheck"):
            res = subprocess.run(["shellcheck", str(SCRIPT)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stdout)


if __name__ == "__main__":
    unittest.main()
