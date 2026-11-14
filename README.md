# GMshield-pipeline

The CI/CD system for GMshield. It runs entirely on **roberto-server** (a home laptop); GitHub
Actions is not used. A systemd timer polls the `develop` and `main` branches of every GMshield
repository once a minute, runs the checks in Docker containers, enforces quality gates, reports
the verdict to GitHub, and deploys to production on the same machine.

## Flow

```
push to develop ──► Resolve flow
                    ├─ Unit tests            (Dockerfile stage "test")
                    ├─ Secret scan           (Gitleaks, pushed commits; full history on first run)
                    ├─ SAST                  (Semgrep: p/default, p/owasp-top-ten, p/cwe-top-25)
                    └─ SCA, SBOM & IaC       (Trivy: dependencies, CycloneDX SBOM, Dockerfile misconfig)
                    ► SAST & quality         (SonarQube: its "GMshield" quality gate must be OK)
                    ► Container image        (build, SBOM, Trivy image scan)
                    ► Integration tests      (optional [test].target stage beside throwaway services)
                    ► DAST, active           (OWASP ZAP against a throwaway copy in an isolated network,
                                              GMSHIELD_MODE=test, beside its throwaway services)
                    ► Quality gate ──pass──► code is promotable (recorded by its git tree)
                                             + GitHub status gmshield-ci/develop = success

push to main ────► Resolve flow              (only via pull request from develop; GitHub requires
                                              gmshield-ci/develop = success before it allows the merge)
                    ► Promotion check        (this exact tree must have passed develop, else BLOCKED)
                    ► Container image        (rebuild + image gate, catches CVEs published since)
                    ► Publish image          (localhost:5000/gmshield-<service>:<sha>)
                    ► Deploy (prd)           (health-checked; unhealthy -> the previous container,
                                              kept stopped as gmshield-<service>-previous, is restored)
                    ► DAST post-deploy       (ZAP passive baseline; gate fail -> rollback)
                    ► Release                (artifacts/<repo>/releases/<tag>, :prod tag, GitHub release)
```

Earlier commits of a multi-commit push to `develop` each get a light run (secrets, SAST, SCA/IaC),
so every commit has reports. Repositories without a Dockerfile run the source checks only. For this
repository, "deploy" on `main` means the runner updates itself (after the new code's tests pass).

## Quality gates

Defined in [`gates.toml`](gates.toml). Defaults: no leaked secrets; no high-severity Semgrep findings
(medium <= 25); SonarQube quality gate OK; no fixable critical or high CVEs in dependencies or the
image; no critical or high Dockerfile misconfigurations; DAST high = 0 (medium <= 5 on develop,
<= 10 in production); failing unit tests always block. A scanner that crashes or times out blocks
the commit (fail closed). Reviewed false positives are suppressed in the app repo
(`.gitleaksignore`, `nosemgrep`, `.trivyignore`, `.gmshield/zap-ignore.txt`, or "Safe" in SonarQube),
never by loosening the gates.

**Warnings.** Semgrep exits successfully when it cannot fully scan a file, for example when the code
uses syntax newer than its parser (in Java 25: `import module` and statements before `super()`).
Findings in that code may be missing, so the run reports a warning for each such file, with the lines
when Semgrep gives them. A warning never changes the result: it appears in the SAST result,
`summary.md`, `RELEASE.md`, the GitHub status and `gmshield-results` (column `Warn`).

### SonarQube and the human decision

The SonarQube gate **GMshield** (defined in `gates.toml`, applied by `sonar-setup`) requires, on new
code: security, reliability and maintainability ratings of A, at most 3% duplication, and **every
security hotspot reviewed by a person**. A hotspot is code that is only a risk in some contexts, so
the pipeline cannot decide alone: it blocks until you mark each one Safe, Fixed or Acknowledged in
SonarQube, then re-run the branch. Coverage (>= 80%) is listed but disabled until the apps have tests.

```
ssh -N -o ExitOnForwardFailure=no -L 9000:127.0.0.1:9000 roberto-server   # then http://localhost:9000
# start it if the pipeline is not running it: cd ~/gmshield-ci/sonarqube && docker compose up -d
# admin password: ~/gmshield-ci/sonarqube/credentials.env on roberto-server
gmshield-results -b develop -r backend --rerun      # from the workstation, after the review
```

SonarQube (26.10 Community Build + PostgreSQL 17, [`sonarqube/compose.yaml`](sonarqube/compose.yaml))
starts on demand for the analysis and stops when the poll ends, unless someone had it open already.
Java projects must export compiled classes to `classes/` in their `test-reports` stage, and should
export their dependency jars (the test runtime classpath) to `libraries/`: the pipeline then passes
`sonar.java.binaries`, `sonar.java.libraries` and `sonar.java.test.libraries` (the jars plus the compiled main classes). For Java projects the
scanner also gets `sonar.java.jdkHome`: the JDK of the pinned `jdk27` image in `tools.toml` (the
backend's own build image), extracted once into `~/gmshield-ci/cache/jdk/<digest>` and mounted
read-only, so Java 27 types resolve although the scanner runs on an older Java. If the scanner log
still says "Unresolved imports/types", the stage carries a warning (the gate is unchanged). Any
`sonar-project.properties` in a repo (for example coverage report paths under `.gmshield-reports/`)
is honoured.

## GitHub integration

With the token in `~/.config/gmshield/github_token` (fine-grained, GMshield repositories, Commit
statuses and Contents read/write), every full run posts a commit status (`gmshield-ci/develop` or
`gmshield-ci/main`), and every passed `main` run creates a GitHub release. The `main via pull
request` ruleset requires `gmshield-ci/develop` to be green, so GitHub itself refuses to merge code
the pipeline rejected. Without the token everything else still works.

## Repository contract

Each app repository describes itself in `.gmshield/pipeline.toml` (template:
[`templates/pipeline.toml`](templates/pipeline.toml)) and builds with a multi-stage `Dockerfile`:

| Stage | Purpose |
|---|---|
| `test` | Runs the unit tests; a failing test fails the build |
| `test-reports` (optional) | `FROM scratch` stage whose files are exported to the artifacts and to SonarQube (`.gmshield-reports/`) |
| `[test].target` (optional) | Integration tests, run as a container beside throwaway services |
| `[[staging.companions]]` targets (optional) | Run beside the app in staging, e.g. a stand-in backend |
| last stage | The production image |

Runtime secrets live only on the server, in `~/gmshield-ci/secrets/<service>.env` (mode 600),
and are injected at deploy time. Nothing secret goes in git.

Every option is optional, and with every default the containers start exactly as they did before
these options existed. The template documents each option and its default; in short:

| Table | Options | What they do |
|---|---|---|
| `[service]` | `port`, `health_path` | Integer 0-65535; a URL path of letters, digits and `._~%:@+,;=/-` (an optional `?query` may add `&`). `[dast].path` follows the same rule. |
| | `health_scheme` | `"https"`: probes verify the app with `curl --cacert /certs/ca.crt` (only the CA certificate is mounted into the probe). Needs `certs = true`. |
| `[deploy]` | `memory`, `cpus` | Limits, in production and staging alike. `memory` such as `"512m"`, at least `6m`; `cpus` from 0.01 to 64 (normalised, e.g. `"1.50"` -> `1.5`). |
| | `slice` | Production cgroup slice: `containers.slice` or `ai.slice`. Staging always runs in `ci.slice`. |
| | `networks` | Production networks: created on the first, `docker network connect` to the rest, then started. Probes and ZAP join the first only. Every network is checked first; a missing one fails the deploy and production is not touched. |
| | `read_only`, `user`, `cap_drop`, `tmpfs` | Hardening, in production and staging alike; any of the first three adds `--security-opt no-new-privileges` |
| | `mounts` | `{ name, target, read_only }`: the source is a name, never a host path. Production: the Docker named volume `gmshield-<service>-<name>`; staging: a throwaway volume of the run (`gmshield-ci-<run>-<service>-<name>`, carrying the run's label, removed afterwards and by crash cleanup). Docker fills a new volume from the image's folder at `target`, owner included, so the image should create that folder owned by its user. Two mounts, tmpfs entries or the certificates may not share a target, and no target may be `/`. |
| | `certs` | Production: the service's own folder `~/gmshield-ci/certs/<service>/` (`tls.crt`, `tls.key`, `ca.crt`; never another service's key or the CA key) read-only at `/run/gmshield/certs`; a missing folder (or, with `"https"`, a missing `ca.crt` in it) fails the deploy before production is touched. Staging: a throwaway CA and leaf (`ca.crt`, `tls.crt`, `tls.key`, for `app` and `<service>`) made with `openssl` for that run; the private authority never enters `ci.slice`. |
| `[staging]` | `env` | Added over `[deploy].env` in staging only |
| | `services` | `postgres` and/or `redis`, started on the run's internal network under those names and ready (`pg_isready`, `redis-cli ping`) before the app starts |
| | `companions` | `[[staging.companions]] target, alias`: that Dockerfile stage (it must exist) is built and run beside the app as a stand-in, with `GMSHIELD_MODE=test` but without the contract's limits and hardening |
| `[test]` | `target`, `services` | Integration tests on develop (full run, after the image): the stage (it must exist) runs on an internal network beside its services, exit 0 passes, limit `limits.integration_tests` (1800 s). No target: skipped. |

Env keys (`[deploy].env`, `[staging].env`) must be variable names (`[A-Za-z_][A-Za-z0-9_]*`).

**Deploy and rollback.** Before production is touched, the pipeline checks every network and the
certificates folder. It then stops the current container and renames it, unchanged,
`gmshield-<service>-previous`, and creates the new one. If the new container cannot be created,
connected or started, is unhealthy, or fails the post-deploy DAST gate, it is removed and the previous
container is renamed back and started exactly as it was (its own image, networks, mounts and
settings, not rebuilt from the new contract). The previous container is removed once the
post-deploy DAST passes (or fails while `rollback_on_fail` is off). Named volumes are never removed by a deploy.

**Test mode.** The pipeline alone sets `GMSHIELD_MODE=test`, in the staging copy, its companions and
the integration tests; a contract that names `GMSHIELD_MODE` in any env table is refused. The
throwaway services use fixed credentials that match GMshield-backend's `application-test-mode.yaml`:
Postgres at `postgres:5432` with database and user `gmshield` and password `gmshield-test-mode`; Redis
at `redis:6379` without a password. Their images are pinned in `tools.toml`; they join only the run's
internal network, carry the run's label, keep their data in memory, and are removed when the stage
ends (and by the crash cleanup, which also removes the run's labelled volumes and companion and
integration-test images). Never asked for: host paths, `--privileged`, `--cap-add`, host
networking.

## Artifacts and results

Every run writes to `~/gmshield-ci/artifacts/<repo>/<branch>/<run-id>/` on roberto-server:
`summary.md`, `summary.json`, `pipeline.log`, and each tool's report (Gitleaks JSON, Semgrep
JSON + SARIF, SonarQube JSON, Trivy JSON, CycloneDX SBOMs for source and image, ZAP
HTML/JSON/Markdown/XML, build and test logs). `artifacts/README.md` indexes all runs;
`releases/<tag>/` records each production release.

On the workstation, results are fetched by hand with
[`workstation/gmshield-results.py`](workstation/gmshield-results.py) (installed as `gmshield-results`;
nothing is scheduled). Each call fetches new runs (raw copies kept in `~/.cache/gmshield/artifacts`)
and files every run as one release folder in `~/agentic-RPG/docs`, separated by branch:

```
ci-cd/develop/release-develop-<YYYYMMDDTHHMMSSZ>/   RELEASE.md, release.json, artifacts/
ci-cd/main/release-main-<YYYYMMDDTHHMMSSZ>/         RELEASE.md, release.json, artifacts/
```

| Command | Shows |
|---|---|
| `gmshield-results` | the latest result of every repo and branch |
| `gmshield-results -b develop` | the most recent develop run of every repo, test by test |
| `gmshield-results -b main -r backend` | the most recent main run of one repo |
| `gmshield-results -b develop -t sonarqube` | one test (names: `--tests`), with threshold and report paths |
| `gmshield-results --list` / `--release <folder>` | every release folder / one past run |
| `gmshield-results -b develop -r backend --rerun` | re-runs it on the server first |

`docs/CI-CD-RESULTS.md` in the workspace lists the command for every test on both branches.

### Dashboard on the server's screen

roberto-server's own screen (tty1) shows a live, read-only status page split into a `develop` section
and a `main` section (side by side on a wide screen, stacked otherwise). Each lists every repo's latest
full run (PASSED, FAILED or BLOCKED) with one column per pipeline stage (`ok`, `FAIL`, `skip`, or `·`
when the stage never ran), then what blocked it with the gate's reason, the run in progress with its
last log line, and the branch's most recent runs; the `main` section also shows the newest release. It redraws every 5 seconds from
`state/` and `artifacts/` only: it never takes the poll lock, calls GitHub or writes anything.
Detailed reports still come through `gmshield-results`.

- Install once: `sudo bash deploy/install-dashboard.sh` (service `gmshield-dashboard`; the login
  prompt moves to tty2, Ctrl+Alt+F2). Times are shown in `America/Sao_Paulo`; set `DASH_TZ` to change.
- Remove: `sudo bash deploy/install-dashboard.sh --remove`.
- Same view over SSH: `python3 -m gmshield_ci dashboard --once`.

## Operations (on roberto-server, in `~/gmshield-ci/runner`)

| Task | Command |
|---|---|
| Status of every repo and branch | `python3 -m gmshield_ci status` |
| Dashboard, one frame | `python3 -m gmshield_ci dashboard --once` |
| Is the server ready? | `python3 -m gmshield_ci selftest` |
| Re-run a branch by hand | `python3 -m gmshield_ci run backend develop` |
| Apply `gates.toml` changes to SonarQube | `python3 -m gmshield_ci sonar-setup` |
| Follow the poller | `journalctl -u gmshield-ci -f` |
| Pause / resume CI | `touch ~/gmshield-ci/PAUSED` / `rm ~/gmshield-ci/PAUSED` |

The local mirrors in `~/gmshield-ci/mirrors/` are force-synced on every poll, so their `develop`
and `main` always equal GitHub's. Only `develop` and `main` are ever built; pull requests and forks
are not, so no outside code runs on the server.

## Encrypted volume (AD-24)

Everything persistent on roberto-server lives on one LUKS2 volume that the TPM unlocks at boot, so a
removed disk exposes nothing: `/var/lib/gmshield/volume.luks`, a 150 GiB container file on the root
filesystem, mounted at `/srv/gmshield`. Its subfolders are bind-mounted back onto the old paths, so
nothing else changes (not Docker, not Compose, not the pipeline's `install_id`):

| Path | Volume subfolder |
|---|---|
| `/var/lib/docker` (named volumes: Postgres, Redis, Qdrant, registry, SonarQube) | `docker` |
| `/var/lib/containerd` (image layers) | `containerd` |
| `~/gmshield-ci` (secrets, certificates, state, work, artifacts, cache, mirrors, runner) | `gmshield-ci` |
| `~/stack` (data stack Compose file and `.env`) | `stack` |
| `~/.config/gmshield` (GitHub token) | `config-gmshield` |

Swap is a 4 GiB logical volume (`ubuntu-vg/gmshield_swap`) encrypted with a new random key at each
boot (`/dev/mapper/cryptswap`); `/swap.img` is gone. Boot never depends on the volume (`nofail`), but
Docker, containerd, `gmshield-ci` and `gmshield-dashboard` carry `RequiresMountsFor=` drop-ins, so they
never start on empty folders: if the volume does not unlock, SSH still comes up and they stay down.

Run it once, when no pipeline run is going, from the spare checkout `~/gmshield-ci-runner-checkout`
(not from `~/gmshield-ci/runner`, which lives in a store that the script moves), inside `tmux` or
`screen` so a dropped SSH connection does not stop it, and directly in the terminal (not through
`tee` or a logger: the recovery key is printed once):

1. `bash deploy/encrypt-volume.sh plan` changes nothing; with `sudo` it also measures the stores.
2. `sudo bash deploy/encrypt-volume.sh setup` shows where the volume goes and the space it uses, asks
   for `yes`, prints the recovery key, asks for `saved` and then for the key typed back (checked
   against the volume), then stops the CI, the dashboard, every container, Docker and containerd,
   copies the stores, bind-mounts them and starts everything again. It refuses if a pipeline run is
   still going after 15 minutes. The originals stay under `<path>.plain`, and `/swap.img` is only
   switched off. Add `--dry-run` to print every command instead.
3. Reboot.
4. `sudo bash deploy/encrypt-volume.sh status`, then `sudo bash deploy/encrypt-volume.sh finish`: it
   checks that the TPM unlocked the volume at this boot and that every bind mount, the encrypted swap
   and the data stack are up; only then it deletes the `.plain` copies and `/swap.img` (not before)
   and trims the free blocks (plain-text blocks may still remain in the SSD's spare area).

Every step checks first whether it is already done, so after `FAILED at step N` fix the cause and run
the same command again. A failed copy leaves the originals in place and restarts the services on them.

**Reading `status`:** `[done]` or `[  --]` for each setup and finish step; then the volume (open, key
slots, mount), each bind mount, the swap and the data stack; then the finish checks, `all pass` or
each failing one by name. After setup and a reboot expect: key slots `recovery tpm2`, every bind mount
active, encrypted swap active, postgres and redis healthy, qdrant and registry up.

**Recovery key:** the TPM slot is bound to no PCRs (the laptop boots in legacy BIOS, where PCRs add
breakage without protection), so the volume opens on this machine by itself: it protects a removed
disk, not a stolen laptop. If the TPM ever fails to unlock it (TPM cleared, board replaced, disk moved),
Docker stays down; open the volume under its usual name with the recovery key, then start everything:

```bash
sudo systemd-cryptsetup attach gmshield /var/lib/gmshield/volume.luks - luks   # type the recovery key
sudo mount -a
sudo systemctl start containerd docker gmshield-dashboard gmshield-ci.timer ai-healthcheck.timer
cd ~/stack && docker compose up -d
# put a working TPM slot back (asks for the recovery key again):
sudo systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs= /var/lib/gmshield/volume.luks
```

`status` reads the unit `systemd-cryptsetup@gmshield`, so until the next reboot it may report the
volume as not open even though the mounts work.

The container file can grow later without downtime (`cryptsetup resize` may ask for a key: type the
recovery key):

```bash
sudo fallocate -l 200G /var/lib/gmshield/volume.luks
sudo losetup -c "$(losetup -j /var/lib/gmshield/volume.luks | cut -d: -f1)"
sudo cryptsetup resize gmshield
sudo resize2fs /dev/mapper/gmshield
```

## Setup

1. `sudo bash deploy/install-server.sh` (Docker buildx, `ci.slice`, the poller service and timer).
2. Clone this repo to `~/gmshield-ci/runner`; copy `sonarqube/compose.yaml` to
   `~/gmshield-ci/sonarqube/` with a `.env` holding `SONAR_DB_PASSWORD`; run
   `python3 -m gmshield_ci sonar-setup`, then `python3 -m gmshield_ci selftest`.
3. Tests: `python3 -m unittest -v` (gates, parsers and `encrypt-volume.sh` against stubs), `bash tests/e2e.sh` (full pipeline against a
   throwaway local repo, about 30 minutes).

Pinned tool versions and digests: [`tools.toml`](tools.toml). Watched repositories: [`repos.toml`](repos.toml).
