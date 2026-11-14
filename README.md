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
                    ► Deploy (prd)           (health-checked; unhealthy -> automatic rollback)
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
`sonar.java.binaries`, `sonar.java.libraries` and `sonar.java.test.libraries`. For Java projects the
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
| `[service]` | `health_scheme` | `"https"`: probes verify the app with `curl --cacert /certs/ca.crt` (only the CA certificate is mounted into the probe). Needs `certs = true`. |
| `[deploy]` | `memory`, `cpus` | Limits, in production and staging alike |
| | `slice` | Production cgroup slice: `containers.slice` or `ai.slice`. Staging always runs in `ci.slice`. |
| | `networks` | Production networks: created on the first, `docker network connect` to the rest, then started. Probes and ZAP join the first only. Every network is checked first; a missing one fails the deploy and production is not touched. |
| | `read_only`, `user`, `cap_drop`, `tmpfs` | Hardening, in production and staging alike; any of the first three adds `--security-opt no-new-privileges` |
| | `mounts` | `{ name, target, read_only }`: the source is a name, never a host path. Production: `~/gmshield-ci/mounts/<service>/<name>` (created 0700); staging: a fresh folder per run. |
| | `certs` | Production: `~/gmshield-ci/certs` read-only at `/run/gmshield/certs`. Staging: a throwaway CA and leaf (`ca.crt`, `tls.crt`, `tls.key`, for `app` and `<service>`) made with `openssl` for that run; the private authority never enters `ci.slice`. |
| `[staging]` | `env` | Added over `[deploy].env` in staging only |
| | `services` | `postgres` and/or `redis`, started on the run's internal network under those names and ready (`pg_isready`, `redis-cli ping`) before the app starts |
| | `companions` | `[[staging.companions]] target, alias`: that Dockerfile stage is built and run beside the app |
| `[test]` | `target`, `services` | Integration tests on develop (full run, after the image): the stage runs on an internal network beside its services, exit 0 passes, limit `limits.integration_tests` (1800 s). No target: skipped. |

**Test mode.** The pipeline alone sets `GMSHIELD_MODE=test`, in the staging copy, its companions and
the integration tests; a contract that names `GMSHIELD_MODE` in any env table is refused. The
throwaway services use fixed credentials that match GMshield-backend's `application-test-mode.yaml`:
Postgres at `postgres:5432` with database and user `gmshield` and password `gmshield-test-mode`; Redis
at `redis:6379` without a password. Their images are pinned in `tools.toml`; they join only the run's
internal network, carry the run's label, keep their data in memory, and are removed when the stage
ends (and by the crash cleanup). Never asked for: host paths, `--privileged`, `--cap-add`, host
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

## Setup

1. `sudo bash deploy/install-server.sh` (Docker buildx, `ci.slice`, the poller service and timer).
2. Clone this repo to `~/gmshield-ci/runner`; copy `sonarqube/compose.yaml` to
   `~/gmshield-ci/sonarqube/` with a `.env` holding `SONAR_DB_PASSWORD`; run
   `python3 -m gmshield_ci sonar-setup`, then `python3 -m gmshield_ci selftest`.
3. Tests: `python3 -m unittest -v` (gates and parsers), `bash tests/e2e.sh` (full pipeline against a
   throwaway local repo, about 30 minutes).

Pinned tool versions and digests: [`tools.toml`](tools.toml). Watched repositories: [`repos.toml`](repos.toml).
