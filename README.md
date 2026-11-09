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
                    ► DAST, active           (OWASP ZAP against a throwaway copy in an isolated network)
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

### SonarQube and the human decision

The SonarQube gate **GMshield** (defined in `gates.toml`, applied by `sonar-setup`) requires, on new
code: security, reliability and maintainability ratings of A, at most 3% duplication, and **every
security hotspot reviewed by a person**. A hotspot is code that is only a risk in some contexts, so
the pipeline cannot decide alone: it blocks until you mark each one Safe, Fixed or Acknowledged in
SonarQube, then re-run the branch. Coverage (>= 80%) is listed but disabled until the apps have tests.

```
ssh -L 9000:127.0.0.1:9000 roberto-server          # then open http://localhost:9000
# start it if the pipeline is not running it: cd ~/gmshield-ci/sonarqube && docker compose up -d
# admin password: ~/gmshield-ci/sonarqube/credentials.env on roberto-server
gmshield-results -b develop -r backend --rerun      # from the workstation, after the review
```

SonarQube (26.10 Community Build + PostgreSQL 17, [`sonarqube/compose.yaml`](sonarqube/compose.yaml))
starts on demand for the analysis and stops when the poll ends, unless someone had it open already.
Java projects must export compiled classes to `classes/` in their `test-reports` stage; any
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
| last stage | The production image |

Runtime secrets live only on the server, in `~/gmshield-ci/secrets/<service>.env` (mode 600),
and are injected at deploy time. Nothing secret goes in git.

## Artifacts and results

Every run writes to `~/gmshield-ci/artifacts/<repo>/<branch>/<run-id>/` on roberto-server:
`summary.md`, `summary.json`, `pipeline.log`, and each tool's report (Gitleaks JSON, Semgrep
JSON + SARIF, SonarQube JSON, Trivy JSON, CycloneDX SBOMs for source and image, ZAP
HTML/JSON/Markdown/XML, build and test logs). `artifacts/README.md` indexes all runs;
`releases/<tag>/` records each production release.

On the workstation, results are fetched by hand with
[`workstation/gmshield-results.py`](workstation/gmshield-results.py) (installed as `gmshield-results`).
Each call copies every new report into `~/agentic-RPG/docs/artifacts` (nothing is deleted) and shows:

| Command | Shows |
|---|---|
| `gmshield-results` | the latest result of every repo and branch |
| `gmshield-results -b develop` | the most recent develop run of every repo, stage by stage |
| `gmshield-results -b main -r backend` | the most recent main run of one repo |
| `gmshield-results -b develop -r backend --rerun` | re-runs it on the server first |

## Operations (on roberto-server, in `~/gmshield-ci/runner`)

| Task | Command |
|---|---|
| Status of every repo and branch | `python3 -m gmshield_ci status` |
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
