# GMshield-pipeline

The CI/CD system for GMshield. It runs entirely on **roberto-server** (a home laptop); GitHub
Actions is not used. A systemd timer polls the `develop` and `main` branches of every GMshield
repository once a minute, runs the checks in Docker containers, enforces quality gates, and
deploys to production on the same machine.

## Flow

```
push to develop ──► Resolve flow
                    ├─ Unit tests            (Dockerfile stage "test")
                    ├─ Secret scan           (Gitleaks, pushed commits; full history on first run)
                    ├─ SAST                  (Semgrep: p/default, p/owasp-top-ten, p/cwe-top-25)
                    └─ SCA, SBOM & IaC       (Trivy: dependencies, CycloneDX SBOM, Dockerfile misconfig)
                    ► Container image        (build, SBOM, Trivy image scan)
                    ► DAST, active           (OWASP ZAP against a throwaway copy in an isolated network)
                    ► Quality gate ──pass──► code is promotable (recorded by its git tree)

push to main ────► Resolve flow
                    ► Promotion check        (this exact tree must have passed develop, else BLOCKED)
                    ► Container image        (rebuild + image gate, catches CVEs published since)
                    ► Publish image          (localhost:5000/gmshield-<service>:<sha>)
                    ► Deploy (prd)           (health-checked; unhealthy -> automatic rollback)
                    ► DAST post-deploy       (ZAP passive baseline; gate fail -> rollback)
                    ► Release                (artifacts/<repo>/releases/<tag>, :prod tag, GitHub release*)
```

Earlier commits of a multi-commit push to `develop` each get a light run (secrets, SAST, SCA/IaC),
so every commit has reports. Repositories without a Dockerfile run the source checks only.
`*` GitHub releases and commit statuses need the optional token (see Operations).

## Quality gates

Defined in [`gates.toml`](gates.toml). Defaults: no leaked secrets; no high-severity SAST findings
(medium <= 25); no fixable critical or high CVEs in dependencies or the image; no critical or high
Dockerfile misconfigurations; DAST high = 0 (medium <= 5 on develop, <= 10 in production); failing
unit tests always block. A scanner that crashes or times out blocks the commit (fail closed).
Reviewed false positives are suppressed in the app repo (`.gitleaksignore`, `nosemgrep`,
`.trivyignore`, `.gmshield/zap-ignore.txt`), never by loosening the gates.

## Repository contract

Each app repository describes itself in `.gmshield/pipeline.toml` (template:
[`templates/pipeline.toml`](templates/pipeline.toml)) and builds with a multi-stage `Dockerfile`:

| Stage | Purpose |
|---|---|
| `test` | Runs the unit tests; a failing test fails the build |
| `test-reports` (optional) | `FROM scratch` stage whose files are exported to the artifacts |
| last stage | The production image |

Runtime secrets live only on the server, in `~/gmshield-ci/secrets/<service>.env` (mode 600),
and are injected at deploy time. Nothing secret goes in git.

## Artifacts

Every run writes to `~/gmshield-ci/artifacts/<repo>/<branch>/<run-id>/` on roberto-server:
`summary.md`, `summary.json`, `pipeline.log`, and each tool's report (Gitleaks JSON, Semgrep
JSON + SARIF, Trivy JSON, CycloneDX SBOMs for source and image, ZAP HTML/JSON/Markdown/XML,
build and test logs). `artifacts/README.md` indexes all runs; `releases/<tag>/` records each
production release. The workstation copies them into `~/agentic-RPG/docs/artifacts` with
[`deploy/workstation-sync.sh`](deploy/workstation-sync.sh), which also fast-forwards the local
`develop` and `main` of each clone (never touching unpushed or uncommitted work). Run it every two
minutes with `bash deploy/install-workstation-timer.sh`.

## Operations (on roberto-server)

| Task | Command |
|---|---|
| Status of every repo and branch | `cd ~/gmshield-ci/runner && python3 -m gmshield_ci status` |
| Is the server ready? | `python3 -m gmshield_ci selftest` |
| Re-run a branch by hand | `python3 -m gmshield_ci run GMshield-backend develop` |
| Follow the poller | `journalctl -u gmshield-ci -f` |
| Pause / resume CI | `touch ~/gmshield-ci/PAUSED` / `rm ~/gmshield-ci/PAUSED` |
| Enable GitHub statuses and releases | put a fine-grained token (GMshield repos; Commit statuses and Contents: read/write) in `~/.config/gmshield/github_token`, mode 600 |
| Update the pipeline itself | `git -C ~/gmshield-ci/runner pull --ff-only` |

The local mirrors in `~/gmshield-ci/mirrors/` are force-synced on every poll, so their `develop`
and `main` always equal GitHub's. Only `develop` and `main` are ever built; pull requests and forks
are not, so no outside code runs on the server.

## Setup

1. `sudo bash deploy/install-server.sh` (Docker buildx, `ci.slice`, the poller service and timer).
2. Clone this repo to `~/gmshield-ci/runner`, then `python3 -m gmshield_ci selftest`.
3. Tests: `python3 -m unittest -v` (gates and parsers), `bash tests/e2e.sh` (full pipeline against a
   throwaway local repo, about 30 minutes).

Pinned tool versions and digests: [`tools.toml`](tools.toml). Watched repositories: [`repos.toml`](repos.toml).
