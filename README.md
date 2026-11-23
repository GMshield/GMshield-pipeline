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
                    ► NFR-1 at rest          (same session, before teardown: a random known text stored
                                              through [nfr1], read back, then searched for in pg_dump,
                                              a Redis RDB, each mounted volume and every log)
                    ► End-to-end             (backend, frontend and worker develop runs only: the three
                                              apps together in test mode with the fake model, driven by
                                              a real browser; see "End-to-end test" below)
                    ► Leak test SM-1         (same runs, on its own stack: two campaigns of one system,
                                              40 questions each, no passage outside a campaign's scope
                                              found, fetched or cited; see "SM-1 leak test" below)
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
<= 10 in production); NFR-1: the run's known text is seeded, read back, its data is present in the
searched stores, and the text is found in no store or log (repositories without `[nfr1]` skip it); failing unit tests always block. A scanner that crashes or times out blocks
the commit (fail closed). Reviewed false positives are suppressed in the app repo
(`.gitleaksignore`, `nosemgrep`, `.trivyignore`, `.gmshield/zap-ignore.txt`, or "Safe" in SonarQube),
never by loosening the gates.

**Warnings.** Semgrep exits successfully when it cannot fully scan a file, for example when the code
uses syntax newer than its parser (in Java 25: `import module` and statements before `super()`).
Findings in that code may be missing, so the run reports a warning for each such file, with the lines
when Semgrep gives them. A warning never changes the result: it appears in the SAST result,
`summary.md`, the artifacts index, `RELEASE.md` and the GitHub status.

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
ssh -o ClearAllForwardings=yes roberto-server 'cd ~/gmshield-ci/runner && python3 -m gmshield_ci run backend develop'   # after the review
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
| `[dast]` | `path`, `openapi` | Where ZAP starts crawling; or, with `openapi` (e.g. `/v3/api-docs`), an API scan of that description on develop. |
| | `auth_header` | One header line `"Name: value"` (an HTTP token as the name, printable ASCII as the value, no line break) that ZAP adds to every scan request, passed to the ZAP container as `ZAP_AUTH_HEADER=<name>` and `ZAP_AUTH_HEADER_VALUE=<value>`. The value goes through the docker CLI's environment and is never printed (not in errors, command lines or the stage summary). Only a public test-mode value belongs here, e.g. the backend's test-mode frontend credential, so that the API scan reaches the controllers instead of meeting 401s. `""` or absent: no header. |
| `[staging]` | `env` | Added over `[deploy].env` in staging only |
| | `services` | `postgres` and/or `redis`, started on the run's internal network under those names and ready (`pg_isready`, `redis-cli ping`) before the app starts |
| | `companions` | `[[staging.companions]] target, alias`: that Dockerfile stage (it must exist) is built and run beside the app as a stand-in, with `GMSHIELD_MODE=test` but without the contract's limits and hardening |
| `[nfr1]` | `seed_path`, `readback_path` | NFR-1 gate (Story 1.7), develop, inside the staging session after ZAP and before teardown. The pipeline makes a random ASCII text, `POST`s `{"text": ...}` to `seed_path` (answer: `{"id": ...}`), `GET`s `readback_path` with `{id}` replaced (answer: a JSON object whose every value is the text), then copies the stores (`pg_dump`, `redis-cli --rdb` with RDB compression off, `docker cp` of each `[deploy].mounts` target) and the logs (app, services, companions) into the run's work folder and searches them for the text (ASCII letters, digits and hyphens) in plain UTF-8; Base64 and Base64url at every alignment, Base64 also with `/` escaped as `\/`; and hex in lower and upper case. Found anywhere, not seeded or not read back, or a store with no trace of the seeded data (the seeded id not in the database dump, a mounted volume with no file, so that "not found" there would prove nothing): the gate fails and names the store. A store that cannot be copied is an error, which still names the stores the text was already found in. `nfr1/nfr1.json` lists every store searched with its size (never the text). Needs `[service].port`. Without the table: skipped. |
| `[test]` | `target`, `services` | Integration tests on develop (full run, after the image): the stage (it must exist) runs on an internal network beside its services, exit 0 passes, limit `limits.integration_tests` (1800 s). No target: skipped. |

Env keys (`[deploy].env`, `[staging].env`) must be variable names (`[A-Za-z_][A-Za-z0-9_]*`).

**Deploy and rollback.** Before production is touched, the pipeline checks every network and the
certificates folder, and runs `deploy/certs.sh check`: a certificate of the private authority that
expires within 30 days becomes a warning of the deploy stage (in every report and on the dashboard);
it never blocks the deploy. It then stops the current container and renames it, unchanged,
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

Results stay on roberto-server; nothing is copied to the workstation. Read them over SSH
(`ssh -o ClearAllForwardings=yes roberto-server '<command>'`, from `~/gmshield-ci/artifacts`):

| Command | Shows |
|---|---|
| `cat README.md` | the latest result of every repo and branch, and the 40 most recent runs |
| `cat GMshield-backend/develop/latest/summary.md` | the most recent run of one repo and branch, test by test |
| `ls GMshield-backend/develop` | every run of one repo and branch (folder `<YYYYMMDD-HHMMSS>-<sha>`, UTC) |
| `scp -r roberto-server:gmshield-ci/artifacts/GMshield-backend/develop/latest/dast .` | one report folder, when it is needed locally |

`docs/CI-CD-RESULTS.md` in the workspace lists the command for every test on both branches.

### Dashboard on the server's screen

roberto-server's own screen (tty1) shows a live, read-only status page split into a `develop` section
and a `main` section (side by side on a wide screen, stacked otherwise). Each lists every repo's latest
full run (PASSED, FAILED or BLOCKED) with one column per pipeline stage (`ok`, `FAIL`, `skip`, or `·`
when the stage never ran), then what blocked it with the gate's reason, the run in progress with its
last log line, and the branch's most recent runs; the `main` section also shows the newest release. It redraws every 5 seconds from
`state/` and `artifacts/` only: it never takes the poll lock, calls GitHub or writes anything.
Detailed reports are in each run's folder under `~/gmshield-ci/artifacts/`.

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
| What housekeeping would remove now | `python3 -m gmshield_ci clean --dry-run` |
| Run housekeeping now (waits for no run in progress) | `python3 -m gmshield_ci clean` |
| Past housekeeping runs | `cat ~/gmshield-ci/state/housekeeping.jsonl` |
| SM-2: sourced answers on the SRD (below) | `python3 -m gmshield_ci sm2 --session-file ~/.config/gmshield/sm2-session` |
| End-to-end test of the latest develop images (below) | `python3 -m gmshield_ci e2e` |
| SM-1 leak test of the latest develop images (below) | `python3 -m gmshield_ci leak` |
| SM-1 with the real model, against production (below) | `python3 -m gmshield_ci sm1 --session-file ~/.config/gmshield/sm1-session` |

### SM-2: sourced answers on the SRD (Story 2.9)

`python3 -m gmshield_ci sm2` asks the fixed SRD 5.2.1 question set (`quality/sm2/questions.json`: 50
questions, 25 in Portuguese and 25 in English, each with short answer phrases and their pages) through
the backend's public API, as the signed-in GM, and records four gates:

| Gate | Passes when |
|---|---|
| Sourced answers (SM-2) | at least 45 of 50 answers cite a passage that holds one of the question's phrases |
| First words (NFR-14) | at least 45 of 50 answers send their first words within 5 s of the turn's creation |
| References open | every reference of every answer opens: its page view, and its picture when the page has one |
| Burst during ingestion (NFR-17) | 5 questions asked at once while a generated 60-page PDF is `processing` all end in `done` |

Exit status: 0 when all four pass, 1 when one fails, 2 when the run cannot start or must stop. A
refused start (no session, no accepted source, indexing still running; exit 2 before any question)
writes nothing; a stop mid-run (a refused renewal, the session ended, Ctrl-C) writes a partial result.

A cited passage is rebuilt from the reference's page view (the lines its boxes overlap, or its range of
a text page's text, plus its part on the next page) and normalised (NFKC, casefold, whitespace
collapsed, a hyphen at a line end joined) before the phrases are looked for: passage ids change at
every ingestion, so the set never names them. Each question is given 300 s, then its turn is stopped
(`timeout`). The burst material is uploaded into the current campaign, never accepted, and discarded
once it needs review (or failed); if it is still processing after an hour, the run says so and it is
discarded by hand in the library.

Before a run:

1. The SRD is accepted in the current campaign's scope and `GET /api/v1/conversations/current` shows
   `indexing: null` (the runner refuses to start otherwise).
2. Dalton signs in with Google in the browser and saves the session cookie's token, the part before
   the last `.`, on the server: `install -D -m 600 /dev/null ~/.config/gmshield/sm2-session`, then paste
   it into that file. The runner renews the session at the start and before it is due, and writes each
   new token back to the file (mode 600).
3. Close the GMshield browser tab without signing out, and do not use the app during the run: after the
   runner renews, a browser call with the old token ends the session the two share.
4. Start it detached, as `docs/CI-CD-RESULTS.md` shows (`setsid nohup python3 -m gmshield_ci sm2 ... >
   ~/sm2-run.log 2>&1 &`). It takes about 50 questions times the answer time (each up to 300 s), plus
   the burst, plus up to an hour waiting for the burst material to need review before it is discarded.

After the run, delete the session file (`rm ~/.config/gmshield/sm2-session`) or sign out in the
browser: the token stays valid until its idle timeout.

Options: `--backend-container` and `--network` (defaults `gmshield-backend`, `gmshield-app`;
`gm27-backend` and `gm27-app` for a temporary develop stack), `--questions` (another set, for a
trial), `--skip-burst` (no burst; the burst gate is then not met). The backend's address and the
frontend's service credential are read from the container (`docker inspect`) at run time; the
credential is never printed or written.

The result goes to `~/gmshield-ci/artifacts/quality/sm2/<UTC yyyy-mm-dd-HHMMSS>-<backend release>/`:
`result.json` (per question: turn id, verdict and reason, timings, cited references with their pages,
section paths and HTTP statuses; the gates; the release tags of the backend, frontend and worker) and
`summary.md`. It holds no answer text and no passage text. Housekeeping never removes these folders.

### End-to-end test with the fake model (Story 2.9)

Every full develop run of GMshield-backend, -frontend and -worker ends, after DAST and NFR-1, with the
`e2e` stage (`gmshield_ci/e2e.py`): the three apps run together, and a real browser walks the chain a
GM walks. It has no gate key: `ok` passes, anything else fails the run, so promotion is blocked.

- **Images.** The run's own image, and for each other app `gmshield-ci/<service>:<sha>` of that repo's
  latest develop run in `state/state.json`, whatever that run's result. When that image is gone (CI
  images are pruned to 3 per service) the stage errors with "no develop image of <repo>; run its develop
  pipeline". After a contract change that spans two repos, one manual `run <repo> develop` re-runs the
  first repo against the second's new image. The three shas are in the stage's metrics and summary line.
- **Containers**, on one throwaway `--internal` network labelled with the run: `postgres` and `redis` (the
  staging services), `stand-in-qdrant` (Qdrant as pinned in `infra/compose.yaml`, no key, storage on
  tmpfs), `stand-in-ollama` (`quality/e2e/stand_in_ollama.py` run with the worker image's Python:
  `POST /api/embed` answers one deterministic 768-number vector per input, from hashed words, and a
  malformed embed body gets 400; any other request is 404), then the backend (`stand-in-backend`), the worker (no alias) and the frontend
  (`frontend`). Each app starts as DAST starts the app under test (`container_args(..., "staging")` with
  its contract read at the image's commit: `GMSHIELD_MODE=test`, caps, hardening, tmpfs, throwaway
  volumes and certificates). The worker's contract points Ollama at the production gateway, so the test
  sets `GMSHIELD_OLLAMA_URL` to the stand-in. The backend must answer `/actuator/health`, the frontend
  `/api/health`, and the worker's HEALTHCHECK must turn healthy (a container without one counts once it
  has run 20 s without exiting), before the browser starts.
- **The driver** (`quality/e2e/driver.py`) runs in Playwright's Python image inside the frontend
  container's network namespace (`--network container:<frontend>`), so Chromium opens
  `http://localhost:3000` and the `__Host-` Secure cookies work over plain HTTP, under the real
  Content-Security-Policy. It reads every label from the frontend's own `src/messages/en.json` at the
  tested commit. The steps, each with its own time limit, stop at the first failure:

  | Step | Passes when |
  |---|---|
  | `sign_in` | the first sign-in through the Google stand-in, with the username step, reaches the questions screen |
  | `upload` | a generated 2-page PDF of invented game content, sent through the guided upload, reaches review |
  | `accept` | Accept makes it ready, and the indexing notice is gone |
  | `ask` | a question about one invented fact in it gets a complete answer (not silent, not an error) listing a reference to it |
  | `open_reference` | the reference opens the source view, its page picture loads (HTTP 200, an image) and the cited passage is marked |

  A Content-Security-Policy violation the browser reports during a step fails that step; one reported
  later (the browser's report arrives asynchronously) fails the stage.
- **Driver image**: Playwright's Python image lacks the `playwright` package, so the stage first builds
  `gmshield-ci/e2e-driver:<hash>` from `quality/e2e/Dockerfile` (the pinned image plus
  `quality/e2e/requirements.txt`, by hash) when it is missing, within its own 900 s, and keeps it.
- **Limit**: `[limits] e2e` (1200 s) starts after the driver image is there. It is checked between the
  start-up phases (each start-up wait also keeps its own `[limits] startup`, 180 s) and bounds the
  browser's run; past it, the stage errors with `timed out`. Every container, volume and network is
  removed at the end, and the run's crash cleanup catches them by label.
- **Files**, in the run folder under `e2e/`: `result.json` (each step's status, seconds and error; the
  outcome, the reason and the three shas), `<step>-failed.png` for a failed step, `driver.log`, `e2e.log`
  and the log of every container. No answer or passage text is written to them; a failure screenshot
  shows only the test's invented PDF and the fake model's answer, never library text.

By hand, against the latest develop image of all three repos: `python3 -m gmshield_ci e2e`. It waits
for no run (it takes the poll lock, so a poll's crash cleanup cannot remove its containers: when a run
is in progress it says so and exits 1), and exits 0 only when every step passes. Its files go to
`~/gmshield-ci/artifacts/quality/e2e/<UTC yyyy-mm-dd-HHMMSS>/`, which housekeeping never removes.
Memory: ci.slice holds about 4.4 GB for the worker's parsing child, the backend's JVM, Chromium and the
services together; the PDF has 2 pages to keep the parsing peak low.

### SM-1 leak test with the fake model (Story 3.13, part A)

Every full develop run of GMshield-backend, -frontend and -worker ends, after `e2e`, with the `leak`
stage (`gmshield_ci/leak.py`): no campaign finds, fetches or cites a passage outside its scope (SM-1,
FR-23). It has no gate key, like `e2e`, and its own column (`Leak`) on the dashboard.

- **Stack.** Its own, started by the same code as `e2e` (`e2e.with_stack`): the same images, stand-ins,
  internal network, labels, limits on start-up and cleanup, under the names `gmshield-ci-<run>-leak-*`.
  No browser: an `e2e` browser failure never hides this verdict.
- **The runner** (`quality/sm1/runner.py`, standard library only) runs with the worker image's Python
  (`python -I`, read-only mount, read-only root, no capability) on the test network. It calls
  `http://stand-in-backend:8080` with the test-mode frontend credential, signs in through the Google
  stand-in as its own new account (`stand-in.sm1.leak@example.test`) and builds the library through the
  public API: system "Vale de Ferro" with its rulebook `R`; its campaigns "Casa", with house rules `HA`
  (each contradicts a rule of `R` and carries a marker word), and "Livro", with by-the-book session notes
  `NB`; a second system "Mar de Cinzas" with its rulebook `X`. The four texts are invented Portuguese
  game content (`quality/sm1/library/`, see `quality/sm1/ATTRIBUTION.txt`), turned into PDFs by
  `sm2.text_pdf`, uploaded, accepted and indexed. Scopes stay at their defaults: Casa may use `R` + `HA`,
  Livro `R` + `NB`. It asks the 40 questions of `quality/sm1/questions.json` (20 pt-BR, 20 en; 24 `house`,
  8 `notes`, 8 `neutral`; part B, the real-model run, asks the same set) in each campaign, one at a time,
  each in a new conversation, then the control. Its record, `runner.json`, holds ids, codes, scope
  versions and timings only.
- **The checks.** The stage reads each material's passage ids from Postgres (by the version id its upload
  returned), maps each turn's job to its conversation's campaign (`turn.job_id` →
  `conversation.campaign_id`), and reads the ids each job found and fetched from the worker's
  `retrieval.search_done` log lines. From Story 4.3 part C answers also find and cite records: the stage reads each
  material's record ids from Postgres too (`select id, version_id from record`), a record id stands for its material
  as a passage id does, and a line's `records` (the record ids the job read) are checked with its `ids`; a record
  citation and a record reference's record id are checked like a passage's. The library holds records for this:
  `HA` (two `fake:record` lines, so Casa finds and cites house records) and `X` (one, never in either campaign's
  scope), which the fake model's records step extracts. Any failed check fails the run:

  | Check | Passes when |
  |---|---|
  | found and fetched | every id in a campaign's jobs' `retrieval.search_done` lines is in the campaign's allowed set |
  | cited | every `citation` event's passage id and every `done` reference's passage ids are in it |
  | clean ends | every turn ends in `done`, not stopped; any `error` fails, and `scope.passage_refused` counts as a found leak |
  | not empty | in each campaign every allowed material is cited at least once, and every `house` question asked in Casa cites `HA` |
  | control | with Livro's other tier on, one `house` question finds `HA` ids (then the tier goes off again); else "control failed: the check cannot see a leak" |

  A failure names the campaign, the question and each foreign id with its material, for example
  `leak found: Livro q07 HA:<id>`; a pass reads `80/80 clean, control ok (backend …, frontend …, worker …)`.
- **Limit**: `[limits] leak` (1800 s) for the whole test: start-up, the library's ingestion, the 80
  questions and the control.
- **Files**, in the run folder under `leak/`: `result.json` (the verdict, each check's failures, per
  campaign and per turn: ids, counts, codes, timings; the three shas), `summary.md`, `runner.json`,
  `runner.log`, `leak.log` and the log of every container. No answer or passage text is written to them.

By hand, against the latest develop image of all three repos: `python3 -m gmshield_ci leak`. Like `e2e`
it takes the poll lock (when a run is in progress it says so and exits 1), removes everything it made,
and exits 0 only when every check passes. Its files go to
`~/gmshield-ci/artifacts/quality/leak/<UTC yyyy-mm-dd-HHMMSS>/`, which housekeeping never removes.

### SM-1 with the real model (Story 3.13, part B)

`python3 -m gmshield_ci sm1` (`gmshield_ci/sm1.py`) runs part A's leak test against the deployed stack, with the
real model, as the signed-in GM. It is not a pipeline stage: part A is the per-run gate. Through the backend's public
API (`quality/sm1/runner.py`, in-process, in its session-given mode: no sign-in) it builds part A's library in the
account under run-suffixed names, for example "Vale de Ferro · sm1 2026-11-23 0130" and "Casa · sm1 2026-11-23 0130",
so the account's other systems never collide: `R` in "Vale de Ferro", `HA` in "Casa", `NB` in "Livro", `X` in "Mar de
Cinzas", the same PDFs as part A. Scopes stay at their defaults, so the account's other systems sit in the "other"
tier, which is off, and model knowledge is off. It asks the 40 questions of `quality/sm1/questions.json` in both
campaigns, one at a time, each in a new questions conversation (300 s each, then the turn is stopped). Then it reads
each material's passage ids through the owner-review page view (`GET /api/v1/materials/{id}/pages/{p}?ground=review`,
every page; no database access), puts the account's current campaign back, and deletes the run's two systems through
the recorded system deletion (Story 3.1 part B: their campaigns, materials and conversations go with them), after a
failure too. `--keep` keeps them for diagnosis; the summary then names what was kept. Names carry the start time
to the second, so a rerun never collides with a kept or still-deleting library.

It holds the CI poll lock for its whole run, so no pipeline run starts meanwhile: a deploy would recreate the
containers whose logs it reads.

Any failed check fails the run:

| Check | Passes when |
|---|---|
| 1. Found and fetched | the ids of each turn's `retrieval.search_done` lines in the worker's log stay inside its campaign's allowed set; the job is matched to the turn through the backend's `conversation.history_read` line (jobId, turnId); a `done` turn with no such line fails |
| 2. Cited | every `citation` id and every `done` reference id is inside the allowed set |
| 3. Clean ends | every turn ends in `done`; `scope.passage_refused` counts as a found leak; other errors (and stopped or timed-out turns) are counted by code, and more than 4 of 80 fail the run, since rate limits may refuse a few |
| 4. Not restated | no Livro answer holds an `HA` marker or house-only phrase (for example "triplicado", where the book says "dobrado"), no Casa answer an `NB` marker, and neither campaign's answers an `X` marker |
| 5. Livro never mentions the house rule | check 4 for Livro and `HA`, reported on its own line, naming each question and marker |
| 6. Not empty | at least 20 of Casa's 24 house answers cite `HA`, and at least 6 of Livro's 8 notes answers cite `NB` |

The markers and phrases live in `quality/sm1/markers.json`: words of the invented library (and their English
translations for the English questions), never answer text, none of them in a question or in a material the
campaign may use. Matching folds case, accents and whitespace and matches at the start of a word, so a stem
("tripl": triplicado, triplica, triplo, triple) covers the inflections. An answer that paraphrases a material without
any listed word is not caught. Each answer's text is read from its `delta` events in memory, matched, and dropped:
only the terms found are kept.

From Story 4.3 part C answers also find and cite records: after the questions the runner reads each material's record
ids from its systems' record lists (`GET /api/v1/systems/{id}/record-types`, every page by `offset` from Story 4.4 part
B, since a system's core and approved types may pass 50; then each type's records, matched to the
material by its name; `recordIds`), so a record id found (a `search_done` line's `records`) or cited stands for its
material as a passage id does. The result and summary count each material's records.

A `done` turn the logs do not show (no `conversation.history_read` line for its job, or no `retrieval.search_done`
line) fails check 1 as "cannot check", not as a leak, and so does an unreadable log, a material whose passage ids
could not be read, or record lists that could not be read (`recordIdsError`: "record ids unread"). The logs are read
from 10 minutes before the start with `docker logs --timestamps --since`; when a log's oldest line is later than the
run's start, the result and summary call it possibly truncated (production rotates logs at 3 x 10 MB).

Exit status: 0 when every check passes; 1 when one fails, or when a pipeline run holds the poll lock (it says "try
again" and makes nothing); 2 when it cannot start (no session file, a stale session: nothing is made, and it says how
to sign in) or when the runner stopped before every question was asked (the result is written, marked incomplete,
and the library is still deleted). A leak or a restatement fails the run even when it stopped early. If the GM's
session ends mid-run (a `session.*` refusal), the run stops at once; the library then cannot be deleted, and the
summary names the systems to delete by hand.

To stop a run, `kill <pid>` (SIGTERM) or Ctrl-C: it stops asking, puts the current campaign back, deletes the
library and writes the result (marked incomplete). Do not `kill -9`, which leaves the library in the account.

Before a run:

1. The release is deployed and its indexing has finished.
2. Dalton signs in with Google in the browser and saves the session cookie's token, the part before the last `.`,
   on the server: `install -D -m 600 /dev/null ~/.config/gmshield/sm1-session`, then paste it into that file. The
   run renews the session first (a refused renewal stops it before anything is made) and before each renewal is due,
   and writes each new token back to the file (mode 600).
3. Close the GMshield browser tab without signing out, and do not use the app during the run: after the runner
   renews, a browser call with the old token ends the session the two share; the run also changes the current
   campaign while it waits for indexing (it puts it back at the end).
4. Start it detached, as `docs/CI-CD-RESULTS.md` shows. It takes the library's ingestion, then 80 questions times the
   answer time, then up to 15 minutes for the backend to log each system's deletion as finished.

After the run, delete the session file or sign out in the browser.

Options: `--backend-container` and `--network` (defaults `gmshield-backend`, `gmshield-app`; `gm27-backend` and
`gm27-app` for a temporary develop stack, whose worker is then `gm27-worker`), `--session-file`, `--keep`. The
backend's address and the frontend's service credential are read from the container (`docker inspect`, as `sm2`);
the credential is never printed or written. The backend's and worker's logs since the run started are read with
`docker logs --since` and held in memory only.

The result goes to `~/gmshield-ci/artifacts/quality/sm1/<UTC yyyy-mm-dd-HHMMSS>-<backend release>/`: `result.json`
(every check's verdict and failures; per turn its ids, how it ended, the materials it cited and the library terms it
held; each material's passage count; the deletion: kept, each system's delete and whether the backend logged it
finished; the release tags of the backend, frontend and worker, resolved as `sm2` does; timings) and `summary.md`.
It holds no answer text and no passage text. Housekeeping never removes these folders. A failing first run is
recorded, not fixed by the run's story: missed gates become a new story.

### Housekeeping (disk space)

Docker data, the run folders and the stack's data share the 150 GB encrypted volume, so the poller
keeps Docker and old results from filling it (`gmshield_ci/housekeeping.py`, settings in
`tools.toml` `[housekeeping]`). It runs at the end of a poll, while that poll still holds the lock, so
it never overlaps or slows a pipeline run: once a day between 03:00 and 06:00 America/Sao_Paulo, once
after every server start (10 minutes after boot, so the stack is up first), and at the next idle
poll (at most hourly) when the volume has less than 15% free.

| What | Removed | Always kept |
|---|---|---|
| Build cache | everything above 40 GB, least recently used first | the layers recent builds use, so builds stay fast |
| `localhost:5000/gmshield-<service>:<sha>` | older tags | `:prod`, images any container uses (also `-previous`, for rollback), the newest 3 |
| `gmshield-ci/<service>:<sha>` | beyond the newest 3; all of them after 30 days with no new image | the newest 3 of an active service |
| Other Docker images | unused and created more than 90 days ago, plus dangling ones | pinned images (`tools.toml` `[images]`, `infra/` and `sonarqube/` compose files), images any container uses |
| Run folders | older than 30 days | the newest 20 per repo and branch, `latest`, the run in `state/state.json`, runs a release links to, `history.jsonl` |

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
| `~/stack` (data stack: a copy of `infra/`, `.env`, `redis-users.acl`) | `stack` |
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

## Data stack and its networks (Story 1.6)

The data stack (Postgres, Redis, Qdrant, the registry) is versioned here, in
[`infra/compose.yaml`](infra/compose.yaml), and deployed by hand: `bash deploy/stack.sh up` copies
`infra/` to `~/stack` (keeping `.env` and `redis-users.acl`), starts or updates it, waits until it is
healthy and creates the backend's role and database when absent. Never edit `~/stack` by hand.

| Network | Subnet | Internet | Members |
|---|---|---|---|
| `gmshield-edge` | 172.30.1.0/24 | no | frontend (later the tunnel) |
| `gmshield-app` | 172.30.2.0/24 | no | frontend, backend |
| `gmshield-data` | 172.30.3.0/24 | no | backend, postgres |
| `gmshield-work` | 172.30.4.0/24 | no | backend, worker, redis, qdrant |
| `gmshield-model` | 172.30.5.0/24 | no | worker; Ollama on the host at the gateway 172.30.5.1:11434 |
| `gmshield-outbound` | 172.30.6.0/24 | yes | backend, worker |
| `gmshield-registry` | 172.30.7.0/24 | yes | registry (127.0.0.1:5000) |

Compose creates every network (a `gmshield-networks` container that only runs `true` holds the ones no
data service joins); the apps join theirs through their contracts. No data service or app publishes a
host port.

**Credentials (AD-23).** `bash deploy/data-credentials.sh` writes each secret once (32 random bytes,
mode 600, never printed; a rerun says `already done`): the stack's own in `~/stack/.env`, the clients'
in `~/gmshield-ci/secrets/<service>.env` (the backend's include `GMSHIELD_VAULT_MASTER_KEY` and
`GMSHIELD_VAULT_INDEX_KEY`, Base64, Story 1.7: an existing vault key is never replaced, since data
encrypted under it would be lost; no off-server copy exists until Epic 10; Story 1.9 adds empty
placeholders `GMSHIELD_GOOGLE_CLIENT_ID=` and `GMSHIELD_GOOGLE_CLIENT_SECRET=`, which Dalton fills by
hand and the script never overwrites; Story 1.10 adds `GMSHIELD_FRONTEND_CREDENTIAL`, one random secret
written to both `backend.env` and `frontend.env`: the frontend sends it as `Authorization: Bearer` on
every `/api/v1` call and the backend refuses any call without it; the script stops when the two files
hold different values; Story 1.12 adds `GMSHIELD_WORKER_CREDENTIAL` the same way, written to both
`backend.env` and `worker.env`: the worker sends it as `Authorization: Bearer` on every `/internal/v1`
call), and the Redis accounts in `~/stack/redis-users.acl` (SHA-256
hashes). Postgres: role `gmshield_backend` owns database `gmshield`, over `hostssl` with SCRAM only;
the superuser `rpg` logs in only on the container's socket (`docker exec -u postgres postgres psql -U
rpg`). Redis: TLS only, `default` off; `backend` on `gmshield:*`; `worker` limited to `AUTH HELLO PING
XREADGROUP XACK XAUTOCLAIM XCLAIM XPENDING` on the two work streams (the backend creates the group
`workers`); `probe` (the health check) to `PING`. Qdrant: one API key, held by the worker.

**Certificates.** `bash deploy/certs.sh issue` creates the private authority in `~/gmshield-ci/ca/`
(mode 700, mounted nowhere) and a 365-day leaf for `postgres`, `redis` and `qdrant` in
`~/gmshield-ci/certs/<service>/` (`tls.crt`, `tls.key`, `ca.crt`); `backend` and `worker` get `ca.crt`
only. Clients verify the chain and the host name. `issue --renew` replaces the leaves (then `stack.sh
up` again); `check` warns about anything expiring within 30 days and always exits 0.

**Ollama (AD-29).** `sudo bash deploy/secure-ollama.sh plan|apply|status` (after `stack.sh up`, since
it needs `gmshield-model`): removes `qwen3.5:4b`, lets only `172.30.5.0/24` reach `172.30.5.1:11434` in
ufw (inserted above the existing deny) and removes the old `172.16.0.0/12` rule, adds the drop-in
`zz-gmshield.conf` (listen on the gateway, after Docker, `OLLAMA_MAX_LOADED_MODELS=1`; `network.conf`
moves to `/var/lib/gmshield/secure-ollama/`), points `/usr/local/bin/ai-healthcheck` at the new address
and restarts Ollama. An SSH tunnel to Ollama must now target `172.30.5.1:11434`.

First deploy, in order (on roberto-server, as roberto, unless it says otherwise):

1. `bash deploy/certs.sh issue`
2. `bash deploy/data-credentials.sh` (rerun it after pulling a version that adds a secret, such as
   Story 1.10's `GMSHIELD_FRONTEND_CREDENTIAL` or Story 1.12's `GMSHIELD_WORKER_CREDENTIAL`, before
   deploying the backend that needs it)
3. Add `GMSHIELD_AZURE_OPENAI_API_KEY=<key>` and
   `GMSHIELD_AZURE_OPENAI_BASE_URL=https://<resource>.openai.azure.com/openai/v1/` by hand to
   `~/gmshield-ci/secrets/worker.env` (mode 600 stays). From Story 2.10 each model provider's key is optional
   (`GMSHIELD_ANTHROPIC_API_KEY` and `GMSHIELD_OPENAI_API_KEY` are the others), the worker refuses to start
   without at least one, and an Azure key without its base URL is refused; the backend's
   `GMSHIELD_MODEL_PROVIDER` (default `azure-openai`) chooses the provider. Remove a placeholder key the worker
   does not really hold: the worker states every provider it has a key for. Fill `GMSHIELD_GOOGLE_CLIENT_ID` and
   `GMSHIELD_GOOGLE_CLIENT_SECRET` by hand in `~/gmshield-ci/secrets/backend.env`, from a Google OAuth
   client whose redirect URI is the backend contract's `GMSHIELD_PUBLIC_URL` followed by
   `/auth/google/callback` (`http://localhost:3000/auth/google/callback`, through the SSH tunnel to the
   frontend); the backend refuses to start without them.
4. `bash deploy/stack.sh up` (also after `certs.sh issue --renew` or a new account list: it recreates
   each service whose certificates, accounts or start script changed since the last successful `up`)
5. `sudo bash deploy/secure-ollama.sh apply`
6. On the workstation: in `~/.ssh/config`, change the Ollama forward of `roberto-server` to
   `LocalForward 11434 172.30.5.1:11434` (Ollama no longer listens on 127.0.0.1).
7. `bash tests/stack_check.sh`: every row of the story's I/O matrix against the live stack
   (`tests/stack_trial.sh [backend image]` runs the same checks against a throwaway copy of the stack).

The apps publish no host port. To reach one by hand, use its address on `gmshield-app` from the server
(`curl http://$(docker inspect -f '{{(index .NetworkSettings.Networks "gmshield-app").IPAddress}}'
gmshield-backend):8080/actuator/health`), or from the workstation forward to that address
(`ssh -N -L 8080:<that address>:8080 roberto-server`; the frontend likewise on port 3000).

## Setup

1. `sudo bash deploy/install-server.sh` (Docker buildx, `ci.slice`, the poller service and timer).
2. Clone this repo to `~/gmshield-ci/runner`; copy `sonarqube/compose.yaml` to
   `~/gmshield-ci/sonarqube/` with a `.env` holding `SONAR_DB_PASSWORD`; run
   `python3 -m gmshield_ci sonar-setup`, then `python3 -m gmshield_ci selftest`.
3. Tests: `python3 -m unittest -v` (gates, parsers, `encrypt-volume.sh` and `secure-ollama.sh` against
   stubs, `certs.sh` and `data-credentials.sh` with the real openssl), `bash tests/e2e.sh` (full pipeline against a
   throwaway local repo, about 30 minutes).

Pinned tool versions and digests: [`tools.toml`](tools.toml). Watched repositories: [`repos.toml`](repos.toml).
