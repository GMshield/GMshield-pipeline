# The end-to-end test's driver image (Story 2.9, gmshield_ci/e2e.py): Playwright's Python image, pinned in tools.toml
# and passed as PLAYWRIGHT_IMAGE, plus the `playwright` package it lacks (requirements.txt, hashes required). Built
# by the pipeline when its tag (a hash of this file, requirements.txt and the base) is missing; the driver script
# itself is mounted at run time, never copied in.
ARG PLAYWRIGHT_IMAGE
FROM ${PLAYWRIGHT_IMAGE}
COPY requirements.txt /tmp/e2e-requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /tmp/e2e-requirements.txt \
    && rm /tmp/e2e-requirements.txt
# Not root by default (pwuser is the image's unprivileged user); the pipeline runs it with --user, as its own user.
USER pwuser
