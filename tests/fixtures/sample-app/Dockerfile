# Pipeline contract: a "test" stage runs unit tests; optional "test-reports" exports results;
# the last stage is the production image.
FROM python:3.13-alpine AS base
# Pick up OS and pip security fixes published after the base image was built.
RUN apk upgrade --no-cache
WORKDIR /app
COPY app.py .

FROM base AS test
COPY test_app.py .
RUN mkdir -p /reports && python -m unittest -v test_app > /reports/unit-tests.txt 2>&1 \
    || (cat /reports/unit-tests.txt; exit 1)

FROM scratch AS test-reports
COPY --from=test /reports /

FROM base AS final
# The running app needs neither pip nor setuptools; removing them shrinks the attack surface
# (pip's vendored copy of setuptools 70.3.0 is otherwise reported as CVE-2025-47273).
RUN python -m pip uninstall -y pip setuptools
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["python", "app.py"]
