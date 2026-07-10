# Sentinel local executor sandbox image.
# The DockerExecutor overrides CMD with `sh -lc <command>`, so this image only
# provides a minimal non-root shell environment. Network, capabilities, and
# filesystem restrictions are enforced at `docker run` time by the executor.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel --home-dir /workspace --shell /usr/sbin/nologin sentinel \
    && mkdir -p /workspace /tmp/sentinel \
    && chown -R sentinel:sentinel /workspace /tmp/sentinel

WORKDIR /workspace

USER sentinel

# Fallback when run without an explicit command (e.g. compose smoke checks).
CMD ["sh", "-lc", "echo 'Sentinel executor sandbox ready.'"]
