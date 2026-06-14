# Sentinel local executor boundary.
# Week 8 only defines the image; Week 9 will add controlled command execution.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system sentinel \
    && useradd --system --gid sentinel --home-dir /workspace --shell /usr/sbin/nologin sentinel \
    && mkdir -p /workspace /tmp/sentinel \
    && chown -R sentinel:sentinel /workspace /tmp/sentinel

WORKDIR /workspace

USER sentinel

CMD ["python", "-c", "print('Sentinel executor image ready; execution wiring is Week 9 scope.')"]
