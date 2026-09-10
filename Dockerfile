FROM ghcr.io/astral-sh/uv:0.8.3@sha256:ef11ed817e6a5385c02cd49fdcc99c23d02426088252a8eace6b6e6a2a511f36 AS uv
FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6
RUN groupadd --system --gid 10001 scanmaster && useradd --system --uid 10001 --gid scanmaster --home /app scanmaster
WORKDIR /app
COPY --from=builder --chown=scanmaster:scanmaster /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    SCANMASTER_DATABASE_PATH=/data/scanmaster.db \
    SCANMASTER_ARTIFACT_PATH=/data/artifacts
RUN mkdir /data && chown scanmaster:scanmaster /data
USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["scanmaster"]
CMD ["--help"]
