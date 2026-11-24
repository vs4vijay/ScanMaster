FROM ghcr.io/astral-sh/uv:0.8.3@sha256:ef11ed817e6a5385c02cd49fdcc99c23d02426088252a8eace6b6e6a2a511f36 AS uv
FROM python:3.15.1-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51 AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.15.1-slim@sha256:533b0b2f9b5d46fd097091cf826f27902f1d6c3bca714b6dc74551356aa97a51
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
