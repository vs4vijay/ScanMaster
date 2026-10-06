FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv
FROM python:3.14.5-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97 AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.14.5-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97
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
