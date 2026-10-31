# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.14-slim-trixie
ARG NODE_IMAGE=node:26-trixie-slim

FROM ${NODE_IMAGE} AS cli
ARG CLI_VERSION
ARG CLI_PACKAGE=@kjanat/vaultwarden-cli
RUN test -n "$CLI_VERSION" \
    && npm install --global --prefix /opt/cli --omit=dev "$CLI_PACKAGE@$CLI_VERSION" \
    && case "$CLI_PACKAGE" in @bitwarden/cli) /opt/cli/bin/bw --version ;; @kjanat/vaultwarden-cli) /opt/cli/bin/vw --version ;; *) exit 1 ;; esac

FROM ${PYTHON_IMAGE} AS package
ARG KP2BW_VERSION
COPY dist/kp2bw-${KP2BW_VERSION}-*.whl /wheels/
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir /wheels/*.whl \
    && /opt/venv/bin/pip check

FROM ${PYTHON_IMAGE}
ARG KP2BW_VERSION
ARG CLI_VERSION
ARG CLI_PACKAGE=@kjanat/vaultwarden-cli
ARG REVISION
ARG PYTHON_IMAGE
ARG NODE_IMAGE
LABEL org.opencontainers.image.title="kp2bw" \
      org.opencontainers.image.source="https://github.com/kjanat/kp2bw" \
      org.opencontainers.image.description="KeePass to Bitwarden migration CLI" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${KP2BW_VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      io.kp2bw.cli.package="${CLI_PACKAGE}" \
      io.kp2bw.cli.version="${CLI_VERSION}" \
      io.kp2bw.python.image="${PYTHON_IMAGE}" \
      io.kp2bw.node.image="${NODE_IMAGE}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libatomic1 libstdc++6 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 kp2bw \
    && useradd --uid 10001 --gid 10001 --create-home kp2bw \
    && mkdir -p /data/bw /data/logs /w \
    && chown -R 10001:10001 /data /w
COPY --from=cli /usr/local/bin/node /usr/local/bin/node
COPY --from=cli /opt/cli /opt/cli
COPY --from=package /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:/opt/cli/bin:$PATH"
RUN cli_command=bw \
    && if [ "$CLI_PACKAGE" = "@kjanat/vaultwarden-cli" ]; then cli_command=vw; fi \
    && test "$("$cli_command" --version)" = "$CLI_VERSION" \
    && test "$(/opt/venv/bin/python -c 'from importlib.metadata import version; print(version("kp2bw"))')" = "$KP2BW_VERSION"
ENV HOME=/home/kp2bw \
    BITWARDENCLI_APPDATA_DIR=/data/bw \
    VW_APPDATA_DIR=/data/bw \
    KP2BW_LOG_DIR=/data/logs
USER 10001:10001
WORKDIR /w
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "kp2bw"]
