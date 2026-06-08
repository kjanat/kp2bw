#!/usr/bin/env bash
# Generate src/kp2bw/_bw_api_types.py from specs/vault-management-api.json.
# Run from the repo root:
#   bash scripts/generate-bw-types.sh
#
# Requires: uvx (ships with uv)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN_FILE="${REPO_ROOT}/specs/vault-management-api.json"
OUT_FILE="${REPO_ROOT}/src/kp2bw/_bw_api_types.py"

if uvx --from "datamodel-code-generator[ruff]" datamodel-codegen \
	--input "${IN_FILE}" \
	--input-file-type openapi \
	--output-model-type typing.TypedDict \
	--target-python-version 3.14 \
	--no-treat-dot-as-module \
	--collapse-root-models \
	--reuse-model \
	--disable-timestamp \
	--formatters ruff-format ruff-check \
	>"${OUT_FILE}"; then
	echo "Generated ${OUT_FILE}"
else
	echo "Failed to generate ${OUT_FILE}"
	exit 1
fi
