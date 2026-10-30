#!/bin/sh
# Exercise the published vw CLI through kp2bw's existing bw command contract.
# Each test's isolated profile and session must reach vw, including serve children.
set -eu
export VW_APPDATA_DIR="${BITWARDENCLI_APPDATA_DIR:?test profile is required}"
export VW_SESSION="${BW_SESSION-}"
exec vw --nointeraction "$@"
