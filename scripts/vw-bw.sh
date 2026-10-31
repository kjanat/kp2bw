#!/bin/sh
# Keep kp2bw's bw command contract while using the published vw CLI.
set -eu
export VW_APPDATA_DIR="${BITWARDENCLI_APPDATA_DIR:-${VW_APPDATA_DIR:-/data/bw}}"
if [ "${BW_SESSION+x}" = x ]; then
	export VW_SESSION="$BW_SESSION"
fi
case "${BW_NOINTERACTION-}" in
	true | 1) exec vw --nointeraction "$@" ;;
	*) exec vw "$@" ;;
esac
