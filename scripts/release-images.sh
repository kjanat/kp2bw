#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repository=${GITHUB_REPOSITORY:?}
image="ghcr.io/${repository,,}"
version=${VERSION:?}
tmp=$(mktemp -d)
trap 'rm -r "${tmp}"' EXIT

fail() {
	echo "$*" >&2
	exit 1
}

remote_digest() {
	if crane digest "$1" 2>"${tmp}/crane.err"; then
		return
	fi
	grep -q -E 'MANIFEST_UNKNOWN|404' "${tmp}/crane.err" || fail "Cannot inspect registry reference $1"
}

publish() {
	local directory=$1 cli arch tag tags candidate checksum previous vw="" bw=""
	for cli in vw bw; do
		if [[ ${cli} == bw ]] && ! [[ -f "${directory}/container-bw-amd64.tar" && -f "${directory}/container-bw-arm64.tar" ]]; then
			echo "bw images were not tested on every architecture; publishing vw images only" >&2
			continue
		fi
		tags=()
		for arch in amd64 arm64; do
			docker load --input "${directory}/container-${cli}-${arch}.tar"
			tag="${image}:build-${GITHUB_RUN_ID:?}-${cli}-${arch}"
			docker tag "kp2bw-production:${cli}-${arch}" "${tag}"
			docker push "${tag}"
			tags+=("${tag}")
		done
		candidate="${image}:build-${GITHUB_RUN_ID}-${cli}"
		docker buildx imagetools create --tag "${candidate}" "${tags[@]}"
		checksum=$(crane digest "${candidate}")
		previous=$(remote_digest "${image}:${version}-${cli}")
		[[ -z ${previous} || ${previous} == "${checksum}" ]] || fail "Refusing to overwrite different image ${image}:${version}-${cli}"
		[[ -n ${previous} ]] || crane tag "${image}@${checksum}" "${version}-${cli}"
		printf -v "${cli}" '%s' "${checksum}"
	done
	previous=$(remote_digest "${image}:${version}")
	[[ -z ${previous} || ${previous} == "${vw}" ]] || fail "Unsuffixed version already identifies a different image"
	[[ -n ${previous} ]] || crane tag "${image}@${vw}" "${version}"
	jq -n -S --arg vw "${vw}" --arg bw "${bw}" '{vw: $vw} + if $bw == "" then {} else {bw: $bw} end' >image-digests.json
	printf 'image=%s\nvw=%s\nbw=%s\n' "${image}" "${vw}" "${bw}" >>"${GITHUB_OUTPUT:?}"
}

verify() {
	local vw bw pair reference checksum attempt actual arch pairs
	vw=$(jq -r .vw image-digests.json)
	bw=$(jq -r '.bw // empty' image-digests.json)
	mkdir "${tmp}/docker"
	pairs=("-vw ${vw}" " ${vw}")
	[[ -z ${bw} ]] || pairs+=("-bw ${bw}")
	for pair in "${pairs[@]}"; do
		reference="${image}:${version}${pair% *}"
		checksum=${pair#* }
		for attempt in {1..30}; do
			if actual=$(DOCKER_CONFIG="${tmp}/docker" crane digest "${reference}" 2>"${tmp}/crane.err"); then
				[[ ${actual} == "${checksum}" ]] || fail "Published digest differs: ${reference}"
				break
			fi
			((attempt < 30)) || fail "Image is not publicly available: ${reference}; check package visibility"
			sleep 10
		done
	done
	for checksum in "${vw}" ${bw:+"${bw}"}; do
		for arch in amd64 arm64; do
			docker --config "${tmp}/docker" pull --platform "linux/${arch}" "${image}@${checksum}"
			docker image rm "${image}@${checksum}"
		done
	done
}

promote() {
	local vw bw current installed newest major minor cli checksum tag
	[[ ${STABLE:?} == true ]] || return 0
	vw=$(jq -r .vw image-digests.json)
	bw=$(jq -r '.bw // empty' image-digests.json)
	current=$(remote_digest "${image}:latest")
	if [[ -n ${current} ]]; then
		installed=$(crane config --platform linux/amd64 "${image}@${current}" | jq -r '.config.Labels["org.opencontainers.image.version"]')
		newest=$(printf '%s\n%s\n' "${installed}" "${version}" | sort -V | tail -n 1)
		[[ ${newest} == "${version}" ]] || fail "Refusing to move stable aliases to an older release"
	fi
	major=${version%%.*}
	minor=${version#*.}
	minor=${minor%%.*}
	for cli in vw bw; do
		checksum=${!cli}
		[[ -n ${checksum} ]] || continue
		for tag in "${cli}" "${major}-${cli}" "${major}.${minor}-${cli}"; do
			crane tag "${image}@${checksum}" "${tag}"
		done
	done
	for tag in latest "${major}" "${major}.${minor}"; do
		crane tag "${image}@${vw}" "${tag}"
	done
}

case ${1:-} in
	publish) publish "${2:-images}" ;;
	verify) verify ;;
	promote) promote ;;
	*) fail "Usage: release-images.sh publish [DIRECTORY] | verify | promote" ;;
esac
