#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
export LC_ALL=C

version=${VERSION:?}
tag="v${version}"
tmp=$(mktemp -d)
trap 'rm -r "${tmp}"' EXIT

fail() {
	echo "$*" >&2
	exit 1
}

verify_tag() {
	local refs last
	refs=$(git ls-remote origin "refs/tags/${tag}" "refs/tags/${tag}^{}")
	last=${refs##*$'\n'}
	[[ -n ${refs} && ${last%%$'\t'*} == "${GITHUB_SHA:?}" ]] || fail "Release tag is missing or points to another commit"
}

# gh prints "release not found" for a missing tag, drafts included.
load_release() {
	found=true
	if gh release view "${tag}" --json assets,isDraft,isPrerelease,targetCommitish >"${tmp}/release.json" 2>"${tmp}/release.err"; then
		return
	fi
	local error
	error=$(<"${tmp}/release.err")
	[[ ${error} == "release not found" ]] || fail "${error}"
	found=false
}

field() {
	jq -r "$1" "${tmp}/release.json"
}

require_release() {
	load_release
	[[ ${found} == true ]] || fail "Release is missing"
}

attach() {
	local draft path name local_digest remote_digest new=()
	require_release
	draft=$(field .isDraft)
	[[ ${draft} == true ]] || fail "Refusing to change assets of a public release"
	for path in "$@"; do
		name=${path##*/}
		if jq -e --arg name "${name}" 'any(.assets[]; .name == $name)' "${tmp}/release.json" >/dev/null; then
			gh release download "${tag}" --pattern "${name}" --dir "${tmp}"
			remote_digest=$(sha256sum "${tmp}/${name}")
			local_digest=$(sha256sum "${path}")
			[[ ${remote_digest%% *} == "${local_digest%% *}" ]] || fail "Release asset differs: ${name}; resume the original run"
			rm "${tmp}/${name}"
		else
			new+=("${path}")
		fi
	done
	((${#new[@]} == 0)) || gh release upload "${tag}" "${new[@]}"
}

write_notes() {
	local changelog section readme start badge
	changelog=$(<CHANGELOG.md)
	start="## [${version}] - "
	[[ ${changelog} == *"${start}"* ]] || fail "Versioned changelog section is missing"
	section=${changelog#*"${start}"}
	section=${section#*$'\n'}
	section=${section%%$'\n## ['*}
	section=${section#"${section%%[![:space:]]*}"}
	section=${section%"${section##*[![:space:]]}"}
	[[ -n ${section} ]] || fail "Release notes are empty"
	if [[ -f ".github/release-notes/${tag}.md" ]]; then
		cp ".github/release-notes/${tag}.md" "${tmp}/notes.md"
		[[ -s "${tmp}/notes.md" ]] || fail "Release notes are empty"
		generate=false
		return
	fi
	readme=$(<README.md)
	start='<a href="https://pypi.org/project/kp2bw/">'
	[[ ${readme} == *"${start}"* ]] || fail "README has no PyPI badge"
	badge=${readme#*"${start}"}
	badge=${badge%%"</a>"*}
	badge=${badge//"https://img.shields.io/pypi/v/kp2bw?"/"https://img.shields.io/badge/pypi-${version}-3775A9?"}
	section=${section//'### '/'## '}
	# GitHub renders every newline in a release body as a line break.
	section=$(awk '
		/^ *```/ { fence = !fence }
		!fence && /^  [^ ]/ && joinable { line = line " " substr($0, 3); next }
		{ if (NR > 1) print line; line = $0; joinable = !fence && !/^ *```/ && /^(- |  |[^ #|>])/ }
		END { print line }
	' <<<"${section}")
	printf '<a href="https://pypi.org/project/kp2bw/%s/">%s</a>\n\n%s\n' "${version}" "${badge}" "${section}" >"${tmp}/notes.md"
	generate=true
}

draft() {
	local prerelease=true generate matches args
	[[ ${version} =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?$ ]] || fail "Unsupported release version"
	[[ ${STABLE:?} != true ]] || prerelease=false
	verify_tag
	jq -n -c -S --arg commit "${GITHUB_SHA}" --arg version "${version}" --arg run "${GITHUB_RUN_ID:?}" \
		'{commit: $commit, version: $version, run: $run}' >release-source.json
	load_release
	if [[ ${found} == false ]]; then
		write_notes
		args=(gh release create "${tag}" release-source.json --draft --target "${GITHUB_SHA}"
			--title "kp2bw ${version}" --notes-file "${tmp}/notes.md")
		[[ ${generate} == false ]] || args+=(--generate-notes)
		[[ ${prerelease} == false ]] || args+=(--prerelease)
		"${args[@]}"
		return
	fi
	matches=$(jq -r --arg sha "${GITHUB_SHA}" --argjson prerelease "${prerelease}" \
		'[.isDraft and .targetCommitish == $sha, .isPrerelease == $prerelease] | map(tostring) | join(" ")' \
		"${tmp}/release.json")
	[[ ${matches%% *} == true ]] || fail "Release is public or belongs to another commit"
	[[ ${matches##* } == true ]] || fail "Release stability does not match the requested version"
	attach release-source.json
}

stage() {
	local directory=$1 manifest=$2 file digest files=()
	: >"${tmp}/digests"
	for file in "${directory}"/*; do
		[[ -f ${file} && ${file##*/} != "${manifest}" ]] || continue
		files+=("${file}")
		digest=$(sha256sum "${file}")
		printf '%s\t%s\n' "${file##*/}" "${digest%% *}" >>"${tmp}/digests"
	done
	jq -n -R -S --indent 2 '[inputs | split("\t") | {(.[0]): .[1]}] | add // {}' "${tmp}/digests" >"${directory}/${manifest}"
	attach "${files[@]}" "${directory}/${manifest}"
}

fetch_pypi() {
	code=$(curl --silent --location --max-time 30 --output "${tmp}/pypi.json" --write-out '%{http_code}' \
		"https://pypi.org/pypi/kp2bw/${version}/json") || code=000
}

pypi_field() {
	jq -r --arg name "$1" ".urls[] | select(.filename == \$name) | .$2" "${tmp}/pypi.json"
}

check_pypi() {
	local directory=$1 code file remote digest
	fetch_pypi
	[[ ${code} != 404 ]] || return 0
	[[ ${code} == 200 ]] || fail "PyPI returned HTTP ${code}"
	for file in "${directory}"/*; do
		remote=$(pypi_field "${file##*/}" digests.sha256)
		[[ -n ${remote} ]] || continue
		digest=$(sha256sum "${file}")
		[[ ${remote} == "${digest%% *}" ]] || fail "PyPI already contains different bytes for ${file##*/}"
	done
}

verify_pypi() {
	local directory=$1
	local code file name remote url digest attempt ready files=("${directory}"/*.whl "${directory}"/*.tar.gz)
	((${#files[@]} == 2)) || fail "Expected a wheel and a source distribution"
	for attempt in {1..30}; do
		fetch_pypi
		if [[ ${code} == 200 ]]; then
			ready=true
			for file in "${files[@]}"; do
				remote=$(pypi_field "${file##*/}" digests.sha256)
				[[ -n ${remote} ]] || ready=false
			done
			if [[ ${ready} == true ]]; then
				for file in "${files[@]}"; do
					name=${file##*/}
					remote=$(pypi_field "${name}" digests.sha256)
					digest=$(sha256sum "${file}")
					[[ ${remote} == "${digest%% *}" ]] || fail "PyPI has different bytes for ${name}"
					url=$(pypi_field "${name}" url)
					curl --fail --silent --show-error --location --max-time 60 --output "${tmp}/${name}" "${url}"
					digest=$(sha256sum "${tmp}/${name}")
					[[ ${digest%% *} == "${remote}" ]] || fail "PyPI download differs: ${name}"
				done
				return
			fi
		elif [[ ${code} != 404 && ${code} != 000 && ${code} -lt 500 ]]; then
			fail "PyPI returned HTTP ${code}"
		fi
		((attempt == 30)) || sleep 10
	done
	fail "PyPI files did not become publicly available"
}

finalize() {
	local target draft
	verify_tag
	require_release
	target=$(field .targetCommitish)
	[[ ${target} == "${GITHUB_SHA}" ]] || fail "Release commit changed"
	draft=$(field .isDraft)
	[[ ${draft} == false ]] || gh release edit "${tag}" --draft=false --latest="${STABLE:?}"
}

case ${1:-} in
	draft) draft ;;
	stage) stage "${2:-dist}" "${3:-distribution-sha256.json}" ;;
	check-pypi) check_pypi "${2:-dist}" ;;
	verify-pypi) verify_pypi "${2:-dist}" ;;
	finalize) finalize ;;
	*) fail "Usage: release.sh draft | stage [DIRECTORY MANIFEST] | check-pypi [DIRECTORY] | verify-pypi [DIRECTORY] | finalize" ;;
esac
