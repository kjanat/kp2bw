/** @typedef {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
/** @typedef {{ package_name: string, version: string, commit_info: Record<string, unknown> | null }} UvVersionInfo */

/** @typedef {{
 * core: AsyncFunctionArguments['core'],
 * context: AsyncFunctionArguments['context'],
 * exec: AsyncFunctionArguments['exec'],
 * packageName?: string,
 * tagPrefixes?: string[],
 * requestedVersionLabel?: string,
 * }} CheckVersionActionOptions
 */

/** Get a printable error message.
 * @param {unknown} error
 * @returns {string}
 */
function errorMessage(error) {
	return error instanceof Error ? error.message : String(error);
}

/** Normalize a version string for comparison.
 * @param {string} version
 * @param {string[]} prefixes
 * @returns {string}
 */
function normalizeVersion(version, prefixes) {
	let normalized = version.trim();
	for (const prefix of prefixes) {
		if (normalized.startsWith(prefix)) {
			normalized = normalized.slice(prefix.length);
		}
	}

	return normalized;
}

/** Resolve the version requested by the workflow trigger.
 * @param {AsyncFunctionArguments['context']} context
 * @returns {string | undefined}
 */
function resolveRequestedVersion(context) {
	if (context.eventName === 'workflow_dispatch') {
		return context.payload.inputs?.version ?? process.env.GITHUB_REF_NAME;
	}

	return process.env.GITHUB_REF_NAME;
}

/** Build the `uv version` command arguments.
 * @param {string | undefined} packageName
 * @returns {string[]}
 */
function uvVersionArgs(packageName) {
	if (!packageName) {
		return ['version', '--output-format=json'];
	}

	return ['version', '--package', packageName, '--output-format=json'];
}

/** Execute `uv version` and parse the output as JSON.
 * @param {AsyncFunctionArguments['exec']} exec
 * @param {string | undefined} packageName
 * @returns {Promise<UvVersionInfo>}
 */
async function getUvVersionInfo(exec, packageName) {
	let [stdout, stderr] = ['', ''];

	const exitCode = await exec.exec('uv', uvVersionArgs(packageName), {
		silent: true,
		ignoreReturnCode: true,
		listeners: {
			stdout: (data) => {
				stdout += data.toString('utf8');
			},
			stderr: (data) => {
				stderr += data.toString('utf8');
			},
		},
	});

	if (exitCode !== 0) {
		const output = stderr.trim() || stdout.trim() || 'no output';
		throw new Error(`uv version failed (exit ${exitCode}): ${output}`);
	}

	let parsed;
	try {
		parsed = JSON.parse(stdout.trim());
	} catch (error) {
		throw new Error(`Failed to parse uv version output as JSON: ${errorMessage(error)}`);
	}

	if (
		typeof parsed !== 'object'
		|| parsed === null
		|| typeof parsed.package_name !== 'string'
		|| typeof parsed.version !== 'string'
		|| !('commit_info' in parsed)
		|| (
			parsed.commit_info !== null
			&& (typeof parsed.commit_info !== 'object' || parsed.commit_info === null)
		)
	) {
		throw new Error('uv version output has an unexpected shape');
	}

	if (packageName && parsed.package_name !== packageName) {
		throw new Error(
			`uv version returned package ${parsed.package_name} but expected ${packageName}`,
		);
	}

	return parsed;
}

/** Create an action fail handler.
 * @param {AsyncFunctionArguments['core']} core
 * @returns {(message: string) => never}
 */
function createFail(core) {
	return (message) => {
		core.setFailed(message);
		throw new Error(message);
	};
}

/** Validate current version against the requested version.
 * @param {CheckVersionActionOptions} options
 * @returns {Promise<{ name: string, version: string, pypi_url: string }>}
 */
export async function checkVersionAction({
	core,
	context,
	exec,
	packageName,
	tagPrefixes = ['v'],
	requestedVersionLabel = 'No requested version was provided (input `version` or `GITHUB_REF_NAME`)',
}) {
	const fail = createFail(core);

	const currentInfo = await getUvVersionInfo(exec, packageName).catch((error) => {
		return fail(errorMessage(error));
	});

	const requestedVersionRaw = resolveRequestedVersion(context);
	if (!requestedVersionRaw) {
		return fail(requestedVersionLabel);
	}

	const requestedVersion = normalizeVersion(requestedVersionRaw, tagPrefixes);
	const currentVersion = currentInfo.version;
	const normalizedCurrentVersion = normalizeVersion(currentVersion, tagPrefixes);

	if (normalizedCurrentVersion !== requestedVersion) {
		fail(
			`Current version (${currentVersion}) does not match requested version (${requestedVersionRaw})`,
		);
	}

	return {
		name: currentInfo.package_name,
		version: currentVersion,
		pypi_url: `https://pypi.org/project/${currentInfo.package_name}/${currentVersion}/`,
	};
}
