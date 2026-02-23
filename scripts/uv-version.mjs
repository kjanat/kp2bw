// @ts-check

/** @typedef {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
/** @typedef {{ package_name: string, version: string, commit_info: Record<string, unknown> | null }} UvVersionInfo */

/** Normalize a version string for comparison.
 * @param {string} version
 * @returns {string}
 */
function normalizeVersion(version) {
	return version.trim().replace(/^v/, '');
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

/** Executes `uv version` and parses the output as JSON.
 * @param {AsyncFunctionArguments['exec']} exec
 * @returns {Promise<UvVersionInfo>}
 */
async function getUvVersion(exec) {
	let [stdout, stderr] = ['', ''];

	const exitCode = await exec.exec('uv', ['version', '--output-format=json'], {
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
		const reason = error instanceof Error ? error.message : String(error);
		throw new Error(`Failed to parse uv version output as JSON: ${reason}`);
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

	return parsed;
}

/**
 * GitHub Action to check the current project version reported by `uv`.
 *
 * The action executes `uv version --output-format=json` to get the current package version.
 * It then compares this version against a requested version, which can be provided via:
 * - The `version` input for `workflow_dispatch` events.
 * - The `GITHUB_REF_NAME` environment variable for other events.
 *
 * If the current version does not match the requested version, the action fails with an error message.
 * If they match, it returns an object containing the package name, version, and a URL to the PyPI page for that version.
 *
 * @returns {Promise<{ name: string, version: string, pypi_url: string }>} An object with the package name, version, and PyPI URL.
 * @throws {Error} If the `uv version` command fails or if the current version does not match the requested version.
 *
 * @see {@link https://github.com/actions/github-script?tab=readme-ov-file#use-scripts-with-jsdoc-support}
 */

/** @param {AsyncFunctionArguments} args */
export default async ({ core, context, exec }) => {
	/** @param {string} message
	 * @returns {never}
	 */
	const fail = (message) => {
		core.setFailed(message);
		throw new Error(message);
	};

	const currentInfo = await getUvVersion(exec).catch((error) => {
		const reason = error instanceof Error ? error.message : String(error);
		return fail(reason);
	});

	const requestedVersionRaw = resolveRequestedVersion(context);
	if (!requestedVersionRaw) {
		return fail('No requested version was provided (input `version` or `GITHUB_REF_NAME`)');
	}

	const requestedVersion = normalizeVersion(requestedVersionRaw);
	const { package_name: packageName, version: currentVersion } = currentInfo;
	const normalizedCurrentVersion = normalizeVersion(currentVersion);

	if (normalizedCurrentVersion !== requestedVersion) {
		fail(`Current version (${currentVersion}) does not match requested version (${requestedVersionRaw})`);
	}

	return {
		name: packageName,
		version: currentVersion,
		pypi_url: `https://pypi.org/project/${packageName}/${currentVersion}/`,
	};
};
