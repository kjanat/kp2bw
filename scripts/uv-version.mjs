import { checkVersionAction } from './version-check-shared.mjs';

/**
 * GitHub Action to check the current project version reported by `uv`.
 *
 * The action executes `uv version --output-format=json` to get the current package version.
 * It then compares this version against a requested version from workflow input or tag name.
 *
 * @param {import('@actions/github-script').AsyncFunctionArguments} args
 * @returns {Promise<{ name: string, version: string, pypi_url: string }>}
 */
export default async ({ core, context, exec }) => {
	return checkVersionAction({
		core,
		context,
		exec,
		tagPrefixes: ['v'],
	});
};
