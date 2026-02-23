import { checkVersionAction } from './version-check-shared.mjs';

/**
 * GitHub Action to validate the `pykeepass-stubs` package version.
 *
 * The action executes `uv version --package pykeepass-stubs --output-format=json`.
 * Tag values like `stubs-v0.1.0` and `v0.1.0` are normalized before comparison.
 *
 * @param {import('@actions/github-script').AsyncFunctionArguments} args
 * @returns {Promise<{ name: string, version: string, pypi_url: string }>}
 */
export default async ({ core, context, exec }) => {
	return checkVersionAction({
		core,
		context,
		exec,
		packageName: 'pykeepass-stubs',
		tagPrefixes: ['stubs-', 'v'],
	});
};
