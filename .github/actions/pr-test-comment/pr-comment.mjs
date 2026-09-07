// @ts-check
import { env } from 'node:process';

/** @typedef {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
/** @typedef {AsyncFunctionArguments['github']} Octokit */
/** @typedef {{ owner: string, repo: string }} RepoContext */
/** @typedef {{ full_name: string }} RepoRef */
/** @typedef {{ repo: RepoRef, sha: string, ref: string }} PullRequestHead */
/** @typedef {{ number: number, state: string, merged: boolean, merge_commit_sha: string | null, head: PullRequestHead }} PullRequest */
/** @typedef {{ cliName: string, pyFlag: string, cliExamples: string }} CommentConfig */
/** @typedef {{ filename: string, previous_filename?: string, status: string }} ChangedFile */
/** @typedef {{ gitUrl: string, ref: string, repo: RepoContext }} Source */
/** @typedef {{ config: CommentConfig, head: Source, branch: string }} ActiveBodyOptions */
/** @typedef {{ config: CommentConfig, source: Source, commitMessage: string, branch: string, merged: boolean }} ArchivedBodyOptions */

const FENCE = '```';
const DEFAULT_ACCEPTED_PERMISSIONS = 'issues=write; pull_requests=write';
const CHANGED_FILE_STATUSES = new Set(['added', 'modified', 'renamed', 'removed']);
const PACKAGE_FILES = new Set(['pyproject.toml', 'uv.lock']);
const PACKAGE_DIRS = ['src/', 'packages/'];

/** @param {AsyncFunctionArguments} args */
export default async ({ core, context, github }) => {
	const { owner, repo } = context.repo;
	const pullRequest = parsePullRequest(context.payload);
	const config = readConfig(repo);
	const marker = `<!-- ${repo}-pr-test-comment -->`;
	/** @type {Source} */
	const head = {
		gitUrl: `git+${context.serverUrl}/${pullRequest.head.repo.full_name}`,
		ref: pullRequest.head.sha,
		repo: splitRepository(pullRequest.head.repo.full_name),
	};

	const comments = await github.paginate(
		github.rest.issues.listComments,
		{ owner, repo, issue_number: pullRequest.number },
	);
	const existingComment = comments.find(comment => comment.body?.includes(marker));
	const packageChanged = await touchesPackage(github, { owner, repo }, pullRequest.number);
	core.info(packageChanged ? 'Package files changed' : 'No package files changed, posting the compact form');

	let title;
	let body;
	if (pullRequest.state === 'closed') {
		const mergeSha = pullRequest.merged ? pullRequest.merge_commit_sha : null;
		/** @type {Source} */
		const source = mergeSha === null
			? head
			: { gitUrl: `git+${context.serverUrl}/${owner}/${repo}`, ref: mergeSha, repo: { owner, repo } };
		const { data: commit } = await github.rest.git.getCommit({
			...source.repo,
			commit_sha: source.ref,
		});
		title = '📦 Test this PR (archived)';
		body = archivedBody({
			config,
			source,
			commitMessage: commit.message.split('\n')[0] ?? '',
			branch: pullRequest.head.ref,
			merged: mergeSha !== null,
		});
	} else {
		title = '🧪 Test this PR';
		body = activeBody({ config, head, branch: pullRequest.head.ref });
	}
	body = packageChanged
		? `${marker}\n\n## ${title}\n${body}`
		: `${marker}\n\n<details>\n<summary>${title} (no package changes)</summary>\n${body}\n</details>\n`;

	try {
		if (existingComment) {
			await github.rest.issues.updateComment({ owner, repo, comment_id: existingComment.id, body });
			core.info(`Updated comment ${existingComment.id}`);
			return;
		}
		const { data: newComment } = await github.rest.issues.createComment({
			owner,
			repo,
			issue_number: pullRequest.number,
			body,
		});
		core.info(`Created comment ${newComment.id}`);
	} catch (error) {
		const acceptedPermissions = acceptedPermissionsFor403(error);
		if (acceptedPermissions === undefined) throw error;
		core.error(errorDetails(error));
		core.setFailed(
			`Could not write PR comment. Event: ${context.eventName}; accepted API permissions: ${acceptedPermissions}. `
				+ 'This action needs issues:write and pull-requests:write.',
		);
	}
};

/** @param {ActiveBodyOptions} options @returns {string} */
function activeBody({ config, head, branch }) {
	const shortSha = head.ref.substring(0, 7);
	return `
You can test this PR directly using [\`uvx\`]:

**From branch:**

${FENCE}bash
${uvxCommand(config, head.gitUrl, branch)} --help
${FENCE}

**From specific commit (\`${shortSha}\`):**

${FENCE}bash
${uvxCommand(config, head.gitUrl, head.ref)} --help
${FENCE}${examplesSection(config, head.gitUrl, branch)}

---

🤖 Auto-updated on push • Commit: ${shortSha}

[\`uvx\`]: https://docs.astral.sh/uv/getting-started/installation/
`;
}

/** @param {ArchivedBodyOptions} options @returns {string} */
function archivedBody({ config, source, commitMessage, branch, merged }) {
	const verb = merged ? 'merged' : 'closed';
	return `
> **Status:** ${merged ? '✅ Merged' : '❌ Closed'}

This PR has been ${verb}. You can still test the final state:

${FENCE}bash
${uvxCommand(config, source.gitUrl, source.ref)} --help
${FENCE}

| Field              | Value            |
|--------------------|------------------|
| **${merged ? 'Merge commit' : 'Final commit'}** | ${source.ref} |
| **Commit message** | ${commitMessage} |
| **Branch**         | \`${branch}\`   |${examplesSection(config, source.gitUrl, source.ref)}

---

🤖 Archived on ${merged ? 'merge' : 'close'}
`;
}

/** @param {CommentConfig} config @param {string} gitUrl @param {string} ref @returns {string} */
function examplesSection(config, gitUrl, ref) {
	if (!config.cliExamples.trim()) return '';
	const examples = config.cliExamples.replaceAll('{cmd}', uvxCommand(config, gitUrl, ref)).trim();
	return `

<details>
<summary>📋 Example usage</summary>

${FENCE}bash
${examples}
${FENCE}

</details>`;
}

/** @param {CommentConfig} config @param {string} gitUrl @param {string} ref @returns {string} */
function uvxCommand(config, gitUrl, ref) {
	return `uvx ${config.pyFlag}--from ${shellQuote(`${gitUrl}@${ref}`)} ${config.cliName}`;
}

/** @param {string} value @returns {string} */
function shellQuote(value) {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

/** @param {Octokit} github @param {RepoContext} repo @param {number} pullNumber @returns {Promise<boolean>} */
async function touchesPackage(github, { owner, repo }, pullNumber) {
	const files = await github.paginate(
		github.rest.pulls.listFiles,
		{ owner, repo, pull_number: pullNumber },
	);
	return files.some(isChangedPackageFile);
}

/** @param {ChangedFile} file @returns {boolean} */
function isChangedPackageFile(file) {
	if (!CHANGED_FILE_STATUSES.has(file.status)) return false;
	return [file.filename, file.previous_filename].some(name =>
		name !== undefined && (PACKAGE_FILES.has(name) || PACKAGE_DIRS.some(dir => name.startsWith(dir)))
	);
}

/** @param {string} defaultCliName @returns {CommentConfig} */
function readConfig(defaultCliName) {
	const pythonVersion = env.PYTHON_VERSION;
	return {
		cliName: env.CLI_NAME || defaultCliName,
		pyFlag: pythonVersion ? `-p ${pythonVersion} ` : '',
		cliExamples: env.CLI_EXAMPLES || '',
	};
}

/** @param {unknown} payload @returns {PullRequest} */
function parsePullRequest(payload) {
	const event = requireRecord(payload, 'event payload');
	const pullRequest = requireRecord(event.pull_request, 'pull_request');
	const head = requireRecord(pullRequest.head, 'pull_request.head');
	const headRepo = requireRecord(head.repo, 'pull_request.head.repo');
	return {
		number: requireNumber(pullRequest.number, 'pull_request.number'),
		state: requireString(pullRequest.state, 'pull_request.state'),
		merged: pullRequest.merged === true,
		merge_commit_sha: requireNullableString(pullRequest.merge_commit_sha, 'pull_request.merge_commit_sha'),
		head: {
			repo: { full_name: requireString(headRepo.full_name, 'pull_request.head.repo.full_name') },
			sha: requireString(head.sha, 'pull_request.head.sha'),
			ref: requireString(head.ref, 'pull_request.head.ref'),
		},
	};
}

/** @param {string} fullName @returns {RepoContext} */
function splitRepository(fullName) {
	const [owner, repo, extra] = fullName.split('/');
	if (!owner || !repo || extra !== undefined) {
		throw new Error(`Unexpected repository name: ${fullName}`);
	}
	return { owner, repo };
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
	return typeof value === 'object' && value !== null;
}

/** @param {unknown} value @param {string} label @returns {Record<string, unknown>} */
function requireRecord(value, label) {
	if (isRecord(value)) return value;
	throw new Error(`Expected ${label} to be an object`);
}

/** @param {unknown} value @param {string} label @returns {string} */
function requireString(value, label) {
	if (typeof value === 'string') return value;
	throw new Error(`Expected ${label} to be a string`);
}

/** @param {unknown} value @param {string} label @returns {number} */
function requireNumber(value, label) {
	if (typeof value === 'number') return value;
	throw new Error(`Expected ${label} to be a number`);
}

/** @param {unknown} value @param {string} label @returns {string | null} */
function requireNullableString(value, label) {
	if (value === null || typeof value === 'string') return value;
	throw new Error(`Expected ${label} to be null or a string`);
}

/** @param {unknown} error @returns {string | undefined} */
function acceptedPermissionsFor403(error) {
	if (!isRecord(error) || error.status !== 403) return undefined;
	const response = isRecord(error.response) ? error.response : undefined;
	const headers = response && isRecord(response.headers) ? response.headers : undefined;
	const accepted = headers?.['x-accepted-github-permissions'];
	return typeof accepted === 'string' ? accepted : DEFAULT_ACCEPTED_PERMISSIONS;
}

/** @param {unknown} error @returns {string} */
function errorDetails(error) {
	return error instanceof Error ? error.stack || error.message : String(error);
}
