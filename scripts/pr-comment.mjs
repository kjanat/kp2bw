// @ts-check
/** Create or update the generated "Test this PR" comment.
 *
 * Runs from `pull_request_target`, reads trusted base-repo script code, and
 * points `uvx` commands at the PR head repo/ref so fork PRs remain testable.
 */

const DEFAULT_ACCEPTED_PERMISSIONS = 'issues=write; pull_requests=write';
const FENCE = '```';
const COMMENTABLE_FILE_STATUSES = new Set(['added', 'modified', 'renamed', 'removed']);

/** @param {CommentConfig} config @param {string} sourceGitUrl @param {string} ref @returns {string} */
function examplesSection(config, sourceGitUrl, ref) {
	if (!config.cliExamples.trim()) return '';

	const baseCmd = `uvx ${config.pyFlag}--from ${sourceGitUrl}@${ref} ${config.cliName}`;
	const examples = config.cliExamples.replace(/\{cmd\}/g, baseCmd).trim();
	return `

📋 Example usage

${FENCE}bash
${examples}
${FENCE}`;
}

/** @param {ActiveBodyOptions} options @returns {string} */
function activeBody({ marker, config, headGitUrl, headRef, headSha, shortSha }) {
	return `${marker}\n
## 🧪 Test this PR

You can test this PR directly using \`uvx\`:

**From branch:**

${FENCE}bash
uvx ${config.pyFlag}--from ${headGitUrl}@${headRef} ${config.cliName} --help
${FENCE}

**From specific commit (\`${shortSha}\`):**

${FENCE}bash
uvx ${config.pyFlag}--from ${headGitUrl}@${headSha} ${config.cliName} --help
${FENCE}${examplesSection(config, headGitUrl, headRef)}

---

🤖 Auto-updated on push • Commit: ${shortSha}
`;
}

/** @param {ArchivedBodyOptions} options @returns {string} */
function archivedBody({
	marker,
	config,
	archivedGitUrl,
	archivedRef,
	commitMessage,
	headRef,
	isMerged,
	mergeCommitSha,
}) {
	const status = isMerged ? '✅ Merged' : '❌ Closed';
	const mergeInfo = isMerged && mergeCommitSha ? `\n\n**Merge commit:** ${mergeCommitSha}` : '';

	return `${marker}\n
## 📦 Test this PR (archived)

> **Status:** ${status}

This PR has been ${isMerged ? 'merged' : 'closed'}. You can still test the final state:

${FENCE}bash
uvx ${config.pyFlag}--from ${archivedGitUrl}@${archivedRef} ${config.cliName} --help
${FENCE}

📋 PR Details

| Field              | Value            |
|--------------------|------------------|
| **Final commit**   | ${archivedRef}   |
| **Commit message** | ${commitMessage} |
| **Branch**         | \`${headRef}\`   |

${mergeInfo}${examplesSection(config, archivedGitUrl, archivedRef)}

---

🤖 Archived on ${isMerged ? 'merge' : 'close'}
`;
}

/** @param {AsyncFunctionArguments} args */
export default async ({ core, context, github }) => {
	const { owner, repo } = context.repo;
	const pullRequest = parsePullRequest(context.payload);
	const config = readConfig(repo);
	const marker = `<!-- ${repo}-pr-test-comment -->`;
	const shortSha = pullRequest.head.sha.substring(0, 7);
	const baseGitUrl = `git+https://github.com/${owner}/${repo}`;
	const headGitUrl = `git+https://github.com/${pullRequest.head.repo.full_name}`;

	const comments = await github.paginate(
		github.rest.issues.listComments,
		{ owner, repo, issue_number: pullRequest.number },
	);
	const existingComment = comments.find(comment => comment.body?.includes(marker));

	if (!existingComment) {
		const files = await github.paginate(
			github.rest.pulls.listFiles,
			{ owner, repo, pull_number: pullRequest.number },
		);
		const pythonFiles = files.filter(isCommentablePythonFile);

		core.info(`Found ${pythonFiles.length} changed Python files`);
		if (pythonFiles.length === 0) {
			core.info('No Python files changed, skipping comment');
			return;
		}
	}

	let body;
	if (pullRequest.state === 'closed') {
		const archivedRef = pullRequest.merged && pullRequest.merge_commit_sha
			? pullRequest.merge_commit_sha
			: pullRequest.head.sha;
		const archivedGitUrl = pullRequest.merged && pullRequest.merge_commit_sha ? baseGitUrl : headGitUrl;
		const archivedRepo = splitRepository(
			pullRequest.merged && pullRequest.merge_commit_sha
				? `${owner}/${repo}`
				: pullRequest.head.repo.full_name,
		);
		const { data: commit } = await github.rest.git.getCommit({
			owner: archivedRepo.owner,
			repo: archivedRepo.repo,
			commit_sha: archivedRef,
		});

		body = archivedBody({
			marker,
			config,
			archivedGitUrl,
			archivedRef,
			commitMessage: commit.message.split('\n')[0] ?? '',
			headRef: pullRequest.head.ref,
			isMerged: pullRequest.merged,
			mergeCommitSha: pullRequest.merge_commit_sha,
		});
	} else {
		body = activeBody({
			marker,
			config,
			headGitUrl,
			headRef: pullRequest.head.ref,
			headSha: pullRequest.head.sha,
			shortSha,
		});
	}

	try {
		if (existingComment) {
			await github.rest.issues.updateComment({
				owner,
				repo,
				comment_id: existingComment.id,
				body,
			});
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
		if (acceptedPermissions) {
			core.error(errorDetails(error));
			core.setFailed(
				`Could not write PR comment. Event: ${context.eventName}; accepted API permissions: ${acceptedPermissions}. `
					+ 'This workflow requests issues:write and pull-requests:write.',
			);
			return;
		}

		throw error;
	}
};

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

/** @param {unknown} payload @returns {PullRequestPayload} */
function parsePullRequest(payload) {
	const event = requireRecord(payload, 'event payload');
	const pullRequest = requireRecord(event.pull_request, 'pull_request');
	const head = requireRecord(pullRequest.head, 'pull_request.head');
	const headRepo = requireRecord(head.repo, 'pull_request.head.repo');

	return {
		number: requireNumber(pullRequest.number, 'pull_request.number'),
		state: requireString(pullRequest.state, 'pull_request.state'),
		merged: pullRequest.merged === true,
		merge_commit_sha: requireNullableString(
			pullRequest.merge_commit_sha,
			'pull_request.merge_commit_sha',
		),
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

/** @param {string} defaultCliName @returns {CommentConfig} */
function readConfig(defaultCliName) {
	const pythonVersion = process.env.PYTHON_VERSION;
	return {
		cliName: process.env.CLI_NAME || defaultCliName,
		pyFlag: pythonVersion ? `-p${pythonVersion} ` : '',
		cliExamples: process.env.CLI_EXAMPLES || '',
	};
}

/** @typedef {import('@actions/github-script').AsyncFunctionArguments} AsyncFunctionArguments */
/** @typedef {{ owner: string, repo: string }} RepoContext */
/** @typedef {{ full_name: string }} RepoRef */
/** @typedef {{ repo: RepoRef, sha: string, ref: string }} PullRequestHead */

/** @typedef {{
 * number: number,
 * state: string,
 * merged: boolean,
 * merge_commit_sha: string | null,
 * head: PullRequestHead,
 * }} PullRequestPayload
 */

/** @typedef {{
 * cliName: string,
 * pyFlag: string,
 * cliExamples: string,
 * }} CommentConfig
 */

/** @typedef {{
 * filename: string,
 * previous_filename?: string,
 * status: string,
 * }} ChangedFile
 */

/** @typedef {{
 * marker: string,
 * config: CommentConfig,
 * headGitUrl: string,
 * headRef: string,
 * headSha: string,
 * shortSha: string,
 * }} ActiveBodyOptions
 */

/** @typedef {{
 * marker: string,
 * config: CommentConfig,
 * archivedGitUrl: string,
 * archivedRef: string,
 * commitMessage: string,
 * headRef: string,
 * isMerged: boolean,
 * mergeCommitSha: string | null,
 * }} ArchivedBodyOptions
 */

/** @param {ChangedFile} file @returns {boolean} */
function isCommentablePythonFile(file) {
	const isPython = file.filename.endsWith('.py') || file.previous_filename?.endsWith('.py') === true;
	return isPython && COMMENTABLE_FILE_STATUSES.has(file.status);
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
	if (error instanceof Error) {
		return error.stack || error.message;
	}

	return String(error);
}
