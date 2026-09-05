<script lang="ts">
	import { resolve } from '$app/paths';

	type Option = {
		flag: string;
		env?: string;
		default: string;
		detail: string;
	};

	const sourceOptions: Option[] = [
		{
			flag: 'FILE',
			env: 'KP2BW_KEEPASS_FILE',
			default: 'Required for migration and KeePass URI reports',
			detail:
				'Path to a KeePass 2.x database. May be omitted only in modes that do not read KeePass.',
		},
		{
			flag: '-k, --keepass-password PASSWORD',
			env: 'KP2BW_KEEPASS_PASSWORD',
			default: 'Prompt securely',
			detail:
				'KeePass database password. Prefer the prompt or environment over a command-line value.',
		},
		{
			flag: '-K, --keepass-keyfile FILE',
			env: 'KP2BW_KEEPASS_KEYFILE',
			default: 'None',
			detail:
				'Key file required to open the KeePass database, when applicable.',
		},
		{
			flag: '-t, --import-tags TAG [TAG ...]',
			env: 'KP2BW_IMPORT_TAGS',
			default: 'All non-excluded entries',
			detail:
				'Import only entries carrying a listed tag. The environment value is a comma-separated list.',
		},
		{
			flag: '--skip-expired, --no-skip-expired',
			env: 'KP2BW_SKIP_EXPIRED',
			default: 'Off',
			detail: 'Exclude or include expired KeePass entries.',
		},
		{
			flag: '--include-recycle-bin, --no-include-recycle-bin',
			env: 'KP2BW_INCLUDE_RECYCLE_BIN',
			default: 'Off',
			detail: 'Include or exclude entries under the KeePass Recycle Bin.',
		},
		{
			flag: '--totp-pps, --no-totp-pps',
			env: 'KP2BW_TOTP_PPS',
			default: 'Off',
			detail:
				'Read Pleasant Password Server TOTPSecret/TOTPDigits/TOTPPeriod fields instead of KeePass TimeOtp-* fields. PPS secrets use Base32 and SHA-1.',
		},
	];

	const destinationOptions: Option[] = [
		{
			flag: '-b, --bitwarden-password PASSWORD',
			env: 'KP2BW_BITWARDEN_PASSWORD',
			default: 'Prompt securely',
			detail:
				'Password used to unlock Bitwarden. Not needed for a KeePass-only URI report.',
		},
		{
			flag: '-o, --bitwarden-org ID',
			env: 'KP2BW_BITWARDEN_ORG',
			default: 'Personal vault',
			detail: 'Create and scope items in this organization.',
		},
		{
			flag: '-c, --bitwarden-collection ID|auto|nested',
			env: 'KP2BW_BITWARDEN_COLLECTION',
			default: 'No collection mapping',
			detail:
				"Use one existing collection ID, 'auto' for top-level KeePass group names, or 'nested' for full group paths. Requires an organization.",
		},
		{
			flag: '--folder, --no-folder',
			env: 'KP2BW_CREATE_FOLDERS',
			default: 'On for personal vault; off with an organization',
			detail:
				'Create personal Bitwarden folders from KeePass groups. --no-folder leaves personal items at the root unless collections apply.',
		},
		{
			flag: '--path-to-name, --no-path-to-name',
			env: 'KP2BW_PATH_TO_NAME',
			default: 'Off',
			detail: 'Prefix each item name with its KeePass group path.',
		},
		{
			flag: '--path-to-name-skip N',
			env: 'KP2BW_PATH_TO_NAME_SKIP',
			default: '1',
			detail:
				'Skip the first N groups when building the item-name prefix. N must be an integer.',
		},
		{
			flag: '--metadata, --no-metadata',
			env: 'KP2BW_MIGRATE_METADATA',
			default: 'On',
			detail:
				'Store tags and expiry in a readable YAML KP2BW_META custom field when present.',
		},
		{
			flag: '--include-oversize-secrets',
			env: 'KP2BW_INCLUDE_OVERSIZE_SECRETS',
			default: 'Off',
			detail:
				'Allow oversized hidden OTP, passkey, and KeePass-protected fields to become plaintext .txt attachments. Without consent they are warned about and dropped, not exposed.',
		},
	];

	const rerunOptions: Option[] = [
		{
			flag: '--update, --no-update',
			env: 'KP2BW_UPDATE',
			default: 'On',
			detail:
				'Sync changed KeePass content and missing or changed attachments onto matched items. --no-update leaves existing content untouched; collection membership may still sync.',
		},
		{
			flag: '--force-update',
			env: 'KP2BW_FORCE_UPDATE',
			default: 'Off',
			detail:
				'Overwrite matched items even when their KP2BW_SYNC stamp shows a later Bitwarden edit. Use only when KeePass must win.',
		},
	];

	const uriOptions: Option[] = [
		{
			flag: '--uri-match MODE',
			env: 'KP2BW_URI_MATCH',
			default: 'default',
			detail:
				'Plain-URL match mode: domain, host, startswith, exact, regex, never, default, or null. default and null leave matching unset so the Bitwarden account setting applies.',
		},
		{
			flag: '--interpret-uri-syntax, --no-interpret-uri-syntax',
			env: 'KP2BW_INTERPRET_URI_SYNTAX',
			default: 'On',
			detail:
				'Interpret KeePassXC additional URLs: double quotes mean exact and * means wildcard. Disable only that syntax handling; invalid, non-web, or unresolved values remain dropped, and Android packages remain transformed.',
		},
		{
			flag: '--report-uris keepass|bitwarden',
			env: 'KP2BW_REPORT_URIS',
			default: 'Off',
			detail:
				'Read-only report of registrable domains containing multiple URI hosts. KeePass source needs FILE; Bitwarden source honors organization and collection scope.',
		},
		{
			flag: '--migrate-uris',
			env: 'KP2BW_MIGRATE_URIS',
			default: 'Off',
			detail:
				'Bitwarden-only, idempotent upgrade: fold legacy KP2A_URL*/AndroidApp custom fields into login URIs, then exit. Honors URI settings and scope; confirms first.',
		},
	];

	const utilityOptions: Option[] = [
		{
			flag: '--strip-ids',
			env: 'KP2BW_STRIP_IDS',
			default: 'Off',
			detail:
				'Bitwarden-only finalization: remove KP2BW_ID and KP2BW_SYNC from in-scope migrated items, then exit. Irreversible and makes future reruns unreliable; confirms first.',
		},
		{
			flag: '-y, --yes',
			env: 'KP2BW_YES',
			default: 'Off',
			detail:
				'Skip the bw setup prompt and confirmations for mutating Bitwarden-only modes.',
		},
		{
			flag: '-v, --verbose',
			env: 'KP2BW_VERBOSE',
			default: 'Off',
			detail: 'Show per-entry kp2bw detail on the console.',
		},
		{
			flag: '-d, --debug',
			env: 'KP2BW_DEBUG',
			default: 'Off',
			detail: 'Show debug and third-party HTTP request logs on the console.',
		},
		{
			flag: '--doctor',
			default: 'Off',
			detail:
				'Print kp2bw, bw, server, installation, and .env diagnostics, then exit. Returns non-zero if bw is unusable.',
		},
		{
			flag: '--redact',
			default: 'Off',
			detail:
				'With --doctor, mask the server URL and home-relative paths before sharing the report.',
		},
		{
			flag: '-V, --version',
			default: '—',
			detail: 'Print the installed kp2bw version and exit.',
		},
		{
			flag: '-h, --help',
			default: '—',
			detail: 'Print the concise command help and exit.',
		},
	];
</script>

<svelte:head>
	<title>kp2bw CLI reference</title>
	<meta
		name="description"
		content="Complete kp2bw CLI option, environment variable, mode, default, and safety reference."
	>
</svelte:head>

<main class="docs-page">
	<header class="docs-hero">
		<a href={resolve('/')}>Back to planner</a>
		<p>command reference</p>
		<h1>kp2bw CLI reference</h1>
		<span>
			Every invocation mode, option, environment mapping, and default. Use
			<code>kp2bw --help</code> for a quick reminder; use this page for
			semantics.
		</span>
	</header>

	<div class="docs-layout">
		<nav aria-label="Documentation sections">
			<a href={resolve('/docs#usage')}>Usage and modes</a>
			<a href={resolve('/docs#precedence')}>Environment</a>
			<a href={resolve('/docs#source')}>KeePass input</a>
			<a href={resolve('/docs#destination')}>Bitwarden output</a>
			<a href={resolve('/docs#reruns')}>Reruns and updates</a>
			<a href={resolve('/docs#uris')}>URI options</a>
			<a href={resolve('/docs#utilities')}>Utility options</a>
			<a href={resolve('/docs#mapping')}>Folders vs collections</a>
			<a href={resolve('/docs#safety')}>Safety and logs</a>
			<a href={resolve('/docs#examples')}>Examples</a>
		</nav>

		<div class="content">
			<section id="usage">
				<p class="eyebrow">usage and modes</p>
				<h2>One executable, several short-circuit modes</h2>
				<pre><code>kp2bw [OPTIONS] FILE
python -m kp2bw [OPTIONS] FILE</code></pre>
				<p>
					The default mode reads <code>FILE</code>, unlocks Bitwarden through
					<code>bw serve</code>, then migrates entries, attachments, OTP and
					passkey fields, tags, expiry, and login URIs. The two invocation forms
					are equivalent.
				</p>
				<div class="fact-grid">
					<article>
						<h3>Migration</h3>
						<p>
							<code>kp2bw [options] FILE</code>. Reads KeePass and writes
							Bitwarden.
						</p>
					</article>
					<article>
						<h3>KeePass-only report</h3>
						<p>
							<code>--report-uris keepass FILE</code>. Reads KeePass and changes
							nothing; no bw CLI or Bitwarden password needed.
						</p>
					</article>
					<article>
						<h3>Bitwarden-only</h3>
						<p>
							<code>--report-uris bitwarden</code>, <code>--migrate-uris</code>,
							and
							<code>--strip-ids</code> need no <code>FILE</code> or KeePass
							password.
						</p>
					</article>
					<article>
						<h3>Diagnostics</h3>
						<p>
							<code>--doctor [--redact]</code>, <code>--version</code>, and
							<code>--help</code> print information and exit.
						</p>
					</article>
				</div>
				<p>
					Choose one special mode per invocation. Among URI report, strip, and
					URI migration, report dispatch precedes strip, which precedes
					migration; relying on that precedence is discouraged.
				</p>
			</section>

			<section id="precedence">
				<p class="eyebrow">environment</p>
				<h2>CLI value → environment → documented default</h2>
				<p>
					kp2bw searches upward from the current working directory for
					<code>.env</code>. A non-empty process environment value wins; an
					unset or empty one may be filled from the file. Explicit command
					options then win over environment values.
				</p>
				<p>
					Boolean environment values accept <code>1/0</code>,
					<code>true/false</code>, <code>yes/no</code>, <code>y/n</code>, or
					<code>on/off</code>, case-insensitively. Invalid values exit with
					status 2.
				</p>
				<pre><code>KP2BW_KEEPASS_PASSWORD=&lt;keepass password&gt;
KP2BW_BITWARDEN_PASSWORD=&lt;bitwarden password&gt;</code></pre>
				<p>
					Protect <code>.env</code> with filesystem permissions and never commit
					it. Prompting is safer on shared systems because command-line
					passwords can appear in shell history and process listings.
				</p>
			</section>

			{#snippet optionList(options: Option[])}
				<div class="option-list">
					{#each options as option (option.flag)}
						<article>
							<h3><code>{option.flag}</code></h3>
							<dl>
								{#if option.env}
									<div>
										<dt>Environment</dt>
										<dd><code>{option.env}</code></dd>
									</div>
								{/if}
								<div>
									<dt>Default</dt>
									<dd>{option.default}</dd>
								</div>
							</dl>
							<p>{option.detail}</p>
						</article>
					{/each}
				</div>
			{/snippet}

			<section id="source">
				<p class="eyebrow">KeePass input and filters</p>
				<h2>Choose the source and included entries</h2>
				{@render optionList(sourceOptions)}
			</section>

			<section id="destination">
				<p class="eyebrow">Bitwarden destination and shape</p>
				<h2>Choose vault scope, hierarchy, and metadata</h2>
				{@render optionList(destinationOptions)}
			</section>

			<section id="reruns">
				<p class="eyebrow">reruns and updates</p>
				<h2>Safe updates are the default</h2>
				<p>
					Migrated items carry a KeePass UUID in <code>KP2BW_ID</code> and a
					content signature in <code>KP2BW_SYNC</code>. Unchanged reruns are
					idempotent. By default, kp2bw updates changed source content but
					protects an item edited in Bitwarden after the prior run.
				</p>
				{@render optionList(rerunOptions)}
			</section>

			<section id="uris">
				<p class="eyebrow">URI matching and maintenance</p>
				<h2>Control autofill matching and inspect collisions</h2>
				<p>
					Additional KeePass URLs such as <code>KP2A_URL</code>,
					<code>URL_1</code>, and <code>AndroidApp</code> become Bitwarden login
					URIs. Quoted-exact and wildcard URLs keep their interpreted modes;
					<code>--uri-match</code> controls plain URLs.
				</p>
				{@render optionList(uriOptions)}
			</section>

			<section id="utilities">
				<p class="eyebrow">finalization, diagnostics, and output</p>
				<h2>Utility options</h2>
				{@render optionList(utilityOptions)}
			</section>

			<section id="mapping">
				<p class="eyebrow">folders vs collections</p>
				<h2>
					Bitwarden folders are personal. Organization structure is collections.
				</h2>
				<p>
					This is the main migration trap. KeePass groups look like folders, but
					a Bitwarden organization does not have org folders. Shared structure
					in an organization is made with collections. Nested collections are
					names with slashes, such as <code>Work/Servers</code>.
				</p>
				<div class="mapping-grid" aria-label="KeePass group mapping examples">
					<div class="mapping-head">KeePass group</div>
					<div class="mapping-head">Nested org collections</div>
					<div class="mapping-head">Top-level org collections</div>
					<div class="mapping-head">Personal folders</div>

					<div><span>KeePass group</span><code>Work/Servers</code></div>
					<div>
						<span>Nested org collections</span><code>Work/Servers</code>
					</div>
					<div><span>Top-level org collections</span><code>Work</code></div>
					<div><span>Personal folders</span><code>Work/Servers</code></div>

					<div><span>KeePass group</span><code>Internet/Banking</code></div>
					<div>
						<span>Nested org collections</span><code>Internet/Banking</code>
					</div>
					<div><span>Top-level org collections</span><code>Internet</code></div>
					<div><span>Personal folders</span><code>Internet/Banking</code></div>
				</div>
				<p>
					For a Vaultwarden organization migration, the usual shape is nested
					collections and no personal folders. That keeps shared data in the org
					model instead of creating a private folder tree beside it.
				</p>
				<p id="personal-folders-under-org">
					Want both? Pass <code>--folder</code> alongside <code>-o</code> (the
					planner's <strong>Also create personal folders</strong> toggle) and
					every item is filed into its org collection <em>and</em> a personal
					folder — the same double-filing Bitwarden's own org import does.
					Leave it off unless you specifically want that private copy.
				</p>
				<div class="fact-grid">
					<article id="full-path-collections">
						<h3>Full-path collections</h3>
						<p>
							<code>-c nested</code>: KeePass <code>Work/Servers</code> becomes
							collection <code>Work/Servers</code>. With <code>-o</code> set,
							personal folders are already off, so no extra flag is needed.
						</p>
					</article>
					<article id="top-folder-collections">
						<h3>Top-folder collections</h3>
						<p>
							<code>-c auto</code>: KeePass <code>Work/Servers</code> and
							<code>Work/Engineering</code> both land in collection
							<code>Work</code>.
						</p>
					</article>
					<article id="single-collection">
						<h3>Single collection</h3>
						<p>
							<code>-c 11111111-1111-1111-1111-111111111111</code>: every
							imported item lands in one existing collection.
						</p>
					</article>
					<article id="flat-org">
						<h3>Flat organization</h3>
						<p>
							<code>-o</code> with no collection mapping: items are created in
							the organization without a generated hierarchy or personal
							folders.
						</p>
					</article>
					<article id="personal-folders">
						<h3>Personal folders</h3>
						<p>
							KeePass groups become personal Bitwarden folders. Use this only
							when importing into a personal vault.
						</p>
					</article>
					<article id="flat-personal">
						<h3>Flat personal</h3>
						<p>
							<code>--no-folder</code>: items stay at the personal vault root.
						</p>
					</article>
				</div>
			</section>

			<section id="safety">
				<p class="eyebrow">safety and operational notes</p>
				<h2>Know what writes, what prompts, and where logs go</h2>
				<ul>
					<li>
						Install and configure <code>bw</code>; for self-hosting run <code>bw
							config server URL</code>, then log in once with <code>bw
							login</code>. kp2bw uses unlock.
					</li>
					<li>
						<code>--report-uris</code> is read-only. <code>--migrate-uris</code>
						mutates matching fields. <code>--strip-ids</code> is irreversible.
					</li>
					<li>
						<code>-c</code> always requires <code>-o</code>. Organization scope
						defaults personal folders off; explicit <code>--folder</code> opts
						into double filing.
					</li>
					<li>
						A declined confirmation exits cleanly. An interrupted migration
						exits 130; partial item or attachment failures produce a non-zero
						exit.
					</li>
					<li>
						A full DEBUG log is always written. Override its location with <code
						>KP2BW_LOG_FILE</code> or directory with <code>KP2BW_LOG_DIR</code>.
					</li>
					<li>
						<code>KP2BW_HTTP_TIMEOUT</code> sets the per-request HTTP timeout in
						seconds. It defaults to 180; values above 3600 are clamped to 3600.
					</li>
				</ul>
				<p>
					Default log directories: <code>%LOCALAPPDATA%/kp2bw/logs</code> on
					Windows, <code>~/Library/Logs/kp2bw</code> on macOS, and
					<code>$XDG_STATE_HOME/kp2bw/logs</code> or
					<code>~/.local/state/kp2bw/logs</code> elsewhere. Logs contain debug
					transport detail; review before sharing.
				</p>
			</section>

			<section id="examples">
				<p class="eyebrow">examples</p>
				<h2>Common complete commands</h2>
				<pre><code># Personal vault; preserve KeePass groups as personal folders
kp2bw vault.kdbx

# Organization; preserve full group paths as nested collections
kp2bw -o 00000000-0000-0000-0000-000000000000 -c nested vault.kdbx

# Organization; map only top-level groups and also create personal folders
kp2bw -o 00000000-0000-0000-0000-000000000000 -c auto --folder vault.kdbx

# Import selected tags, excluding expired and Recycle Bin entries
kp2bw -t work shared --skip-expired vault.kdbx

# Read-only URI collision reports
kp2bw --report-uris keepass vault.kdbx
kp2bw --report-uris bitwarden -o 00000000-0000-0000-0000-000000000000

# Upgrade legacy URL fields in one organization, without reading KeePass
kp2bw --migrate-uris -o 00000000-0000-0000-0000-000000000000

# Final adoption; remove migration stamps after interactive confirmation
kp2bw --strip-ids -o 00000000-0000-0000-0000-000000000000

# Shareable diagnostics
kp2bw --doctor --redact</code></pre>
			</section>
		</div>
	</div>
</main>

<style>
	.docs-page {
		padding: 28px;
		/* font-family inherited from :global(body) — no need to redeclare. */
	}

	.docs-hero,
	.docs-layout {
		max-width: 1120px;
		margin: 0 auto;
	}

	.docs-hero {
		display: grid;
		gap: 10px;
		border-bottom: 1px solid var(--edge);
		padding-bottom: 18px;
	}

	a {
		width: fit-content;
		color: var(--accent);
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}

	.docs-hero p,
	.eyebrow,
	nav a,
	h3 {
		margin: 0;
		color: var(--text-muted);
		font-size: var(--fs-label);
		text-transform: uppercase;
	}

	h1,
	h2,
	h3,
	p {
		letter-spacing: 0;
	}

	h1 {
		max-width: 16ch;
		margin: 0;
		font-family: var(--mono);
		font-size: clamp(2.2rem, 4.5vw, 3.6rem);
		font-weight: 700;
		letter-spacing: -0.02em;
		line-height: 1.05;
	}

	.docs-hero span {
		max-width: 74ch;
		color: var(--text-dim);
		line-height: 1.55;
	}

	.docs-layout {
		display: grid;
		grid-template-columns: 220px minmax(0, 1fr);
		gap: 28px;
		padding-top: 24px;
	}

	.docs-layout > * {
		min-width: 0;
	}

	nav {
		position: sticky;
		top: 24px;
		display: grid;
		align-content: start;
		gap: 10px;
		height: fit-content;
		border: 1px solid var(--edge);
		background: var(--panel);
		padding: 14px;
	}

	.content {
		display: grid;
		gap: 18px;
	}

	section {
		min-width: 0;
		border: 1px solid var(--edge);
		background: var(--panel);
		padding: 24px 24px 26px;
	}

	section > h2 {
		margin: 4px 0 14px;
		color: var(--text);
		font-size: clamp(1.2rem, 2vw, 1.45rem);
		font-weight: 700;
		line-height: 1.3;
	}

	p,
	li {
		max-width: 78ch;
		color: var(--text-dim);
		line-height: 1.62;
	}

	code {
		color: #d8f3df;
		font: inherit;
	}

	pre {
		overflow: auto;
		border: 1px solid var(--code-edge);
		background: var(--code-bg);
		padding: 14px;
		color: #d8f3df;
		white-space: pre;
	}

	.fact-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 6px 22px;
		margin-top: 16px;
	}

	/* Was a bordered box inside a bordered section (box-in-box). A left rule
	   groups each fact without stacking another full border on the panel. */
	.fact-grid article {
		min-width: 0;
		border-left: 2px solid var(--edge);
		padding: 2px 0 6px 14px;
	}

	.fact-grid p {
		margin-bottom: 0;
	}

	.option-list {
		display: grid;
		gap: 18px;
		margin-top: 18px;
	}

	.option-list article {
		min-width: 0;
		border-left: 2px solid var(--edge);
		padding-left: 14px;
	}

	.option-list h3 {
		text-transform: none;
	}

	.option-list dl {
		display: flex;
		flex-wrap: wrap;
		gap: 4px 18px;
		margin: 8px 0 0;
	}

	.option-list dl div {
		display: flex;
		min-width: 0;
		gap: 6px;
	}

	.option-list dt {
		color: var(--text-muted);
		font-size: 0.72rem;
		text-transform: uppercase;
	}

	.option-list dd {
		margin: 0;
		color: var(--text-dim);
	}

	.option-list p {
		margin: 8px 0 0;
	}

	.mapping-grid {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		margin: 16px 0;
		border-top: 1px solid var(--edge);
		border-left: 1px solid var(--edge);
	}

	.mapping-grid > div {
		min-width: 0;
		border-right: 1px solid var(--edge);
		border-bottom: 1px solid var(--edge);
		padding: 10px;
	}

	.mapping-head {
		color: var(--text-muted);
		font-size: 0.74rem;
		text-transform: uppercase;
	}

	.mapping-grid span {
		display: none;
	}

	@media (max-width: 820px) {
		.docs-page {
			padding: 16px;
		}

		.docs-layout,
		.fact-grid,
		.mapping-grid {
			grid-template-columns: 1fr;
		}

		nav {
			position: static;
		}

		pre {
			overflow-wrap: anywhere;
			white-space: pre-wrap;
		}

		p,
		li,
		h2,
		h3,
		code,
		nav a {
			overflow-wrap: anywhere;
		}

		.mapping-head {
			display: none;
		}

		.mapping-grid {
			border-top: 0;
		}

		.mapping-grid > div {
			display: flex;
			justify-content: space-between;
			gap: 14px;
			border-top: 1px solid var(--edge);
		}

		.mapping-grid span {
			display: inline;
			color: var(--text-muted);
			font-size: 0.68rem;
			text-transform: uppercase;
		}

		.option-list dl,
		.option-list dl div {
			display: grid;
			gap: 2px;
		}
	}
</style>
