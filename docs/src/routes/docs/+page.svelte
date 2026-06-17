<script lang="ts">
	import { resolve } from '$app/paths';
</script>

<svelte:head>
	<title>kp2bw migration notes</title>
	<meta
		name="description"
		content="How kp2bw maps KeePass entries, folders, metadata, URLs, and reruns into Bitwarden."
	>
</svelte:head>

<main class="docs-page">
	<header class="docs-hero">
		<a href={resolve('/')}>Back to planner</a>
		<p>migration notes</p>
		<h1>How kp2bw moves a vault</h1>
		<span>
			The planner gives you a command. This page explains the Bitwarden model
			behind it, especially the folder and collection choices that matter for
			organization migrations.
		</span>
	</header>

	<div class="docs-layout">
		<nav aria-label="Documentation sections">
			<a href={resolve('/docs#moves')}>What moves</a>
			<a href={resolve('/docs#options')}>Planner options</a>
			<a href={resolve('/docs#mapping')}>Folders vs collections</a>
			<a href={resolve('/docs#recommended')}>Default org command</a>
			<a href={resolve('/docs#reruns')}>Running again</a>
			<a href={resolve('/docs#urls')}>URL handling</a>
			<a href={resolve('/docs#after')}>After migration</a>
			<a href={resolve('/docs#credentials')}>Credentials</a>
		</nav>

		<div class="content">
			<section id="moves">
				<p class="eyebrow">what moves</p>
				<h2>kp2bw is not just a CSV-style import</h2>
				<p>
					It reads a KeePass 2.x database and creates Bitwarden items through
					<code>bw serve</code>. Entries, group paths, attachments,
					passkey-related fields, OTP-related fields, tags, expiry data, and
					login URIs are mapped into Bitwarden shapes instead of being dumped as
					plain notes.
				</p>
				<div class="fact-grid">
					<article>
						<h3>Entries</h3>
						<p>
							Titles, usernames, passwords, notes, custom fields, and identities
							are migrated as Bitwarden item data.
						</p>
					</article>
					<article>
						<h3>Attachments</h3>
						<p>
							Files attached to KeePass entries are uploaded after their
							Bitwarden item exists.
						</p>
					</article>
					<article>
						<h3>Metadata</h3>
						<p>
							Tags and expiry are kept in a readable <code>KP2BW_META</code>
							field when Bitwarden has no native slot.
						</p>
					</article>
					<article>
						<h3>Identity stamps</h3>
						<p>
							<code>KP2BW_ID</code> lets reruns match the same KeePass entry
							instead of guessing by title.
						</p>
					</article>
				</div>
			</section>

			<section id="options">
				<p class="eyebrow">planner options</p>
				<h2>Each option changes placement, filtering, or rerun behavior</h2>
				<div class="fact-grid">
					<article id="target-vault">
						<h3>Target vault</h3>
						<p>
							Organization means shared Bitwarden collections. Personal means
							your own vault and optional personal folders.
						</p>
					</article>
					<article id="organization-id">
						<h3>Organization ID</h3>
						<p>
							The value passed with <code>-o</code>. Use the Bitwarden
							organization ID for the destination org.
						</p>
					</article>
					<article id="collection-id">
						<h3>Collection ID</h3>
						<p>
							The value passed with <code>-c</code> when every imported item
							should land in one existing collection.
						</p>
					</article>
					<article id="keepass-file">
						<h3>KeePass file</h3>
						<p>
							The final command argument. Point it at the <code>.kdbx</code>
							database to migrate.
						</p>
					</article>
					<article id="key-file">
						<h3>Key file</h3>
						<p>
							Adds <code>-K</code> when the KeePass database also needs a key
							file.
						</p>
					</article>
					<article id="tag-filter">
						<h3>Tag filter</h3>
						<p>
							Adds <code>-t</code> values. Empty means every non-excluded entry
							is included.
						</p>
					</article>
					<article id="filters">
						<h3>Filters</h3>
						<p>
							Filters decide which KeePass entries are part of the plan before
							collections or folders are calculated.
						</p>
					</article>
					<article id="skip-expired">
						<h3>Skip expired</h3>
						<p>
							Adds <code>--skip-expired</code>. Expired KeePass entries are
							included unless this is enabled.
						</p>
					</article>
					<article id="recycle-bin">
						<h3>Recycle Bin</h3>
						<p>
							Adds <code>--include-recycle-bin</code>. Recycle Bin entries are
							excluded by default.
						</p>
					</article>
				</div>
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
				<div class="fact-grid">
					<article id="full-path-collections">
						<h3>Full-path collections</h3>
						<p>
							<code>-c nested --no-folder</code>: KeePass
							<code>Work/Servers</code> becomes collection
							<code>Work/Servers</code>.
						</p>
					</article>
					<article id="top-folder-collections">
						<h3>Top-folder collections</h3>
						<p>
							<code>-c auto --no-folder</code>: KeePass
							<code>Work/Servers</code> and <code>Work/Engineering</code> both
							land in collection <code>Work</code>.
						</p>
					</article>
					<article id="single-collection">
						<h3>Single collection</h3>
						<p>
							<code>-c 11111111-1111-1111-1111-111111111111 --no-folder</code>:
							every imported item lands in one existing collection.
						</p>
					</article>
					<article id="flat-org">
						<h3>Flat organization</h3>
						<p>
							<code>--no-folder</code> without collection creation: items are
							created without a generated hierarchy.
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

			<section id="recommended">
				<p class="eyebrow">recommended org migration</p>
				<h2>Start with full-path organization collections</h2>
				<p>
					Use an organization ID, map full KeePass group paths to collections,
					and omit personal folders:
				</p>
				<pre><code># .env
KP2BW_KEEPASS_PASSWORD=&lt;keepass password&gt;
KP2BW_BITWARDEN_PASSWORD=&lt;bitwarden password&gt;

kp2bw -o 00000000-0000-0000-0000-000000000000 -c nested --no-folder vault.kdbx</code></pre>
				<p>
					Choose top-level collections if you need fewer collections. Choose one
					existing collection only when you intentionally want to flatten the
					KeePass group tree into a single shared place.
				</p>
			</section>

			<section id="reruns">
				<p class="eyebrow">running again</p>
				<h2>Choose the situation, not the flag name</h2>
				<p>
					Every migrated item carries <code>KP2BW_ID</code>, the KeePass UUID
					used to match the same item next time. kp2bw also writes a
					<code>KP2BW_SYNC</code> content stamp. Those markers let kp2bw decide
					whether an existing Bitwarden item is still safe to update.
				</p>
				<ul>
					<li>
						KeePass is still my main vault: use <code>--force-update</code>.
					</li>
					<li>
						Mostly Bitwarden, sync forgotten KeePass edits: default mode.
					</li>
					<li>
						Testing migrations against an existing Vaultwarden DB: use
						<code>--no-update</code>.
					</li>
				</ul>
				<div class="fact-grid">
					<article id="force-update">
						<h3>KeePass is still my main vault</h3>
						<p>
							<code>--force-update</code>: KeePass content wins over later
							Bitwarden edits. Use this when KeePass is still the source of
							truth.
						</p>
					</article>
					<article id="safe-rerun">
						<h3>Mostly Bitwarden, sync forgotten KeePass edits</h3>
						<p>
							Default mode. kp2bw updates migrated items when Bitwarden has not
							been edited since the last kp2bw run.
						</p>
					</article>
					<article id="no-update">
						<h3>Testing migrations; keep the existing Vaultwarden DB</h3>
						<p>
							<code>--no-update</code>: create missing items only. Existing
							migrated items stay untouched, so you do not need to wipe the DB
							just to try another pass.
						</p>
					</article>
				</div>
			</section>

			<section id="urls">
				<p class="eyebrow">url handling</p>
				<h2>Additional URLs become real login URIs</h2>
				<p>
					KeePass fields like <code>KP2A_URL</code>, <code>URL_1</code>, and
					<code>AndroidApp</code> are folded into Bitwarden login URIs where
					they can drive autofill. Free-text fields like <code>API Url</code>
					stay as custom fields so API endpoints do not accidentally become
					login matches.
				</p>
				<p>
					Plain URLs use your Bitwarden account default. KeePassXC-style quoted
					URLs become exact matches, and wildcards become starts-with or regex
					matches. If too many subdomains surface together, use the URI
					collision report to inspect the problem before changing match
					behavior.
				</p>
			</section>

			<section id="after">
				<p class="eyebrow">after migration</p>
				<h2>Only strip kp2bw stamps when you are truly done</h2>
				<p>
					<code>kp2bw --strip-ids</code> removes <code>KP2BW_ID</code> and
					<code>KP2BW_SYNC</code> from migrated items. That is final adoption:
					Bitwarden becomes the source of truth and future KeePass reruns become
					unreliable because kp2bw can no longer match by KeePass UUID.
				</p>
				<p class="warning">
					This is irreversible. Do not run it while you still expect to rerun a
					KeePass migration.
				</p>
			</section>

			<section id="credentials">
				<p class="eyebrow">credentials</p>
				<h2>Use a .env file for passwords</h2>
				<p>
					The command can prompt for passwords. For repeated runs, put secrets
					in <code>.env</code> instead of in command arguments.
				</p>
				<pre><code>KP2BW_KEEPASS_PASSWORD=&lt;keepass password&gt;
KP2BW_BITWARDEN_PASSWORD=&lt;bitwarden password&gt;</code></pre>
				<p>
					kp2bw loads <code>.env</code> automatically. Real environment
					variables still win when both are set.
				</p>
			</section>
		</div>
	</div>
</main>

<style>
	.docs-page {
		min-height: 100vh;
		padding: 28px;
		font-family:
			"Aptos Mono",
			"Cascadia Mono",
			"SFMono-Regular",
			Consolas,
			"Liberation Mono",
			monospace;
	}

	.docs-hero,
	.docs-layout {
		max-width: 1120px;
		margin: 0 auto;
	}

	.docs-hero {
		display: grid;
		gap: 10px;
		border-bottom: 1px solid #30372f;
		padding-bottom: 18px;
	}

	a {
		width: fit-content;
		color: #8ed9aa;
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
		color: #9c9587;
		font-size: 0.74rem;
		text-transform: uppercase;
	}

	h1,
	h2,
	h3,
	p {
		letter-spacing: 0;
	}

	h1 {
		max-width: 12ch;
		margin: 0;
		font-family: Georgia, "Times New Roman", serif;
		font-size: clamp(2.4rem, 5vw, 4.5rem);
		line-height: 1;
	}

	.docs-hero span {
		max-width: 74ch;
		color: #bcb5a5;
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
		border: 1px solid #30372f;
		background: #171a16;
		padding: 14px;
	}

	.content {
		display: grid;
		gap: 18px;
	}

	section {
		min-width: 0;
		border: 1px solid #30372f;
		background: #171a16;
		padding: 20px;
	}

	section > h2 {
		margin: 5px 0 10px;
		font-size: 1.25rem;
		line-height: 1.35;
	}

	p,
	li {
		max-width: 78ch;
		color: #d6ceb9;
		line-height: 1.62;
	}

	code {
		color: #d8f3df;
		font: inherit;
	}

	pre {
		overflow: auto;
		border: 1px solid #31513f;
		background: #0f1812;
		padding: 14px;
		color: #d8f3df;
		white-space: pre;
	}

	.fact-grid {
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 10px;
		margin-top: 14px;
	}

	.fact-grid article {
		min-width: 0;
		border: 1px solid #2b302a;
		padding: 14px;
	}

	.fact-grid p {
		margin-bottom: 0;
	}

	.mapping-grid {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		margin: 16px 0;
		border-top: 1px solid #30372f;
		border-left: 1px solid #30372f;
	}

	.mapping-grid > div {
		min-width: 0;
		border-right: 1px solid #30372f;
		border-bottom: 1px solid #30372f;
		padding: 10px;
	}

	.mapping-head {
		color: #9c9587;
		font-size: 0.74rem;
		text-transform: uppercase;
	}

	.mapping-grid span {
		display: none;
	}

	.warning {
		border: 1px solid #7a5a40;
		background: #201a13;
		padding: 12px;
		color: #f0c08a;
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
			border-top: 1px solid #30372f;
		}

		.mapping-grid span {
			display: inline;
			color: #9c9587;
			font-size: 0.68rem;
			text-transform: uppercase;
		}
	}
</style>
