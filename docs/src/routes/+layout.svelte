<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head><link rel="icon" href={favicon}></svelte:head>
{@render children()}

<footer>
	<nav aria-label="Project links">
		<a href="https://github.com/kjanat/kp2bw" target="_blank" rel="noreferrer">
			GitHub
		</a>
		<a href="https://pypi.org/project/kp2bw/" target="_blank" rel="noreferrer">
			PyPI
		</a>
	</nav>
	<span>kp2bw — KeePass → Bitwarden migration</span>
</footer>

<style>
	:global(:root) {
		color-scheme: dark;

		/* Surfaces — three steps only: page, raised panel, inset field/code. */
		--bg: #111411;
		--panel: #181c16;
		--field: #10130f;
		--code-bg: #0f1812;

		/* Text — a real ladder; --muted is lifted to clear WCAG AA on panels. */
		--text: #f0ecdc;
		--text-dim: #cdcabb;
		--text-muted: #b0b5a4;

		/* Edges — two tiers, not eight. Hairline inside, stronger on raised. */
		--edge: #333b31;
		--edge-strong: #4a544757;
		--code-edge: #31513f;

		/* Accent + focus. */
		--accent: #8ecf9f;
		--accent-deep: #112016;
		--focus: #9ff0ba;

		/* Icon colors. */
		--icon-folder: #d2b56f;
		--icon-folder-bg: #211d12;
		--icon-collection: var(--accent);
		--icon-collection-bg: #101d16;
		--icon-recycle: #d48670;
		--icon-recycle-bg: #251713;

		/* Type scale — body speaks, labels whisper (not everything tiny). */
		--fs-label: 0.72rem;
		--fs-small: 0.8rem;
		--fs-body: 0.9rem;

		/* Spacing rhythm + one radius. */
		--sp-1: 4px;
		--sp-2: 8px;
		--sp-3: 12px;
		--sp-4: 18px;
		--sp-5: 28px;
		--radius: 4px;

		--mono:
			"Aptos Mono",
			"Cascadia Mono",
			"SFMono-Regular",
			Consolas,
			"Liberation Mono",
			monospace;

		background: var(--bg);
	}

	:global(html) {
		min-width: 320px;
		min-height: 100%;
	}

	:global(body) {
		margin: 0;
		background: var(--bg);
		color: var(--text);
		font-family: var(--mono);
		font-size: var(--fs-body);
		line-height: 1.5;
	}

	:global(*) {
		box-sizing: border-box;
	}

	/* One focus treatment for the whole app — replaces the scattered, and in
	   places removed, outlines. Keyboard users always get a visible ring. */
	:global(:focus-visible) {
		outline: 2px solid var(--focus);
		outline-offset: 1px;
	}

	footer {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: var(--sp-2) var(--sp-4);
		max-width: 1320px;
		margin: var(--sp-5) auto 0;
		border-top: 1px solid var(--edge);
		padding: var(--sp-4) var(--sp-5) var(--sp-5);
		color: var(--text-muted);
		font-size: var(--fs-label);
	}

	footer nav {
		display: flex;
		gap: var(--sp-4);
	}

	footer a {
		color: var(--accent);
		text-decoration: none;
	}

	footer a:hover {
		text-decoration: underline;
	}
</style>
