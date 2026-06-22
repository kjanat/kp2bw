<script lang="ts">
	import { resolve } from '$app/paths';

	type DocsHref = '/docs' | `/docs#${string}`;

	let { text, href = '/docs' }: { text: string; href?: DocsHref } = $props();
</script>

<span class="wrap">
	<button class="help" type="button" aria-label={text}>?</button>
	<span class="popover" role="tooltip">
		{text}
		<a href={resolve(href)}>continue reading</a>
	</span>
</span>

<style>
	.wrap {
		position: relative;
		display: inline-grid;
	}

	.help {
		display: inline-grid;
		place-items: center;
		width: 1.25rem;
		height: 1.25rem;
		border: 1px solid var(--edge-strong);
		background: transparent;
		color: var(--text-dim);
		font: inherit;
		font-size: var(--fs-small);
		line-height: 1;
		cursor: help;
	}

	.help:hover,
	.help:focus-visible {
		border-color: var(--accent);
		color: var(--accent);
	}

	.popover {
		position: absolute;
		z-index: 5;
		top: calc(100% + 7px);
		right: 0;
		display: none;
		width: min(250px, 78vw);
		border: 1px solid var(--edge-strong);
		background: var(--bg);
		padding: 10px;
		color: var(--text);
		font-size: var(--fs-small);
		line-height: 1.4;
		text-transform: none;
		box-shadow: 0 10px 24px rgba(0, 0, 0, 0.35);
	}

	.wrap:hover .popover,
	.wrap:focus-within .popover {
		display: grid;
		gap: 8px;
	}

	a {
		width: fit-content;
		color: var(--accent);
		text-decoration: none;
	}

	a:hover,
	a:focus-visible {
		text-decoration: underline;
	}
</style>
