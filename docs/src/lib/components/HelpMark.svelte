<script lang="ts">
	import { resolve } from '$app/paths';

	type DocsHref = 'docs' | `docs#${string}`;

	let { text, href = 'docs' }: { text: string; href?: DocsHref } = $props();
</script>

<span class="wrap">
	<a class="help" href={resolve(href)} aria-label={text}>?</a>
	<span class="popover" aria-hidden="true">{text}</span>
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
		text-decoration: none;
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
		pointer-events: none;
	}

	.wrap:hover .popover,
	.wrap:focus-within .popover {
		display: block;
	}
</style>
