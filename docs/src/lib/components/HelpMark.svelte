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
		border: 1px solid #667267;
		background: transparent;
		color: #d9ded2;
		font: inherit;
		font-size: 0.78rem;
		line-height: 1;
		cursor: help;
	}

	.help:hover,
	.help:focus-visible {
		border-color: #8ecf9f;
		color: #8ecf9f;
		outline: none;
	}

	.popover {
		position: absolute;
		z-index: 5;
		top: calc(100% + 7px);
		right: 0;
		display: none;
		width: min(250px, 78vw);
		border: 1px solid #4b594d;
		background: #111411;
		padding: 10px;
		color: #f0ecdc;
		font-size: 0.78rem;
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
		color: #8ecf9f;
		text-decoration: none;
	}

	a:hover,
	a:focus-visible {
		text-decoration: underline;
		outline: none;
	}
</style>
