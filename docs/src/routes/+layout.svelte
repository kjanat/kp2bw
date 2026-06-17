<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head><link rel="icon" href={favicon}></svelte:head>
{@render children()}

<style>
	:global(:root) {
		color-scheme: dark;
		background: #111411;
	}

	:global(html) {
		min-width: 320px;
		min-height: 100%;
	}

	:global(body) {
		margin: 0;
		background: #111411;
		color: #f0ecdc;
		font-family:
			"Aptos Mono",
			"Cascadia Mono",
			"SFMono-Regular",
			Consolas,
			"Liberation Mono",
			monospace;
	}

	:global(*) {
		box-sizing: border-box;
	}
</style>
