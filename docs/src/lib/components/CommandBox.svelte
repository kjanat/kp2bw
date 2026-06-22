<script lang="ts">
	import { onDestroy } from 'svelte';

	let { command, envFile }: { command: string; envFile: string } = $props();

	// Which box was last copied, so each Copy button flips to "Copied" on its own.
	let copied = $state<'env' | 'run' | null>(null);
	let resetTimer: ReturnType<typeof setTimeout> | undefined;

	async function copy(which: 'env' | 'run', text: string): Promise<void> {
		try {
			await navigator.clipboard.writeText(text);
		} catch {
			return;
		}
		copied = which;
		if (resetTimer !== undefined) clearTimeout(resetTimer);
		resetTimer = setTimeout(() => {
			copied = null;
		}, 1200);
	}

	onDestroy(() => {
		if (resetTimer !== undefined) clearTimeout(resetTimer);
	});
</script>

<section class="command">
	<h2>Command</h2>
	<div class="blocks">
		<div class="block">
			<div class="block-head">
				<h3>.env</h3>
				<button type="button" onclick={() => copy('env', envFile)}>
					{copied === 'env' ? 'Copied' : 'Copy'}
				</button>
			</div>
			<pre><code>{envFile}</code></pre>
		</div>
		<div class="block">
			<div class="block-head">
				<h3>Run</h3>
				<button type="button" onclick={() => copy('run', command)}>
					{copied === 'run' ? 'Copied' : 'Copy'}
				</button>
			</div>
			<pre><code>{command}</code></pre>
		</div>
	</div>
	<span class="sr-only" aria-live="polite" aria-atomic="true">
		{
			copied === 'env'
			? '.env copied to clipboard'
			: copied === 'run'
			? 'Command copied to clipboard'
			: ''
		}
	</span>
</section>

<style>
	.command {
		grid-column: 1 / -1;
		border: 1px solid var(--edge);
		background: var(--panel);
		padding: 14px;
	}

	h2 {
		margin: 0 0 10px;
		color: var(--text-muted);
		font-size: var(--fs-label);
		letter-spacing: 0;
		text-transform: uppercase;
	}

	h3 {
		margin: 0;
		color: var(--text-muted);
		font-size: var(--fs-label);
		letter-spacing: 0;
		text-transform: uppercase;
	}

	.blocks {
		display: grid;
		grid-template-columns: minmax(220px, 0.7fr) minmax(260px, 1.3fr);
		gap: 10px;
	}

	.block-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		min-height: 28px;
	}

	button {
		min-height: 28px;
		border: 1px solid var(--edge-strong);
		background: #1f241e;
		color: var(--text);
		padding: 0 12px;
		font: inherit;
		font-size: var(--fs-small);
		cursor: pointer;
	}

	button:hover {
		border-color: var(--accent);
	}

	.sr-only {
		position: absolute;
		overflow: hidden;
		width: 1px;
		height: 1px;
		margin: -1px;
		border: 0;
		padding: 0;
		white-space: nowrap;
		clip-path: inset(50%);
	}

	pre {
		overflow: auto;
		margin: 6px 0 0;
		border: 1px solid var(--code-edge);
		background: var(--code-bg);
		padding: 10px;
		color: #d8f3df;
		white-space: pre;
	}

	code {
		font: inherit;
	}

	@media (max-width: 820px) {
		.blocks {
			grid-template-columns: 1fr;
		}
	}
</style>
