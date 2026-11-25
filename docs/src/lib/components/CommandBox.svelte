<script lang="ts">
	import { resolve } from '$app/paths';
	import { onDestroy } from 'svelte';

	let { command, previewCommand, envFile, inputError }: {
		command: string;
		previewCommand: string;
		envFile: string;
		inputError?: string;
	} = $props();

	let copied = $state<string | null>(null);
	let copyFailed = $state(false);
	let resetTimer: ReturnType<typeof setTimeout> | undefined;

	async function copy(label: string, text: string): Promise<void> {
		copyFailed = false;
		copied = null;
		clearTimeout(resetTimer);
		try {
			await navigator.clipboard.writeText(text);
		} catch {
			copyFailed = true;
			return;
		}
		copied = label;
		resetTimer = setTimeout(() => {
			copied = null;
		}, 1200);
	}

	onDestroy(() => {
		if (resetTimer !== undefined) clearTimeout(resetTimer);
	});
</script>

{#snippet codeBlock(label: string, text: string)}
	<div class="block">
		<div class="block-head">
			<h3>{label}</h3>
			<button
				type="button"
				aria-label={`Copy ${label}`}
				onclick={() => copy(label, text)}
			>
				{copied === label ? 'Copied' : 'Copy'}
			</button>
		</div>
		<pre><code>{text}</code></pre>
	</div>
{/snippet}

<section class="command">
	<h2>Commands for Bash or Zsh</h2>
	{#if inputError}
		<p>{inputError}</p>
	{:else}
		<p>
			Start with the <a href={resolve('/docs#preview')}>read-only preview</a>.
			Migration writes to Bitwarden. Options omitted from either command can
			come from your environment or <code>.env</code>.
		</p>
		<div class="blocks">
			{@render codeBlock('Preview locally', previewCommand)}
			{@render codeBlock('Run migration', command)}
		</div>
	{/if}
	<details>
		<summary>Optional password configuration</summary>
		<p>
			kp2bw prompts for passwords by default. To use a local <code>.env</code>
			file, replace these placeholders.
		</p>
		{@render codeBlock('.env', envFile)}
	</details>
	<span class:sr-only={!copyFailed} role="status">
		{
			copyFailed
			? 'Clipboard unavailable. Select the text to copy it.'
			: copied
			? `${copied} copied to clipboard`
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
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 10px;
	}

	p {
		margin: 0 0 8px;
		color: var(--text-dim);
	}

	a {
		color: var(--accent);
	}

	details {
		margin-top: 12px;
	}

	summary {
		margin-bottom: 8px;
		cursor: pointer;
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
