<script lang="ts">
	let { command, envFile, copied, onCopy }: {
		command: string;
		envFile: string;
		copied: boolean;
		onCopy: () => void;
	} = $props();
</script>

<section class="command">
	<div class="head">
		<h2>Command</h2>
		<button type="button" onclick={onCopy}>{copied ? 'Copied' : 'Copy'}</button>
		<span class="sr-only" aria-live="polite" aria-atomic="true">
			{copied ? 'Command copied to clipboard' : ''}
		</span>
	</div>
	<div class="blocks">
		<div>
			<h3>.env</h3>
			<pre><code>{envFile}</code></pre>
		</div>
		<div>
			<h3>Run</h3>
			<pre><code>{command}</code></pre>
		</div>
	</div>
</section>

<style>
	.command {
		grid-column: 1 / -1;
		border: 1px solid #2f372f;
		background: #151914;
		padding: 14px;
	}

	.head {
		display: flex;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 10px;
	}

	h2,
	h3 {
		margin: 0;
		color: #aab0a3;
		font-size: 0.72rem;
		letter-spacing: 0;
		text-transform: uppercase;
	}

	button {
		min-height: 34px;
		border: 1px solid #3b4239;
		background: #1f241e;
		color: #f0ecdc;
		padding: 0 12px;
		font: inherit;
		cursor: pointer;
	}

	button:hover {
		border-color: #8ecf9f;
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

	.blocks {
		display: grid;
		grid-template-columns: minmax(220px, 0.7fr) minmax(260px, 1.3fr);
		gap: 10px;
	}

	pre {
		overflow: auto;
		margin: 6px 0 0;
		border: 1px solid #31513f;
		background: #0f1812;
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
