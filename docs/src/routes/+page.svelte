<script lang="ts">
	import { resolve } from '$app/paths';
	import CommandBox from '$lib/components/CommandBox.svelte';
	import PathTable from '$lib/components/PathTable.svelte';
	import PlannerOptions from '$lib/components/PlannerOptions.svelte';
	import TreeLegend from '$lib/components/TreeLegend.svelte';
	import {
		commandForState,
		defaultPlannerState,
		envFileForState,
		placementLabel,
		previewForState,
	} from '$lib/planner';
	import type { PlannerState } from '$lib/planner';
	import { onDestroy } from 'svelte';

	let planner: PlannerState = $state({ ...defaultPlannerState });
	let copied = $state(false);
	let copyResetTimer: ReturnType<typeof setTimeout> | undefined = $state();

	let preview = $derived(previewForState(planner));
	let command = $derived(commandForState(planner));
	let envFile = $derived(envFileForState());
	let stats = $derived(preview.stats);
	let title = $derived(placementLabel(planner));
	let copyText = $derived(`# .env\n${envFile}\n\n${command}`);

	onDestroy(() => {
		if (copyResetTimer !== undefined) clearTimeout(copyResetTimer);
	});

	async function copyCommand(): Promise<void> {
		try {
			await navigator.clipboard.writeText(copyText);
		} catch {
			copied = false;
			return;
		}

		copied = true;
		if (copyResetTimer !== undefined) clearTimeout(copyResetTimer);
		copyResetTimer = setTimeout(() => {
			copied = false;
			copyResetTimer = undefined;
		}, 1200);
	}
</script>

<svelte:head>
	<title>kp2bw migration planner</title>
	<meta
		name="description"
		content="Plan a KeePass to Bitwarden migration and preview how the tree maps into Bitwarden."
	>
</svelte:head>

<main>
	<header>
		<div>
			<p>migration planner</p>
			<h1>kp2bw</h1>
		</div>
		<a href={resolve('/docs')}>details</a>
	</header>

	<div class="summary">
		<strong>{title}</strong>
		<TreeLegend />
		<span>{stats.items} items · {stats.attachments} attachments · {
				stats.passkeys
			} passkey{stats.passkeys === 1 ? '' : 's'}</span>
	</div>

	<div class="grid">
		<PathTable
			keepass={{ title: 'Tree in KeePass', nodes: preview.keepass }}
			bitwarden={{ title: 'Tree in Bitwarden', nodes: preview.bitwarden }}
		/>
		<PlannerOptions state={planner} />

		<CommandBox {command} {envFile} {copied} onCopy={copyCommand} />
	</div>
</main>

<style>
	main {
		min-height: 100vh;
		padding: 22px;
	}

	header {
		display: flex;
		align-items: end;
		justify-content: space-between;
		gap: 18px;
		max-width: 1320px;
		margin: 0 auto 12px;
		border-bottom: 1px solid #30372f;
		padding-bottom: 12px;
	}

	p {
		margin: 0 0 4px;
		color: #aab0a3;
		font-size: 0.72rem;
		text-transform: uppercase;
	}

	h1 {
		margin: 0;
		font-family: Georgia, "Times New Roman", serif;
		font-size: clamp(2.4rem, 4vw, 4rem);
		letter-spacing: 0;
		line-height: 1;
	}

	a {
		color: #8ecf9f;
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}

	.summary {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
		align-items: center;
		gap: 10px;
		max-width: 1320px;
		margin: 0 auto 12px;
		color: #c7c9bd;
	}

	.summary strong {
		color: #f0ecdc;
	}

	.summary > span:last-child {
		text-align: right;
	}

	.grid {
		display: grid;
		grid-template-columns:
			minmax(260px, 1fr) minmax(260px, 1fr) minmax(320px, 0.9fr);
		gap: 12px;
		max-width: 1320px;
		margin: 0 auto;
	}

	@media (max-width: 980px) {
		main {
			padding: 14px;
		}

		header {
			align-items: start;
		}

		.summary {
			grid-template-columns: 1fr;
		}

		.summary > span:last-child {
			text-align: left;
		}

		.grid {
			grid-template-columns: 1fr;
		}
	}
</style>
