<script lang="ts">
	import { resolve } from '$app/paths';
	import CommandBox from '$lib/components/CommandBox.svelte';
	import PathTable from '$lib/components/PathTable.svelte';
	import PlannerOptions from '$lib/components/PlannerOptions.svelte';
	import TreeLegend from '$lib/components/TreeLegend.svelte';
	import {
		commandDisplayForState,
		defaultPlannerState,
		envFileForState,
		PLANNER_STORAGE_KEY,
		previewFixture,
		previewForState,
		sanitizePlannerState,
		statsForState,
	} from '$lib/planner';
	import type { PlannerState } from '$lib/planner';
	import { onMount } from 'svelte';

	let planner: PlannerState = $state({ ...defaultPlannerState });

	// Persist selections so a refresh keeps them. Load on mount (client only, so
	// SSR still renders defaults and hydration matches); the guard stops the save
	// effect from clobbering stored state with defaults before that load runs.
	let hydrated = false;

	onMount(() => {
		try {
			const stored = localStorage.getItem(PLANNER_STORAGE_KEY);
			if (stored) {
				Object.assign(planner, sanitizePlannerState(JSON.parse(stored)));
			}
		} catch {
			// corrupt JSON or storage unavailable — keep the defaults
		}
		hydrated = true;
	});

	$effect(() => {
		const snapshot = JSON.stringify(planner);
		if (!hydrated) return;
		try {
			localStorage.setItem(PLANNER_STORAGE_KEY, snapshot);
		} catch {
			// storage full or disabled — selections just won't persist
		}
	});

	let preview = $derived(previewForState(planner));
	let command = $derived(commandDisplayForState(planner));
	let envFile = $derived(envFileForState());
	let stats = $derived(preview.stats);
	// KeePass-side totals (the whole source vault, pre-filter) so the Bitwarden
	// result count has something to be measured against.
	let sourceStats = $derived(statsForState(planner, previewFixture.keepass));

	// Selections persist, so give people a way back to a clean slate. Mutating in
	// place keeps the deep-reactive references the child controls bind to; the
	// save effect then writes the defaults back to storage.
	function resetPlanner(): void {
		Object.assign(planner, { ...defaultPlannerState });
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
		<div class="header-actions">
			<button type="button" class="reset" onclick={resetPlanner}>Reset</button>
			<a href={resolve('/docs')}>details</a>
		</div>
	</header>

	<div class="summary">
		<span class="tally">
			<span class="tally-label">KeePass</span>
			{sourceStats.items} items · {sourceStats.attachments} attachments · {
				sourceStats.passkeys
			} passkey{sourceStats.passkeys === 1 ? '' : 's'}
		</span>
		<TreeLegend />
		<span class="tally tally-right">
			<span class="tally-label">Bitwarden</span>
			{stats.items} items · {stats.attachments} attachments · {stats.passkeys}
			passkey{stats.passkeys === 1 ? '' : 's'}
		</span>
	</div>

	<div class="grid">
		<PathTable
			keepass={{ title: 'Tree in KeePass', nodes: preview.keepass }}
			bitwarden={{ title: 'Tree in Bitwarden', nodes: preview.bitwarden }}
		/>
		<PlannerOptions state={planner} />

		<CommandBox {command} {envFile} />
	</div>
</main>

<style>
	main {
		padding: 22px;
	}

	header {
		display: flex;
		align-items: end;
		justify-content: space-between;
		gap: 18px;
		max-width: 1320px;
		margin: 0 auto 12px;
		border-bottom: 1px solid var(--edge);
		padding-bottom: 12px;
	}

	p {
		margin: 0 0 4px;
		color: var(--text-muted);
		font-size: var(--fs-label);
		text-transform: uppercase;
	}

	h1 {
		margin: 0;
		font-family: var(--mono);
		font-size: clamp(2.4rem, 4vw, 4rem);
		font-weight: 700;
		letter-spacing: -0.02em;
		line-height: 1;
	}

	/* The route to the docs — was bare green text lost in the tree noise.
	   Now a bordered pill with a clear hover fill so it reads as a control. */
	header a {
		flex: none;
		align-self: center;
		border: 1px solid var(--accent);
		border-radius: var(--radius);
		padding: 7px 14px;
		color: var(--accent);
		text-decoration: none;
		white-space: nowrap;
	}

	header a::after {
		content: " \2192";
	}

	header a:hover,
	header a:focus-visible {
		background: var(--accent);
		color: var(--bg);
	}

	.header-actions {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	/* Secondary to the accent "details" pill — a quiet ghost button. */
	.reset {
		border: 1px solid var(--edge-strong);
		border-radius: var(--radius);
		background: transparent;
		color: var(--text-muted);
		padding: 7px 14px;
		font: inherit;
		cursor: pointer;
	}

	.reset:hover {
		border-color: var(--accent);
		color: var(--text);
	}

	.summary {
		display: grid;
		grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
		align-items: center;
		gap: 10px;
		max-width: 1320px;
		margin: 0 auto 12px;
		color: var(--text-dim);
	}

	.tally-label {
		margin-right: 6px;
		color: var(--text-muted);
		font-size: var(--fs-label);
		text-transform: uppercase;
	}

	.tally-right {
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

		.tally-right {
			text-align: left;
		}

		.grid {
			grid-template-columns: 1fr;
		}
	}
</style>
