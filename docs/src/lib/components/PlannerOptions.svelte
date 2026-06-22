<script lang="ts">
	import { availableTags, selectedTags } from '$lib/planner';
	import type { Mapping, PlannerState, RerunMode } from '$lib/planner';
	import HelpMark from './HelpMark.svelte';

	type Choice<T extends string> = {
		value: T;
		label: string;
	};

	let { state }: { state: PlannerState } = $props();

	// Labels are self-describing; the per-option rationale lives in the docs
	// page, reached via the section-level help marks (Tree mapping / Running
	// again), so the controls stay compact instead of a wall of ? buttons.
	const orgMappings: Choice<Mapping>[] = [
		{ value: 'org-nested', label: 'Org collections: full paths' },
		{ value: 'org-top', label: 'Org collections: top folder only' },
		{ value: 'org-fixed', label: 'One existing collection' },
		{ value: 'org-flat', label: 'Flat organization import' },
	];

	const personalMappings: Choice<Mapping>[] = [
		{ value: 'personal-folders', label: 'Personal folders' },
		{ value: 'personal-flat', label: 'Flat personal import' },
	];

	const reruns: Choice<RerunMode>[] = [
		{ value: 'keepass-wins', label: 'KeePass is still my main vault' },
		{ value: 'safe', label: 'Mostly Bitwarden, sync forgotten KeePass edits' },
		{
			value: 'no-update',
			label: 'Testing migrations; keep the existing Vaultwarden DB',
		},
	];

	let mappings = $derived(
		state.destination === 'org' ? orgMappings : personalMappings,
	);
	const tagChoices = availableTags();
	let activeTags = $derived(selectedTags(state.tagInput));

	function setDestination(destination: PlannerState['destination']): void {
		state.destination = destination;
		state.mapping = destination === 'org' ? 'org-nested' : 'personal-folders';
	}

	function toggleTag(tag: string): void {
		const current = selectedTags(state.tagInput);
		if (current.includes(tag)) {
			state.tagInput = current.filter((entry) => entry !== tag).join(', ');
		} else {
			state.tagInput = [...current, tag].join(', ');
		}
	}
</script>

<section class="options">
	<!--
		Target-independent options first. Toggling Target adds/removes Org ID,
		swaps the mapping list (4 org vs 2 personal) and the folders opt-in, so
		keeping it below means a toggle only reflows the bottom of the panel
		instead of shoving every field down.
	-->
	<div class="fields">
		<label class="field file-field">
			<span>KeePass file</span>
			<input bind:value={state.keepassFile} spellcheck="false">
		</label>
		<label class="field file-field">
			<span>Key file</span>
			<input bind:value={state.keyFile} spellcheck="false">
		</label>
		<label class="field tag-field">
			<span>Tags</span>
			<input bind:value={state.tagInput} spellcheck="false">
		</label>
		<div
			class="tag-chips"
			aria-label="Available tags in the mock KeePass vault"
		>
			{#each tagChoices as tag (tag)}
				<button
					type="button"
					class:active={activeTags.includes(tag)}
					aria-pressed={activeTags.includes(tag)}
					onclick={() => toggleTag(tag)}
				>
					{tag}
				</button>
			{/each}
		</div>
	</div>

	<fieldset class="filters">
		<legend>Filters</legend>
		<div class="choice">
			<label>
				<input type="checkbox" bind:checked={state.includeExpired}>
				Expired
			</label>
		</div>
		<div class="choice">
			<label>
				<input type="checkbox" bind:checked={state.includeRecycleBin}>
				Recycle bin
			</label>
		</div>
	</fieldset>

	<fieldset>
		<legend>
			Running again <HelpMark
				text="Pick the situation you are in when this command hits an existing Bitwarden vault."
				href="/docs#reruns"
			/>
		</legend>
		{#each reruns as rerun (rerun.value)}
			<div class="choice">
				<label>
					<input
						type="radio"
						name="rerun"
						value={rerun.value}
						bind:group={state.rerunMode}
					>
					{rerun.label}
				</label>
			</div>
		{/each}
	</fieldset>

	<fieldset class="target">
		<legend>
			Target <HelpMark
				text="Choose whether items land in an organization or your personal vault."
				href="/docs#target-vault"
			/>
		</legend>
		<label>
			<input
				type="radio"
				name="destination"
				checked={state.destination === 'personal'}
				onchange={() => setDestination('personal')}
			>
			Personal
		</label>
		<label>
			<input
				type="radio"
				name="destination"
				checked={state.destination === 'org'}
				onchange={() => setDestination('org')}
			>
			Organization
		</label>
	</fieldset>

	{#if state.destination === 'org'}
		<label class="field">
			<span>Org ID</span>
			<input bind:value={state.organizationId} spellcheck="false">
		</label>
	{/if}

	<fieldset>
		<legend>
			Tree mapping <HelpMark
				text="Controls how KeePass groups become Bitwarden placement."
				href="/docs#mapping"
			/>
		</legend>
		{#each mappings as mapping (mapping.value)}
			<div class="choice">
				<label>
					<input
						type="radio"
						name="mapping"
						value={mapping.value}
						bind:group={state.mapping}
					>
					{mapping.label}
				</label>
			</div>
		{/each}
	</fieldset>

	{#if state.destination === 'org'}
		<div class="choice">
			<label>
				<input type="checkbox" bind:checked={state.orgFolders}>
				Also create personal folders
			</label>
			<HelpMark
				text="Org imports skip personal folders by default. Tick this to also build the KeePass folder tree in your personal vault (kp2bw --folder)."
				href="/docs#personal-folders-under-org"
			/>
		</div>
	{/if}

	{#if state.mapping === 'org-fixed'}
		<label class="field">
			<span>Collection ID</span>
			<input bind:value={state.collectionId} spellcheck="false">
		</label>
	{/if}
</section>

<style>
	.options {
		min-width: 0;
		border: 1px solid var(--edge);
		background: var(--panel);
		padding: 14px;
	}

	fieldset,
	.fields {
		display: grid;
		gap: 8px;
		margin: 0 0 14px;
		border: 0;
		padding: 0;
	}

	.target {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	.target legend,
	.filters legend {
		grid-column: 1 / -1;
	}

	.fields,
	.filters {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}

	legend,
	.field > span {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-bottom: 6px;
		color: var(--text-muted);
		font-size: 0.72rem;
		text-transform: uppercase;
	}

	fieldset > label:not(.field),
	.choice {
		display: flex;
		align-items: center;
		gap: 8px;
		justify-content: space-between;
		min-width: 0;
		border: 1px solid var(--edge);
		padding: 8px;
		color: var(--text);
	}

	.target > label {
		min-height: 34px;
		padding: 6px 8px;
	}

	.filters .choice {
		min-height: 34px;
		padding: 6px 8px;
	}

	.choice label {
		display: flex;
		align-items: center;
		gap: 8px;
		min-width: 0;
	}

	input[type="radio"],
	input[type="checkbox"] {
		accent-color: var(--accent);
	}

	input:not([type="radio"]):not([type="checkbox"]) {
		width: 100%;
		min-height: 34px;
		border: 1px solid var(--edge);
		background: var(--field);
		color: var(--text);
		padding: 0 8px;
	}

	.tag-field,
	.tag-chips {
		grid-column: 1 / -1;
	}

	.tag-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		margin-top: -4px;
	}

	.tag-chips button {
		min-height: 26px;
		border: 1px solid var(--edge);
		background: var(--field);
		color: var(--text-dim);
		padding: 0 8px;
		font: inherit;
		font-size: var(--fs-small);
		cursor: pointer;
	}

	/* Focus is intentionally NOT merged with :hover/.active here: a keyboard
	   user needs the global :focus-visible ring to tell focus from selected. */
	.tag-chips button:hover,
	.tag-chips button.active {
		border-color: var(--accent);
		color: var(--text);
	}

	.tag-chips button.active {
		background: var(--accent-deep);
	}
</style>
