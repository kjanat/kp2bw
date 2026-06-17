<script lang="ts">
	import { availableTags, selectedTags } from '$lib/planner';
	import type { Mapping, PlannerState, RerunMode } from '$lib/planner';
	import HelpMark from './HelpMark.svelte';

	type Choice<T extends string> = {
		value: T;
		label: string;
		help: string;
		href: `/docs#${string}`;
	};

	let { state }: { state: PlannerState } = $props();

	const orgMappings: Choice<Mapping>[] = [
		{
			value: 'org-nested',
			label: 'Org collections: full paths',
			help:
				'KeePass group Work/Servers becomes organization collection Work/Servers.',
			href: '/docs#full-path-collections',
		},
		{
			value: 'org-top',
			label: 'Org collections: top folder only',
			help:
				'KeePass Work/Servers and Work/Engineering both land in collection Work.',
			href: '/docs#top-folder-collections',
		},
		{
			value: 'org-fixed',
			label: 'One existing collection',
			help:
				'Every item lands in the collection ID below. KeePass groups are not recreated.',
			href: '/docs#single-collection',
		},
		{
			value: 'org-flat',
			label: 'Flat organization import',
			help: 'No generated collections and no personal folders.',
			href: '/docs#flat-org',
		},
	];

	const personalMappings: Choice<Mapping>[] = [
		{
			value: 'personal-folders',
			label: 'Personal folders',
			help: 'KeePass groups become personal Bitwarden folders.',
			href: '/docs#personal-folders',
		},
		{
			value: 'personal-flat',
			label: 'Flat personal import',
			help: 'No Bitwarden folders. Items stay at the personal vault root.',
			href: '/docs#flat-personal',
		},
	];

	const reruns: Choice<RerunMode>[] = [
		{
			value: 'keepass-wins',
			label: 'KeePass is still my main vault',
			help:
				'Use KeePass as the source of truth and push it over Bitwarden edits.',
			href: '/docs#force-update',
		},
		{
			value: 'safe',
			label: 'Mostly Bitwarden, sync forgotten KeePass edits',
			help:
				'Update migrated items when Bitwarden has not been edited since the last kp2bw run.',
			href: '/docs#safe-rerun',
		},
		{
			value: 'no-update',
			label: 'Testing migrations; keep the existing Vaultwarden DB',
			help:
				'Create missing items only and leave existing migrated Bitwarden items untouched.',
			href: '/docs#no-update',
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
				checked={state.destination === 'org'}
				onchange={() => setDestination('org')}
			>
			Organization
		</label>
		<label>
			<input
				type="radio"
				name="destination"
				checked={state.destination === 'personal'}
				onchange={() => setDestination('personal')}
			>
			Personal
		</label>
	</fieldset>

	{#if state.destination === 'org'}
		<label class="field">
			<span>Org ID <HelpMark
					text="Bitwarden organization ID passed to kp2bw."
					href="/docs#organization-id"
				/></span>
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
				<HelpMark text={mapping.help} href={mapping.href} />
			</div>
		{/each}
	</fieldset>

	{#if state.mapping === 'org-fixed'}
		<label class="field">
			<span>Collection ID <HelpMark
					text="Existing collection all imported items should land in."
					href="/docs#collection-id"
				/></span>
			<input bind:value={state.collectionId} spellcheck="false">
		</label>
	{/if}

	<div class="fields">
		<label class="field file-field">
			<span>KeePass file <HelpMark
					text="Path to the KeePass database."
					href="/docs#keepass-file"
				/></span>
			<input bind:value={state.keepassFile} spellcheck="false">
		</label>
		<label class="field file-field">
			<span>Key file <HelpMark
					text="Optional KeePass key file."
					href="/docs#key-file"
				/></span>
			<input bind:value={state.keyFile} spellcheck="false">
		</label>
		<label class="field tag-field">
			<span>Tags <HelpMark
					text="Comma-separated KeePass tags to import. Empty imports all tags."
					href="/docs#tag-filter"
				/></span>
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
		<legend>
			Filters <HelpMark
				text="Controls which KeePass entries are omitted."
				href="/docs#filters"
			/>
		</legend>
		<div class="choice">
			<label>
				<input type="checkbox" bind:checked={state.skipExpired}>
				Skip expired
			</label>
			<HelpMark
				text="Expired entries are imported by default. This omits them."
				href="/docs#skip-expired"
			/>
		</div>
		<div class="choice">
			<label>
				<input type="checkbox" bind:checked={state.includeRecycleBin}>
				Include Recycle Bin
			</label>
			<HelpMark
				text="Recycle Bin entries are excluded by default."
				href="/docs#recycle-bin"
			/>
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
				<HelpMark text={rerun.help} href={rerun.href} />
			</div>
		{/each}
	</fieldset>
</section>

<style>
	.options {
		min-width: 0;
		border: 1px solid #2f372f;
		background: #151914;
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
		color: #aab0a3;
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
		border: 1px solid #2d342d;
		padding: 8px;
		color: #f0ecdc;
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
		accent-color: #8ecf9f;
	}

	input:not([type="radio"]):not([type="checkbox"]) {
		width: 100%;
		min-height: 34px;
		border: 1px solid #303a31;
		background: #10130f;
		color: #f0ecdc;
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
		border: 1px solid #303a31;
		background: #10130f;
		color: #c7c9bd;
		padding: 0 8px;
		font: inherit;
		font-size: 0.78rem;
		cursor: pointer;
	}

	.tag-chips button:hover,
	.tag-chips button:focus-visible,
	.tag-chips button.active {
		border-color: #8ecf9f;
		color: #f0ecdc;
		outline: none;
	}

	.tag-chips button.active {
		background: #112016;
	}
</style>
