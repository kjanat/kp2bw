<script lang="ts">
	import type { PreviewNode } from '$lib/planner';
	import { SvelteSet } from 'svelte/reactivity';

	type Tree = {
		title: string;
		nodes: PreviewNode[];
	};

	let { keepass, bitwarden }: { keepass: Tree; bitwarden: Tree } = $props();

	let collapsed = new SvelteSet<string>();

	function toggleNode(nodeId: string): void {
		if (collapsed.has(nodeId)) {
			collapsed.delete(nodeId);
		} else {
			collapsed.add(nodeId);
		}
	}

	function actionLabel(action: PreviewNode['action']): string {
		if (action === undefined) return '';
		if (action === 'create') return 'create';
		if (action === 'update') return 'sync to BW';
		if (action === 'protected') return 'protect BW';
		if (action === 'overwrite') return 'KP wins';
		if (action === 'left-alone') return 'leave';
		if (action === 'unchanged') return 'same';
		if (action === 'skip') return 'skip';
		const exhaustive: never = action;
		return exhaustive;
	}

	function deltaLabel(delta: PreviewNode['delta']): string {
		if (delta === undefined || delta === 'unchanged') return '';
		if (delta === 'new-in-keepass') return 'new in KP';
		if (delta === 'keepass-changed') return 'KP changed';
		if (delta === 'bitwarden-changed') return 'BW changed';
		if (delta === 'both-changed') return 'both changed';
		const exhaustive: never = delta;
		return exhaustive;
	}

	function showDelta(node: PreviewNode): boolean {
		return Boolean(node.delta && node.delta !== 'unchanged');
	}
</script>

{#snippet branch(nodes: PreviewNode[], prefix = '')}
	<ul>
		{#each nodes as node, i (`${prefix}/${i}`)}
			{@const nodeId = `${prefix}/${i}`}
			{@const canCollapse = node.children.length > 0}
			{@const isCollapsed = collapsed.has(nodeId)}
			<li>
				<div
					class="node"
					class:root={node.kind === 'root'}
					class:folder={node.kind === 'folder'}
					class:collection={node.kind === 'collection'}
					class:recycle={node.kind === 'recycle'}
					class:item={node.kind === 'item'}
					class:empty={node.kind === 'empty'}
					class:skipped={node.action === 'skip' || node.muted}
					class:conflicted={node.action === 'protected' || node.action === 'overwrite'}
				>
					{#if canCollapse}
						<button
							class="twist"
							type="button"
							aria-label={`${isCollapsed ? 'Expand' : 'Collapse'} ${node.name}`}
							aria-expanded={!isCollapsed}
							onclick={() => toggleNode(nodeId)}
						>
							{isCollapsed ? '›' : '⌄'}
						</button>
					{:else}
						<span class="twist" aria-hidden="true"></span>
					{/if}
					<span class="icon" data-kind={node.kind}></span>
					<span class="name">{node.name}</span>
					{#if node.count !== undefined && node.kind !== 'item'}
						<span class="count">{node.count}</span>
					{:else if node.kind === 'item' && (node.action || showDelta(node))}
						<span class="badges">
							{#if showDelta(node)}
								<span class="delta" data-delta={node.delta}>
									{deltaLabel(node.delta)}
								</span>
							{/if}
							{#if node.action}
								<span class="action" data-action={node.action}>
									{actionLabel(node.action)}
								</span>
							{/if}
						</span>
					{/if}
				</div>
				{#if canCollapse && !isCollapsed}
					{@render branch(node.children, nodeId)}
				{/if}
			</li>
		{/each}
	</ul>
{/snippet}

<section class="preview" aria-label="Migration tree preview">
	<div class="panel">
		<div class="head">
			<h2>{keepass.title}</h2>
		</div>
		<div class="tree">
			{@render branch(keepass.nodes, 'keepass')}
		</div>
	</div>
	<div class="panel">
		<div class="head">
			<h2>{bitwarden.title}</h2>
		</div>
		<div class="tree">
			{@render branch(bitwarden.nodes, 'bitwarden')}
		</div>
	</div>
</section>

<style>
	.preview {
		grid-column: span 2;
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 12px;
		min-width: 0;
	}

	.panel {
		min-width: 0;
		border: 1px solid #2f372f;
		background: #151914;
		padding: 12px;
	}

	.head {
		border-bottom: 1px solid #30372f;
		padding-bottom: 8px;
	}

	h2,
	span {
		margin: 0;
		color: #aab0a3;
		font-size: 0.72rem;
		letter-spacing: 0;
		text-transform: uppercase;
	}

	.tree {
		overflow: auto;
		padding-top: 8px;
	}

	ul {
		display: grid;
		gap: 2px;
		margin: 0;
		padding: 0;
		list-style: none;
	}

	li li {
		margin-left: 15px;
		border-left: 1px solid #30372f;
		padding-left: 10px;
	}

	.node {
		display: grid;
		grid-template-columns: 14px 16px minmax(0, 1fr) auto;
		align-items: center;
		gap: 6px;
		min-width: 0;
		min-height: 28px;
		border-radius: 3px;
		padding: 2px 4px;
		transition:
			background-color 180ms ease,
			color 180ms ease,
			opacity 220ms ease,
			filter 220ms ease;
	}

	.node:hover {
		background: #1d241d;
	}

	.root {
		color: #f0ecdc;
		font-weight: 700;
	}

	.folder {
		color: #d2b56f;
	}

	.collection {
		color: #85d7ad;
	}

	.recycle {
		color: #d48670;
	}

	.item {
		color: #d4d0c3;
	}

	.skipped {
		opacity: 0.46;
		filter: grayscale(1);
	}

	.conflicted {
		background: #241916;
	}

	.empty {
		color: #7e897d;
		font-style: italic;
	}

	.twist {
		display: grid;
		place-items: center;
		width: 14px;
		height: 22px;
		border: 0;
		background: transparent;
		color: #8ecf9f;
		padding: 0;
		font: inherit;
		font-size: 0.85rem;
		line-height: 1;
		cursor: pointer;
	}

	span.twist {
		cursor: default;
	}

	button.twist:hover,
	button.twist:focus-visible {
		color: #f0ecdc;
		outline: 1px solid #8ecf9f;
		outline-offset: 1px;
	}

	.icon {
		position: relative;
		width: 14px;
		height: 12px;
		border: 1px solid #95a195;
	}

	.icon::before {
		position: absolute;
		content: "";
	}

	.icon::after {
		position: absolute;
		content: "";
	}

	.icon[data-kind="root"],
	.icon[data-kind="bucket"] {
		border-color: #8ecf9f;
	}

	.icon[data-kind="folder"] {
		border-color: #d2b56f;
		background: #211d12;
	}

	.icon[data-kind="folder"]::before {
		top: -4px;
		left: 1px;
		width: 7px;
		height: 4px;
		border: 1px solid #d2b56f;
		border-bottom: 0;
		background: #151914;
	}

	.icon[data-kind="collection"] {
		width: 14px;
		height: 14px;
		border-color: #8ecf9f;
		background: #101d16;
	}

	.icon[data-kind="collection"]::before {
		inset: 3px;
		border: 1px solid #8ecf9f;
	}

	.icon[data-kind="collection"]::after {
		top: 5px;
		left: -4px;
		width: 2px;
		height: 2px;
		background: #8ecf9f;
		box-shadow: 16px 0 0 #8ecf9f, 8px -6px 0 #8ecf9f, 8px 6px 0 #8ecf9f;
	}

	.icon[data-kind="recycle"] {
		border-color: #d48670;
		border-radius: 0 0 4px 4px;
		background: #251713;
	}

	.icon[data-kind="recycle"]::before {
		top: -4px;
		left: -2px;
		width: 16px;
		height: 2px;
		border: 1px solid #d48670;
		background: #151914;
	}

	.icon[data-kind="recycle"]::after {
		top: 3px;
		left: 3px;
		width: 1px;
		height: 6px;
		background: #d48670;
		box-shadow: 4px 0 0 #d48670;
	}

	.icon[data-kind="item"] {
		width: 10px;
		height: 13px;
		border-color: #868c83;
	}

	.icon[data-kind="item"]::before {
		top: 2px;
		left: 2px;
		width: 4px;
		height: 1px;
		background: #868c83;
		box-shadow: 0 3px 0 #868c83, 0 6px 0 #868c83;
	}

	.icon[data-kind="empty"] {
		border-color: #5c655b;
		border-style: dashed;
		opacity: 0.75;
	}

	.icon[data-kind="empty"]::before {
		top: 5px;
		left: 3px;
		width: 6px;
		height: 1px;
		background: #7e897d;
	}

	.name {
		overflow-wrap: anywhere;
		color: inherit;
		text-transform: none;
	}

	.count {
		border: 1px solid #30372f;
		padding: 1px 6px;
		color: #8ecf9f;
		font-size: 0.68rem;
	}

	.badges {
		display: flex;
		flex-wrap: wrap;
		justify-content: end;
		gap: 4px;
	}

	.action,
	.delta {
		border: 1px solid #30372f;
		padding: 1px 6px;
		color: #c7c9bd;
		font-size: 0.64rem;
		line-height: 1.25;
		text-transform: uppercase;
		white-space: nowrap;
		transition:
			border-color 180ms ease,
			background-color 180ms ease,
			color 180ms ease;
	}

	.delta[data-delta="new-in-keepass"] {
		border-color: #8ecf9f;
		color: #9ff0ba;
	}

	.delta[data-delta="keepass-changed"] {
		border-color: #d2b56f;
		color: #e3c77d;
	}

	.delta[data-delta="bitwarden-changed"] {
		border-color: #7da2d8;
		color: #9dbdec;
	}

	.delta[data-delta="both-changed"] {
		border-color: #d48670;
		color: #f0a58d;
	}

	.action[data-action="create"] {
		border-color: #8ecf9f;
		background: #112016;
		color: #9ff0ba;
	}

	.action[data-action="update"] {
		border-color: #d2b56f;
		background: #211d12;
		color: #e3c77d;
	}

	.action[data-action="protected"] {
		border-color: #7da2d8;
		background: #111a25;
		color: #9dbdec;
	}

	.action[data-action="overwrite"] {
		border-color: #d48670;
		background: #271711;
		color: #f0a58d;
	}

	.action[data-action="left-alone"],
	.action[data-action="skip"] {
		border-color: #5c655b;
		color: #9ba397;
	}

	@media (max-width: 820px) {
		.preview {
			grid-column: auto;
			grid-template-columns: 1fr;
		}
	}
</style>
