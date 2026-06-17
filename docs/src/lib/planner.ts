import previewFixtureData from './preview-fixture.json';

export type Destination = 'org' | 'personal';
export type Mapping =
	| 'org-nested'
	| 'org-top'
	| 'org-fixed'
	| 'org-flat'
	| 'personal-folders'
	| 'personal-flat';
export type RerunMode = 'safe' | 'no-update' | 'keepass-wins';
export type ItemDelta =
	| 'new-in-keepass'
	| 'unchanged'
	| 'keepass-changed'
	| 'bitwarden-changed'
	| 'both-changed';
export type PreviewAction =
	| 'create'
	| 'update'
	| 'protected'
	| 'overwrite'
	| 'left-alone'
	| 'unchanged'
	| 'skip';
export type ExclusionReason = 'tag-filter' | 'expired' | 'recycle-bin';

export type KeePassEntry = {
	id: string;
	name: string;
	group: string | null;
	tags: string[];
	keepassRevision: string;
	expired?: boolean;
	recycle?: boolean;
	attachments?: number;
	passkey?: boolean;
};

export type BitwardenItem = {
	id: string;
	kp2bwId: string;
	name: string;
	group: string | null;
	syncedKeePassRevision: string;
	syncedBitwardenRevision: string;
	currentBitwardenRevision: string;
	recycle?: boolean;
	attachments?: number;
	passkey?: boolean;
	type?: 'login' | 'note' | 'card' | 'identity';
};

export type PlannerState = {
	destination: Destination;
	mapping: Mapping;
	keepassFile: string;
	keyFile: string;
	organizationId: string;
	collectionId: string;
	tagInput: string;
	skipExpired: boolean;
	includeRecycleBin: boolean;
	rerunMode: RerunMode;
};

export type PreviewFixture = {
	name: string;
	keepass: KeePassEntry[];
	bitwarden: BitwardenItem[];
};

export type PreviewNode = {
	name: string;
	kind: 'root' | 'folder' | 'collection' | 'recycle' | 'bucket' | 'item' | 'empty';
	count?: number;
	delta?: ItemDelta;
	action?: PreviewAction;
	muted?: boolean;
	children: PreviewNode[];
};

export type PlannedItem = {
	source: KeePassEntry;
	existing?: BitwardenItem;
	included: boolean;
	exclusionReason?: ExclusionReason;
	delta: ItemDelta;
	action: PreviewAction;
	sourcePath: string;
	targetPath: string;
};

export type MigrationPreview = {
	items: KeePassEntry[];
	plan: PlannedItem[];
	keepass: PreviewNode[];
	bitwarden: PreviewNode[];
	stats: ReturnType<typeof statsForState>;
};

export const previewFixture: PreviewFixture = previewFixtureData;
export const samples = previewFixture.keepass;
export const sampleOrganizationId = '00000000-0000-0000-0000-000000000000';
export const sampleCollectionId = '11111111-1111-1111-1111-111111111111';

export const defaultPlannerState: PlannerState = {
	destination: 'org',
	mapping: 'org-nested',
	keepassFile: 'vault.kdbx',
	keyFile: '',
	organizationId: sampleOrganizationId,
	collectionId: sampleCollectionId,
	tagInput: '',
	skipExpired: false,
	includeRecycleBin: false,
	rerunMode: 'safe',
};

export function selectedTags(tagInput: string): string[] {
	return tagInput.split(',').map((tag) => tag.trim()).filter(Boolean);
}

export function availableTags(items = samples): string[] {
	return [...new Set(items.flatMap((item) => item.tags))].sort((a, b) => a.localeCompare(b));
}

export function filteredItems(state: PlannerState, items = samples): KeePassEntry[] {
	return items.filter((item) => itemIncluded(state, item));
}

export function itemIncluded(state: PlannerState, item: KeePassEntry): boolean {
	return exclusionReasonForItem(state, item) === undefined;
}

export function exclusionReasonForItem(
	state: PlannerState,
	item: KeePassEntry,
): ExclusionReason | undefined {
	const tags = selectedTags(state.tagInput);
	if (!state.includeRecycleBin && item.recycle) return 'recycle-bin';
	if (state.skipExpired && item.expired) return 'expired';
	if (tags.length > 0 && !tags.some((tag) => item.tags.includes(tag))) {
		return 'tag-filter';
	}
	return undefined;
}

export function deltaForItem(
	item: KeePassEntry,
	existing = existingForEntry(item),
): ItemDelta {
	if (!existing) return 'new-in-keepass';
	const keepassChanged = item.keepassRevision !== existing.syncedKeePassRevision;
	const bitwardenChanged = existing.currentBitwardenRevision !== existing.syncedBitwardenRevision;
	if (keepassChanged && bitwardenChanged) return 'both-changed';
	if (keepassChanged) return 'keepass-changed';
	if (bitwardenChanged) return 'bitwarden-changed';
	return 'unchanged';
}

export function actionForState(state: PlannerState, item: KeePassEntry): PreviewAction {
	const existing = existingForEntry(item);
	const included = itemIncluded(state, item);
	return reconcileExisting(state, item, existing, included);
}

export function buildMigrationPlan(
	state: PlannerState,
	fixture = previewFixture,
): PlannedItem[] {
	const existingByKpId = new Map(fixture.bitwarden.map((item) => [item.kp2bwId, item]));
	return fixture.keepass.map((source) => {
		const existing = existingByKpId.get(source.id);
		const exclusionReason = exclusionReasonForItem(state, source);
		const included = exclusionReason === undefined;
		const delta = deltaForItem(source, existing);
		const action = reconcileExisting(state, source, existing, included);
		return {
			source,
			existing,
			included,
			exclusionReason,
			delta,
			action,
			sourcePath: source.group ?? 'Vault root',
			targetPath: targetPathForPlan(source, existing, action),
		};
	});
}

export function previewForState(
	state: PlannerState,
	fixture = previewFixture,
): MigrationPreview {
	const plan = buildMigrationPlan(state, fixture);
	const items = plan.filter((item) => item.included).map((item) => item.source);
	return {
		items,
		plan,
		keepass: sourceTree(state, fixture),
		bitwarden: bitwardenTree(state, fixture),
		stats: statsForState(state, items),
	};
}

export function sourceTree(
	state = defaultPlannerState,
	fixture = previewFixture,
): PreviewNode[] {
	const plan = buildMigrationPlan(state, fixture);
	return [
		{
			name: fixture.name,
			kind: 'root',
			count: fixture.keepass.length,
			children: treeWithItems(
				plan,
				(item) => item.sourcePath,
				'folder',
				(item) => ({
					delta: item.delta,
				}),
				() => true,
			),
		},
	];
}

export function bitwardenTree(
	state: PlannerState,
	fixtureOrItems: PreviewFixture | KeePassEntry[] = previewFixture,
): PreviewNode[] {
	const fixture = Array.isArray(fixtureOrItems)
		? { ...previewFixture, keepass: fixtureOrItems }
		: fixtureOrItems;
	const plan = buildMigrationPlan(state, fixture);
	const importableCount = plan.filter((item) => item.included).length;

	if (state.destination === 'personal') {
		return [
			{
				name: 'My vault',
				kind: 'root',
				count: importableCount,
				children: state.mapping === 'personal-folders'
					? [
						{
							name: 'Folders',
							kind: 'bucket',
							count: importableCount,
							children: treeWithItems(
								plan,
								(item) => item.targetPath,
								'folder',
								targetLeafState,
							),
						},
					]
					: [flatBucket('No folder', plan)],
			},
			{
				name: 'Organization vault',
				kind: 'root',
				count: 0,
				children: [emptyNode('No organization changes')],
			},
		];
	}

	const collectionChildren = (() => {
		if (state.mapping === 'org-nested') {
			return treeWithItems(
				plan,
				(item) => item.targetPath,
				'collection',
				targetLeafState,
			);
		}
		if (state.mapping === 'org-top') {
			return treeWithItems(
				plan,
				(item) => firstSegment(item.targetPath),
				'collection',
				targetLeafState,
			);
		}
		if (state.mapping === 'org-fixed') {
			return treeWithItems(
				plan,
				() => state.collectionId || sampleCollectionId,
				'collection',
				targetLeafState,
			);
		}
		return [flatBucket('No collection', plan)];
	})();

	return [
		{
			name: 'My vault',
			kind: 'root',
			count: 0,
			children: [emptyNode('No personal folders created')],
		},
		{
			name: 'Organization vault',
			kind: 'root',
			count: importableCount,
			children: state.mapping === 'org-flat'
				? collectionChildren
				: [
					{
						name: 'Collections',
						kind: 'bucket',
						count: importableCount,
						children: collectionChildren,
					},
				],
		},
	];
}

export function commandForState(state: PlannerState): string {
	const args = ['kp2bw'];

	if (state.destination === 'org') {
		args.push('-o', quoteArg(state.organizationId || sampleOrganizationId));
		if (state.mapping === 'org-nested') args.push('-c', 'nested');
		if (state.mapping === 'org-top') args.push('-c', 'auto');
		if (state.mapping === 'org-fixed') {
			args.push('-c', quoteArg(state.collectionId || sampleCollectionId));
		}
		args.push('--no-folder');
	}

	if (state.destination === 'personal' && state.mapping === 'personal-flat') {
		args.push('--no-folder');
	}

	if (state.keyFile.trim()) args.push('-K', quoteArg(state.keyFile.trim()));
	const tags = selectedTags(state.tagInput);
	if (tags.length > 0) args.push('-t', ...tags.map(quoteArg));
	if (state.skipExpired) args.push('--skip-expired');
	if (state.includeRecycleBin) args.push('--include-recycle-bin');
	if (state.rerunMode === 'no-update') args.push('--no-update');
	if (state.rerunMode === 'keepass-wins') args.push('--force-update');

	args.push(quoteArg(state.keepassFile || 'passwords.kdbx'));
	return args.join(' ');
}

export function envFileForState(): string {
	return [
		'KP2BW_KEEPASS_PASSWORD=<keepass password>',
		'KP2BW_BITWARDEN_PASSWORD=<bitwarden password>',
	].join('\n');
}

export function statsForState(state: PlannerState, items = filteredItems(state)) {
	return {
		items: items.length,
		attachments: items.reduce((total, item) => total + (item.attachments ?? 0), 0),
		passkeys: items.filter((item) => item.passkey).length,
	};
}

export function placementLabel(state: PlannerState): string {
	if (state.mapping === 'org-nested') return 'KeePass paths -> org collections';
	if (state.mapping === 'org-top') return 'Top folders -> org collections';
	if (state.mapping === 'org-fixed') return 'Everything -> one collection';
	if (state.mapping === 'org-flat') return 'Flat organization import';
	if (state.mapping === 'personal-flat') return 'Flat personal import';
	return 'KeePass paths -> personal folders';
}

function reconcileExisting(
	state: PlannerState,
	source: KeePassEntry,
	existing: BitwardenItem | undefined,
	included: boolean,
): PreviewAction {
	if (!included) return 'skip';
	if (!existing) return 'create';
	if (existing.type && existing.type !== 'login') return 'left-alone';
	if (state.rerunMode === 'no-update') return 'left-alone';

	const delta = deltaForItem(source, existing);
	if (delta === 'unchanged') return 'unchanged';
	if (state.rerunMode === 'keepass-wins') {
		return delta === 'keepass-changed' ? 'update' : 'overwrite';
	}
	if (delta === 'keepass-changed') return 'update';
	return 'protected';
}

function targetPathForPlan(
	source: KeePassEntry,
	existing: BitwardenItem | undefined,
	action: PreviewAction,
): string {
	if (
		existing
		&& (
			action === 'protected' || action === 'left-alone' || action === 'unchanged'
			|| action === 'skip'
		)
	) {
		return existing.group ?? source.group ?? 'Unfiled';
	}
	return source.group ?? 'Unfiled';
}

function existingForEntry(
	entry: KeePassEntry,
	fixture = previewFixture,
): BitwardenItem | undefined {
	return fixture.bitwarden.find((item) => item.kp2bwId === entry.id);
}

function targetLeafState(item: PlannedItem): Pick<PreviewNode, 'delta' | 'action' | 'muted'> {
	return {
		delta: item.delta,
		action: item.action,
		muted: item.action === 'skip',
	};
}

function treeWithItems<T>(
	items: T[],
	getPath: (item: T) => string,
	branchKind: PreviewNode['kind'],
	getLeafState: (item: T) => Pick<PreviewNode, 'delta' | 'action' | 'muted'>,
	countLeaf: (leaf: Pick<PreviewNode, 'delta' | 'action' | 'muted'>) => boolean = (
		leaf,
	) => leaf.action !== 'skip' && !leaf.muted,
): PreviewNode[] {
	const root: PreviewNode[] = [];
	for (const item of items) {
		const leafState = getLeafState(item);
		let level = root;
		for (const part of getPath(item).split('/').filter(Boolean)) {
			let node = level.find((entry) => entry.name === part);
			if (!node) {
				node = {
					name: part,
					kind: branchKindForPart(part, branchKind),
					count: 0,
					children: [],
				};
				level.push(node);
			}
			if (countLeaf(leafState)) {
				node.count = (node.count ?? 0) + 1;
			}
			level = node.children;
		}
		level.push({
			name: itemName(item),
			kind: 'item',
			...leafState,
			children: [],
		});
	}
	return sortTree(root);
}

function flatBucket(name: string, plan: PlannedItem[]): PreviewNode {
	return {
		name,
		kind: 'bucket',
		count: plan.filter((item) => item.included).length,
		children: sortTree(
			plan.map((item) => ({
				name: item.source.name,
				kind: 'item' as const,
				...targetLeafState(item),
				children: [],
			})),
		),
	};
}

function emptyNode(name: string): PreviewNode {
	return {
		name,
		kind: 'empty',
		children: [],
	};
}

function sortTree(nodes: PreviewNode[]): PreviewNode[] {
	return nodes
		.sort((a, b) => {
			if (a.kind === 'recycle' && b.kind !== 'recycle') return 1;
			if (a.kind !== 'recycle' && b.kind === 'recycle') return -1;
			if (a.kind === 'item' && b.kind !== 'item') return 1;
			if (a.kind !== 'item' && b.kind === 'item') return -1;
			return a.name.localeCompare(b.name);
		})
		.map((node) => ({ ...node, children: sortTree(node.children) }));
}

function itemName(item: unknown): string {
	if (isPlannedItem(item)) return item.source.name;
	return String(item);
}

function isPlannedItem(item: unknown): item is PlannedItem {
	return Boolean(item && typeof item === 'object' && 'source' in item);
}

function firstSegment(path: string | null): string {
	return path?.split('/').filter(Boolean)[0] ?? 'Unfiled';
}

function branchKindForPart(
	part: string,
	branchKind: PreviewNode['kind'],
): PreviewNode['kind'] {
	return part === 'Recycle Bin' ? 'recycle' : branchKind;
}

function quoteArg(value: string): string {
	if (/^[A-Za-z0-9_./:=@+-]+$/.test(value)) return value;
	return '"' + value.replaceAll('"', '\\"') + '"';
}
