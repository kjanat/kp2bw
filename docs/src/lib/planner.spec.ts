import { describe, expect, it } from 'vitest';
import {
	availableTags,
	bitwardenTree,
	buildMigrationPlan,
	commandForState,
	defaultPlannerState,
	deltaForItem,
	envFileForState,
	filteredItems,
	previewFixture,
	previewForState,
	sampleOrganizationId,
	sourceTree,
} from './planner';
import type { PreviewNode } from './planner';

describe('planner', () => {
	it('defaults to nested organization collections without personal folders', () => {
		expect(defaultPlannerState).toMatchObject({
			destination: 'org',
			mapping: 'org-nested',
			keepassFile: 'vault.kdbx',
			organizationId: sampleOrganizationId,
		});
		expect(bitwardenTree(defaultPlannerState).map((node) => node.name)).toEqual([
			'My vault',
			'Organization vault',
		]);
		expect(bitwardenTree(defaultPlannerState)[0]).toMatchObject({
			name: 'My vault',
			count: 0,
			children: [expect.objectContaining({ name: 'No personal folders created' })],
		});
		expect(bitwardenTree(defaultPlannerState)[1]).toMatchObject({
			name: 'Organization vault',
			children: [
				{
					name: 'Collections',
					children: expect.arrayContaining([
						expect.objectContaining({ name: 'Work', kind: 'collection' }),
					]),
				},
			],
		});
	});

	it('builds an organization command from state values', () => {
		const state = {
			...defaultPlannerState,
			organizationId: '22222222-2222-2222-2222-222222222222',
			keepassFile: 'source vault.kdbx',
		};

		expect(commandForState(state)).toBe(
			'kp2bw -o 22222222-2222-2222-2222-222222222222 -c nested --no-folder "source vault.kdbx"',
		);
	});

	it('maps top-level organization collections', () => {
		const state = {
			...defaultPlannerState,
			mapping: 'org-top' as const,
			keepassFile: 'source.kdbx',
		};

		expect(commandForState(state)).toBe(
			`kp2bw -o ${sampleOrganizationId} -c auto --no-folder source.kdbx`,
		);
		const collections = bitwardenTree(state)[1]?.children[0]?.children;
		expect(collections?.find((node) => node.name === 'Work')?.count).toBe(4);
	});

	it('shows both Bitwarden scopes for personal imports too', () => {
		const state = {
			...defaultPlannerState,
			destination: 'personal' as const,
			mapping: 'personal-folders' as const,
		};

		expect(bitwardenTree(state).map((node) => node.name)).toEqual([
			'My vault',
			'Organization vault',
		]);
		expect(bitwardenTree(state)[0]?.children[0]).toMatchObject({
			name: 'Folders',
			children: expect.arrayContaining([
				expect.objectContaining({ name: 'Work', kind: 'folder' }),
			]),
		});
		expect(bitwardenTree(state)[1]).toMatchObject({
			name: 'Organization vault',
			count: 0,
			children: [expect.objectContaining({ name: 'No organization changes' })],
		});
	});

	it('builds both trees from the same preview fixture', () => {
		const preview = previewForState(defaultPlannerState);

		expect(preview.items).toEqual(filteredItems(defaultPlannerState, previewFixture.keepass));
		expect(preview.keepass[0]?.count).toBe(previewFixture.keepass.length);
		expect(preview.bitwarden.map((node) => node.name)).toEqual([
			'My vault',
			'Organization vault',
		]);
	});

	it('discovers tag choices from the source fixture', () => {
		expect(availableTags()).toEqual(['admin', 'dev', 'finance', 'hr', 'legacy', 'ops']);
	});

	it('derives item state from KeePass and Bitwarden revisions', () => {
		const byName = new Map(previewFixture.keepass.map((item) => [item.name, item]));

		// Fixture state must come from side-specific inventories, not precomputed sync labels.
		expect(previewFixture.keepass.some((item) => 'bitwarden' in item || 'sync' in item)).toBe(false);
		expect(deltaForItem(byName.get('Root Admin')!)).toBe('new-in-keepass');
		expect(deltaForItem(byName.get('Stripe')!)).toBe('unchanged');
		expect(deltaForItem(byName.get('Payroll')!)).toBe('keepass-changed');
		expect(deltaForItem(byName.get('Production SSH')!)).toBe('bitwarden-changed');
		expect(deltaForItem(byName.get('GitHub')!)).toBe('both-changed');
	});

	it('keeps skipped entries visible and marks them skipped in Bitwarden', () => {
		const preview = previewForState({
			...defaultPlannerState,
			skipExpired: true,
		});

		expect(treeNames(preview.keepass)).toContain('Archive Box');
		expect(treeNames(preview.bitwarden)).toContain('Archive Box');
		expect(findTreeNode(preview.keepass, 'Archive Box')?.action).toBeUndefined();
		expect(findTreeNode(preview.keepass, 'Archive Box')?.muted).toBeUndefined();
		expect(findTreeNode(preview.bitwarden, 'Archive Box')?.action).toBe('skip');
		expect(preview.stats.items).toBe(filteredItems({ ...defaultPlannerState, skipExpired: true }).length);
	});

	it('keeps Recycle Bin visible in KeePass while excluding it from Bitwarden by default', () => {
		const preview = previewForState(defaultPlannerState);
		const withRecycleBin = previewForState({
			...defaultPlannerState,
			includeRecycleBin: true,
		});

		expect(treeNames(preview.keepass)).toContain('Recycle Bin');
		expect(treeNames(preview.keepass)).toContain('Old SaaS');
		expect(treeNames(preview.bitwarden)).toContain('Old SaaS');
		expect(lastNode(preview.keepass[0]?.children)).toMatchObject({
			name: 'Recycle Bin',
			kind: 'recycle',
		});
		expect(lastNode(preview.bitwarden[1]?.children[0]?.children)).toMatchObject({
			name: 'Recycle Bin',
			kind: 'recycle',
		});
		expect(findTreeNode(preview.bitwarden, 'Old SaaS')?.action).toBe('skip');
		expect(treeNames(withRecycleBin.bitwarden)).toContain('Old SaaS');
		expect(findTreeNode(withRecycleBin.bitwarden, 'Old SaaS')?.action).toBe('create');
		expect(findTreeNode(withRecycleBin.keepass, 'Old SaaS')?.action).toBeUndefined();
		expect(findTreeNode(withRecycleBin.bitwarden, 'Retired Jira')?.action).toBe('update');
		expect(findTreeNode(preview.bitwarden, 'Deprecated VPN')?.action).toBe('protected');
		expect(treeNames(findTreeNode(preview.bitwarden, 'Recycle Bin')?.children ?? []))
			.toContain('Deprecated VPN');
	});

	it('plans rerun protection and selected resolutions like the converter', () => {
		const safe = previewForState(defaultPlannerState);
		const keepassWins = previewForState({
			...defaultPlannerState,
			rerunMode: 'keepass-wins',
		});
		const noUpdate = previewForState({
			...defaultPlannerState,
			rerunMode: 'no-update',
		});

		expect(findTreeNode(safe.bitwarden, 'GitHub')?.action).toBe('protected');
		expect(findTreeNode(safe.bitwarden, 'Production SSH')?.action).toBe('protected');
		expect(findTreeNode(keepassWins.bitwarden, 'GitHub')?.action).toBe('overwrite');
		expect(findTreeNode(noUpdate.bitwarden, 'GitHub')?.action).toBe('left-alone');
	});

	it('keeps target actions out of the KeePass source tree', () => {
		const preview = previewForState({
			...defaultPlannerState,
			includeRecycleBin: true,
		});

		expect(findTreeNode(preview.keepass, 'Old SaaS')?.action).toBeUndefined();
		expect(findTreeNode(preview.keepass, 'Retired Jira')?.action).toBeUndefined();
		const oldSaasPlan = buildMigrationPlan(defaultPlannerState).find((item) => item.source.name === 'Old SaaS');

		expect(oldSaasPlan).toMatchObject({
			action: 'skip',
			exclusionReason: 'recycle-bin',
		});
	});

	it('filters imports and keeps the KeePass source tree unchanged', () => {
		const state = {
			...defaultPlannerState,
			tagInput: 'finance',
			skipExpired: true,
		};

		expect(filteredItems(state).map((item) => item.name)).toEqual(['Stripe', 'Payroll']);
		expect(sourceTree()[0]?.children.map((node) => node.name)).toContain('Recycle Bin');
		expect(commandForState(state)).toContain('-t finance --skip-expired');
	});

	it('uses a .env block for credentials', () => {
		expect(envFileForState()).toBe(
			'KP2BW_KEEPASS_PASSWORD=<keepass password>\nKP2BW_BITWARDEN_PASSWORD=<bitwarden password>',
		);
	});
});

function treeNames(nodes: PreviewNode[]): string[] {
	return nodes.flatMap((node) => [node.name, ...treeNames(node.children)]);
}

function findTreeNode(nodes: PreviewNode[], name: string): PreviewNode | undefined {
	for (const node of nodes) {
		if (node.name === name) return node;
		const child = findTreeNode(node.children, name);
		if (child) return child;
	}
	return undefined;
}

function lastNode(nodes: PreviewNode[] | undefined): PreviewNode | undefined {
	return nodes?.[nodes.length - 1];
}
