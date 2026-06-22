import { describe, expect, it } from 'vitest';
import {
	availableTags,
	bitwardenTree,
	buildMigrationPlan,
	commandDisplayForState,
	commandForState,
	defaultPlannerState,
	deltaForItem,
	envFileForState,
	filteredItems,
	previewFixture,
	previewForState,
	sampleOrganizationId,
	sanitizePlannerState,
	sourceTree,
} from './planner';
import type { PreviewNode } from './planner';

// The default is now a personal import (mirrors `kp2bw vault.kdbx` with no -o);
// org-specific behaviour is exercised from this explicit baseline.
const orgState = {
	...defaultPlannerState,
	destination: 'org' as const,
	mapping: 'org-nested' as const,
};

describe('planner', () => {
	it('defaults to a personal-vault import with folders', () => {
		expect(defaultPlannerState).toMatchObject({
			destination: 'personal',
			mapping: 'personal-folders',
			keepassFile: 'vault.kdbx',
		});
		const [myVault, orgVault] = bitwardenTree(defaultPlannerState);
		expect(myVault).toMatchObject({ name: 'My vault' });
		expect(myVault?.children[0]).toMatchObject({ name: 'Folders' });
		expect(orgVault).toMatchObject({
			name: 'Organization vault',
			count: 0,
			children: [expect.objectContaining({ name: 'No organization changes' })],
		});
	});

	it('builds nested organization collections without personal folders', () => {
		expect(bitwardenTree(orgState).map((node) => node.name)).toEqual([
			'My vault',
			'Organization vault',
		]);
		expect(bitwardenTree(orgState)[0]).toMatchObject({
			name: 'My vault',
			count: 0,
			children: [expect.objectContaining({ name: 'No personal folders created' })],
		});
		expect(bitwardenTree(orgState)[1]).toMatchObject({
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
			...orgState,
			organizationId: '22222222-2222-2222-2222-222222222222',
			keepassFile: 'source vault.kdbx',
		};

		expect(commandForState(state)).toBe(
			'kp2bw -o 22222222-2222-2222-2222-222222222222 -c nested "source vault.kdbx"',
		);
	});

	it('escapes backslashes before quotes in command arguments', () => {
		expect(
			commandForState({
				...defaultPlannerState,
				keepassFile: String.raw`C:\Vaults\test\".kdbx`,
			}),
		).toBe(String.raw`kp2bw "C:\\Vaults\\test\\\".kdbx"`);
	});

	it('maps top-level organization collections', () => {
		const state = {
			...orgState,
			mapping: 'org-top' as const,
			keepassFile: 'source.kdbx',
		};

		expect(commandForState(state)).toBe(
			`kp2bw -o ${sampleOrganizationId} -c auto source.kdbx`,
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
			includeExpired: false,
		});

		expect(treeNames(preview.keepass)).toContain('Archive Box');
		expect(treeNames(preview.bitwarden)).toContain('Archive Box');
		expect(findTreeNode(preview.keepass, 'Archive Box')?.action).toBeUndefined();
		expect(findTreeNode(preview.keepass, 'Archive Box')?.muted).toBeUndefined();
		expect(findTreeNode(preview.bitwarden, 'Archive Box')?.action).toBe('skip');
		expect(preview.stats.items).toBe(filteredItems({ ...defaultPlannerState, includeExpired: false }).length);
	});

	it('keeps Recycle Bin visible in KeePass while excluding it from Bitwarden by default', () => {
		const preview = previewForState(orgState);
		const withRecycleBin = previewForState({
			...orgState,
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
			includeExpired: false,
		};

		expect(filteredItems(state).map((item) => item.name)).toEqual(['Stripe', 'Payroll']);
		expect(sourceTree()[0]?.children.map((node) => node.name)).toContain('Recycle Bin');
		expect(commandForState(state)).toContain('-t finance --skip-expired');
	});

	it('adds --folder and a personal folder tree when org folders are enabled', () => {
		const state = { ...orgState, orgFolders: true };

		expect(commandForState(state)).toContain('-c nested --folder');

		const [myVault, orgVault] = bitwardenTree(state);
		expect(myVault).toMatchObject({ name: 'My vault' });
		expect(myVault?.count).toBeGreaterThan(0);
		expect(myVault?.children[0]).toMatchObject({ name: 'Folders' });
		// --folder double-files: collections stay populated alongside folders.
		expect(orgVault?.count).toBe(myVault?.count);
	});

	it('omits --folder for org imports unless opted in', () => {
		const command = commandForState(orgState);
		expect(command).not.toContain('--folder');
		expect(bitwardenTree(orgState)[0]?.children[0]).toMatchObject({
			name: 'No personal folders created',
		});
	});

	it('treats the Expired filter as inclusion with the CLI default on', () => {
		// Default keeps expired (no --skip-expired); unticking adds the flag.
		expect(defaultPlannerState.includeExpired).toBe(true);
		expect(commandForState(defaultPlannerState)).not.toContain('--skip-expired');
		expect(
			commandForState({ ...defaultPlannerState, includeExpired: false }),
		).toContain('--skip-expired');
	});

	it('ends option parsing with -- so a trailing tag filter cannot swallow the file', () => {
		// -t is nargs="+"; without -- argparse would read vault.kdbx as a tag.
		const state = { ...defaultPlannerState, tagInput: 'ops' };
		const command = commandForState(state);

		expect(command).toContain('-t ops -- vault.kdbx');
		expect(command.endsWith('-- vault.kdbx')).toBe(true);
	});

	it('omits the -- separator when no tag filter is set', () => {
		expect(commandForState(defaultPlannerState)).not.toContain(' -- ');
	});

	it('keeps a short command on one line but wraps a long one with backslashes', () => {
		expect(commandDisplayForState(defaultPlannerState)).not.toContain('\n');

		const long = commandDisplayForState({
			...defaultPlannerState,
			tagInput: 'admin, dev, finance, hr, legacy, ops',
			includeRecycleBin: true,
			rerunMode: 'keepass-wins',
		});
		expect(long).toContain(' \\\n  ');
		// Joining the wrapped lines back must reproduce the one-line command.
		expect(long.replaceAll(' \\\n  ', ' ')).toBe(
			commandForState({
				...defaultPlannerState,
				tagInput: 'admin, dev, finance, hr, legacy, ops',
				includeRecycleBin: true,
				rerunMode: 'keepass-wins',
			}),
		);
	});

	it('sanitizes persisted state: keeps valid values, repairs junk and mismatches', () => {
		const custom = {
			...defaultPlannerState,
			destination: 'personal' as const,
			mapping: 'personal-flat' as const,
			tagInput: 'ops',
			includeExpired: false,
		};
		expect(sanitizePlannerState(custom)).toEqual(custom);

		// Non-objects and unknown/wrong-typed fields fall back to defaults.
		expect(sanitizePlannerState(null)).toEqual(defaultPlannerState);
		expect(sanitizePlannerState('nope')).toEqual(defaultPlannerState);
		expect(
			sanitizePlannerState({ destination: 'mars', includeExpired: 'yes' }),
		).toMatchObject({
			destination: defaultPlannerState.destination,
			includeExpired: true,
		});

		// A mapping that doesn't belong to the destination is reset to that
		// destination's default so the radio group is never left unselected.
		expect(
			sanitizePlannerState({ destination: 'personal', mapping: 'org-nested' })
				.mapping,
		).toBe('personal-folders');
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
