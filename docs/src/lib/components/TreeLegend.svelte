<div class="legend" aria-label="Tree legend">
	<span><i class="icon folder"></i>Folder</span>
	<span><i class="icon collection"></i>Collection</span>
	<span><i class="icon recycle"></i>Recycle Bin</span>
</div>

<style>
	.legend {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: center;
		gap: 6px 12px;
		min-height: 22px;
		color: var(--text-dim);
		font-size: 0.68rem;
		line-height: 1;
	}

	.legend > span {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		white-space: nowrap;
	}

	.icon {
		position: relative;
		display: inline-block;
		width: 11px;
		height: 10px;
		border: 1px solid #95a195;
	}

	.icon::before,
	.icon::after {
		position: absolute;
		content: "";
	}

	.folder {
		border-color: var(--icon-folder);
		background: var(--icon-folder-bg);
	}

	.folder::before {
		top: -4px;
		left: 1px;
		width: 6px;
		height: 3px;
		border: 1px solid var(--icon-folder);
		border-bottom: 0;
		background: var(--bg);
	}

	.collection {
		width: 11px;
		height: 11px;
		border-color: var(--icon-collection);
		background: var(--icon-collection-bg);
	}

	.collection::before {
		inset: 2px;
		border: 1px solid var(--icon-collection);
	}

	.collection::after {
		top: 4px;
		left: -3px;
		width: 2px;
		height: 2px;
		background: var(--icon-collection);
		box-shadow:
			13px 0 0 var(--icon-collection),
			6px -5px 0 var(--icon-collection),
			6px 5px 0 var(--icon-collection);
	}

	.recycle {
		border-color: var(--icon-recycle);
		border-radius: 0 0 3px 3px;
		background: var(--icon-recycle-bg);
	}

	.recycle::before {
		top: -4px;
		left: -2px;
		width: 13px;
		height: 2px;
		border: 1px solid var(--icon-recycle);
		background: var(--bg);
	}

	.recycle::after {
		top: 3px;
		left: 3px;
		width: 1px;
		height: 5px;
		background: var(--icon-recycle);
		box-shadow: 3px 0 0 var(--icon-recycle);
	}
</style>
