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
		color: #c7c9bd;
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
		border-color: #d2b56f;
		background: #211d12;
	}

	.folder::before {
		top: -4px;
		left: 1px;
		width: 6px;
		height: 3px;
		border: 1px solid #d2b56f;
		border-bottom: 0;
		background: #111411;
	}

	.collection {
		width: 11px;
		height: 11px;
		border-color: #8ecf9f;
		background: #101d16;
	}

	.collection::before {
		inset: 2px;
		border: 1px solid #8ecf9f;
	}

	.collection::after {
		top: 4px;
		left: -3px;
		width: 2px;
		height: 2px;
		background: #8ecf9f;
		box-shadow: 13px 0 0 #8ecf9f, 6px -5px 0 #8ecf9f, 6px 5px 0 #8ecf9f;
	}

	.recycle {
		border-color: #d48670;
		border-radius: 0 0 3px 3px;
		background: #251713;
	}

	.recycle::before {
		top: -4px;
		left: -2px;
		width: 13px;
		height: 2px;
		border: 1px solid #d48670;
		background: #111411;
	}

	.recycle::after {
		top: 3px;
		left: 3px;
		width: 1px;
		height: 5px;
		background: #d48670;
		box-shadow: 3px 0 0 #d48670;
	}
</style>
