import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const basePath = process.argv.includes('dev') ? '' : (process.env.BASE_PATH ?? '');
if (basePath && !basePath.startsWith('/')) {
	throw new Error('BASE_PATH must start with /');
}
const base = basePath ? `/${basePath.slice(1)}` as const : '';

export default defineConfig({
	plugins: [sveltekit({
		compilerOptions: { runes: true },
		adapter: adapter({ fallback: '404.html' }),
		paths: { base },
		preprocess: vitePreprocess(),
	})],
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'client',
					browser: {
						enabled: true,
						provider: playwright(),
						instances: [{ browser: 'chromium', headless: true }],
					},
					include: ['src/**/*.svelte.{test,spec}.{js,ts}'],
					exclude: ['src/lib/server/**'],
				},
			},

			{
				extends: './vite.config.ts',
				test: {
					name: 'server',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}'],
				},
			},
		],
	},
});
