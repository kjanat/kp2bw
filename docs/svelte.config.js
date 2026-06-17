import adapter from '@sveltejs/adapter-auto';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
	compilerOptions: {
		runes: true,
	},
	kit: {
		adapter: adapter(),
	},
	preprocess: vitePreprocess(),
};

export default config;
