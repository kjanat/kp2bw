import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

const config = {
	compilerOptions: {
		runes: true,
	},
	kit: {
		adapter: adapter({ fallback: '404.html' }),
		paths: { base: process.argv.includes('dev') ? '' : process.env.BASE_PATH },
	},
	preprocess: vitePreprocess(),
};

export default config;
