// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://trawl.cloud',
	integrations: [
		starlight({
			title: 'Trawl',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/shart-cloud/trawl' }],
			sidebar: [
				{ label: 'Quickstart', slug: 'quickstart' },
				{
					label: 'Planning',
					items: [{ label: 'Post-MVP Evolution Plan', slug: 'roadmap' }],
				},
				{
					label: 'Architecture Decisions',
					items: [{ autogenerate: { directory: 'adr' } }],
				},
				{
					label: 'Operations',
					items: [{ autogenerate: { directory: 'operations' } }],
				},
				{
					label: 'Security',
					items: [{ autogenerate: { directory: 'security' } }],
				},
				{
					label: 'Reference',
					items: [{ autogenerate: { directory: 'reference' } }],
				},
			],
		}),
	],
});
