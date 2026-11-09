// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

import { BASE, BRANCH, REPO_URL, SECTIONS, SITE } from './site.config.mjs';

export default defineConfig({
	site: SITE,
	base: BASE,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'FortressGD',
			description:
				'Open-source release toolchain for Godot 4: export hygiene, derived pack keys, a per-project pack dialect and GDScript mangling.',
			logo: { src: './src/assets/logo.svg' },
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: REPO_URL }],
			// Synced pages set their own editUrl to the source file; this covers index.mdx.
			editLink: { baseUrl: `${REPO_URL}/edit/${BRANCH}/docs/` },
			sidebar: SECTIONS.map((section) => ({
				label: section.label,
				items: section.pages.map((page) => ({ label: page.label, slug: page.slug })),
			})),
		}),
	],
});
