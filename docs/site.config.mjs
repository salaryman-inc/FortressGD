// Shared by astro.config.mjs and scripts/sync-content.mjs.

export const REPO = 'salaryman-inc/FortressGD';
export const REPO_URL = `https://github.com/${REPO}`;
export const BRANCH = 'main';

// GitHub Pages serves a project site at https://<owner>.github.io/<repo>/.
export const SITE = 'https://salaryman-inc.github.io';
export const BASE = '/FortressGD';

// Every page except the landing page is built from Markdown that already lives
// in the repository, so the site and the files on GitHub never drift apart.
// `source` is relative to the repository root; `slug` is the URL path.
export const SECTIONS = [
	{
		label: 'Start here',
		pages: [
			{
				source: 'docs/getting-started.md',
				slug: 'getting-started',
				label: 'Getting started',
				description: 'Leak checks with the official Godot editor: no Docker, no custom templates.',
			},
			{
				source: 'README.md',
				slug: 'overview',
				title: 'Overview',
				label: 'Overview',
				description: 'Features, install, usage, configuration and commands.',
			},
		],
	},
	{
		label: 'Guides',
		pages: [
			{
				source: 'docs/secrets.md',
				slug: 'guides/secrets',
				label: 'Project secret',
				description: 'Where to keep the project secret, what doctor checks, and the rotation runbook.',
			},
			{
				source: 'docs/ci.md',
				slug: 'guides/ci',
				label: 'CI and templates',
				description: 'The GitHub Action, Docker template builds and unpacker fixtures.',
			},
			{
				source: 'docs/agent-rules.md',
				slug: 'guides/agent-rules',
				label: 'Agent rules',
				description: 'Rules for AI coding agents working on a FortressGD project.',
			},
		],
	},
	{
		label: 'Reference',
		pages: [
			{
				source: 'DESIGN.md',
				slug: 'reference/design',
				label: 'Design spec',
				description: 'The FortressGD design specification.',
			},
			{
				source: 'THREAT_MODEL.md',
				slug: 'reference/threat-model',
				label: 'Threat model',
				description: 'What FortressGD tries to stop, and what it does not.',
			},
		],
	},
	{
		label: 'Project',
		pages: [
			{
				source: 'SECURITY.md',
				slug: 'project/security',
				label: 'Security policy',
				description: 'How to report a vulnerability, and what to do if a project secret leaks.',
			},
			{
				source: 'docs/releasing.md',
				slug: 'project/releasing',
				label: 'Releases',
				description: 'Installing and verifying a release, and how maintainers cut one.',
			},
			{
				source: 'CONTRIBUTING.md',
				slug: 'project/contributing',
				label: 'Contributing',
				description: 'Setting up a checkout, running the tests, and opening a pull request.',
			},
		],
	},
];

export const PAGES = SECTIONS.flatMap((section) => section.pages);
