// Copies the repository's Markdown into src/content/docs/ for Starlight:
// adds frontmatter, drops the H1 (Starlight renders the title), and rewrites
// relative links to site pages or to files on GitHub.
//
// Run by `npm run dev` and `npm run build`. The output is git-ignored.

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { BASE, BRANCH, PAGES, REPO_URL } from '../site.config.mjs';

const DOCS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = resolve(DOCS_DIR, '..');
const OUT_DIR = join(DOCS_DIR, 'src', 'content', 'docs');
const KEEP = new Set(['index.mdx']);

const pageBySource = new Map(PAGES.map((page) => [page.source, page]));

function pageUrl(page, anchor) {
	return `${BASE}/${page.slug}/${anchor}`;
}

function githubUrl(repoPath, anchor) {
	const absolute = join(REPO_ROOT, repoPath);
	const kind = existsSync(absolute) && statSync(absolute).isDirectory() ? 'tree' : 'blob';
	return `${REPO_URL}/${kind}/${BRANCH}/${repoPath}${anchor}`;
}

function rewriteTarget(target, sourceDir) {
	if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return target;
	const hash = target.indexOf('#');
	const pathPart = hash === -1 ? target : target.slice(0, hash);
	const anchor = hash === -1 ? '' : target.slice(hash);
	const repoPath = posix.normalize(posix.join(sourceDir, pathPart)).replace(/\/$/, '');
	if (repoPath.startsWith('..')) {
		throw new Error(`link "${target}" in ${sourceDir || '.'} points outside the repository`);
	}
	const page = pageBySource.get(repoPath);
	return page ? pageUrl(page, anchor) : githubUrl(repoPath, anchor);
}

function rewriteLinks(markdown, sourcePath) {
	const sourceDir = posix.dirname(sourcePath) === '.' ? '' : posix.dirname(sourcePath);
	let inFence = false;
	return markdown
		.split('\n')
		.map((line) => {
			if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
			if (inFence) return line;
			return line.replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteTarget(target, sourceDir)})`);
		})
		.join('\n');
}

function splitTitle(markdown, sourcePath) {
	const match = markdown.match(/^\s*# (.+)\n/);
	if (!match) throw new Error(`${sourcePath} does not start with a "# Title" heading`);
	return { h1: match[1].trim(), body: markdown.slice(match[0].length).replace(/^\s+/, '') };
}

function frontmatter(fields) {
	// JSON strings are valid YAML scalars, so this needs no YAML library.
	const lines = Object.entries(fields).map(([key, value]) => `${key}: ${JSON.stringify(value)}`);
	return `---\n${lines.join('\n')}\n---\n`;
}

mkdirSync(OUT_DIR, { recursive: true });
for (const entry of readdirSync(OUT_DIR)) {
	if (!KEEP.has(entry)) rmSync(join(OUT_DIR, entry), { recursive: true, force: true });
}

for (const page of PAGES) {
	const source = readFileSync(join(REPO_ROOT, page.source), 'utf8').replace(/\r\n/g, '\n');
	const { h1, body } = splitTitle(source, page.source);
	const out = join(OUT_DIR, `${page.slug}.md`);
	mkdirSync(dirname(out), { recursive: true });
	writeFileSync(
		out,
		frontmatter({
			title: page.title ?? h1,
			description: page.description,
			editUrl: `${REPO_URL}/edit/${BRANCH}/${page.source}`,
		}) +
			`\n<!-- Generated from ${page.source} by scripts/sync-content.mjs. Edit that file instead. -->\n\n` +
			rewriteLinks(body, page.source),
	);
}

console.log(`sync-content: wrote ${PAGES.length} pages to src/content/docs/`);
