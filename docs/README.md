# FortressGD docs site

The documentation website, built with [Starlight](https://starlight.astro.build/) and published to GitHub Pages at <https://fortressgd.salaryman.com/>.

The guides in this folder (`getting-started.md`, `ci.md`, `secrets.md`, `agent-rules.md`, `releasing.md`) and the Markdown at the repository root (`README.md`, `DESIGN.md`, `THREAT_MODEL.md`, `SECURITY.md`, `CONTRIBUTING.md`) are the source. They read fine on GitHub as they are. `scripts/sync-content.mjs` copies them into `src/content/docs/` before each build, adds frontmatter, and rewrites relative links to site pages or to files on GitHub. Those copies are git-ignored; edit the originals.

Only the landing page, `src/content/docs/index.mdx`, is written for the site alone.

## Adding a page

1. Write the Markdown file. It must start with a `# Title` line.
2. Add it to `SECTIONS` in `site.config.mjs` with a URL slug and a sidebar label.

## Preview

Needs Node.js 22.23.4 or later.

```bash
cd docs
npm ci
npm run dev      # http://localhost:4321/
npm run build    # writes dist/
```

## Deploy

`.github/workflows/docs.yml` builds the site on pull requests that touch `docs/` or a root Markdown file, and deploys it on pushes to `main`. The repository's Pages source must be set to **GitHub Actions** (Settings → Pages).
