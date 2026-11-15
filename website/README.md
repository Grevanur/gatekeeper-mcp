# Gatekeeper landing page

An Astro landing page for Gatekeeper, built with Tailwind CSS and TypeScript. The production output is static and ready for Cloudflare Pages.

## Requirements

- Node.js 20 or newer
- npm 10 or newer

## Local development

```bash
npm install
npm run dev
```

Open the local URL shown by Astro.

## Production build

```bash
npm run build
npm run preview
```

The optimized site is generated in `dist/`.

## Deploy to Cloudflare Pages

In the Cloudflare dashboard, create a Pages project from this repository and use:

- Root directory: `website`
- Build command: `npm run build`
- Build output directory: `dist`
- Node.js version: `20` or newer

Or authenticate Wrangler and run:

```bash
npm run deploy
```

The only remote media dependency is the supplied hero background MP4. The fonts are self-hosted in `public/`.
