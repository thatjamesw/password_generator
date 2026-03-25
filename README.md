# Password Generator

This repo now ships as a static browser app that can be published directly with GitHub Pages. It keeps the original password policy behavior, but moves generation into the browser with `crypto.getRandomValues` so there is no backend and no build step.

## What Changed

- Root `index.html` is the app entry point for GitHub Pages
- `static/app.js` contains the browser-side password generation logic
- `static/styles.css` reuses the visual language from `redactor_mvp`
- `.nojekyll` is included so GitHub Pages serves the site as-is

The original CLI tools are still present:

- `password_generator.py`
- `password_generator.sh`

## Features

- Static site, suitable for GitHub Pages
- Browser-only generation with Web Crypto
- No third-party JavaScript libraries or npm packages required
- Default 32-character passwords
- Automatic all-class mode when no class is selected
- Guaranteed class coverage for class-based generation
- Optional exclusion of similar and ambiguous characters
- Optional custom character sets
- Optional weighted custom character sets
- Multi-password generation
- Clipboard copy and text download
- Estimated entropy display
- Passphrase mode backed by the official EFF large wordlist

## Local Preview

You can open the page directly:

```bash
open index.html
```

Or serve it locally:

```bash
python3 -m http.server
```

Then visit `http://localhost:8000`.

## GitHub Pages

1. Push the repository to GitHub.
2. Ensure the default branch is `main` or adjust [`pages.yml`](./.github/workflows/pages.yml) if you deploy from a different branch.
3. In the repository settings, open Pages.
4. Set the source to `GitHub Actions`.
5. Push to `main` or run the workflow manually, then wait for Pages to publish the site.

The workflow simply uploads the static repository contents and deploys them. There is no build step.

## Security Notes

- Passwords are generated in-browser using `crypto.getRandomValues`.
- The shipped app uses plain browser APIs only, with no external runtime dependencies.
- The page is designed not to make outbound network requests.
- A restrictive Content Security Policy is set in [`index.html`](./index.html).
- Input size is bounded in the UI to avoid accidental oversized generation requests.
- Passphrase mode uses a bundled local copy of the official EFF large wordlist rather than a tiny handcrafted set.
- Clipboard copy depends on browser permissions and secure context rules.
- Entropy is an estimate based on the active pool and should be treated as guidance, not a formal proof.
- If you use clipboard managers, copied passwords may still persist outside the page.
