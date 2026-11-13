# BoxCop website

The marketing site for BoxCop. It is a static page with no build step:

- `index.html`: the whole site, one page.
- `styles.css`: all styles, including dark mode and the phone layout.
- `assets/`: the BoxCop mark, the app icon and the favicons, copied from `../brand/`.

There is no JavaScript, no framework, no external font, no CDN, no tracker and no cookie.
The app window in the hero is an HTML and CSS illustration with sample data, not a
screenshot. Replace it when real screenshots exist.

## Preview locally

Open `index.html` in a browser. All paths are relative, so it works from the file system.

To serve it over HTTP instead:

```sh
cd website
python3 -m http.server 8000
```

Then open <http://localhost:8000>.

## Deploy

Nothing is deployed yet. Any static host works (GitHub Pages, Cloudflare Pages, Netlify,
S3 or a plain web server). Upload the contents of this directory as they are; the site
works at a domain root or in a subdirectory.

## Editing rules

- Keep the "What works today" table in step with the product. Do not describe anything
  as working that the table says is not built.
- Do not claim BoxCop is first, prevents all credential theft, sandboxes every process,
  sees every agent action or has no false positives.
- BoxCop is licensed under Apache-2.0, so the site may say it is open source under
  Apache 2.0. The GitHub repository is still private. Until it is public, do not say
  or imply that the source can be read or downloaded, and keep the note that the
  repository is not public yet.
- The GitHub and "Get the beta" links point at the private repository and do not
  work for visitors. Do not deploy the site until they do, or replace them first.
- The hero illustration follows the real app: the navigation reads Overview, Events,
  Protections, Health, and an event is marked "Blocked" or "Finding". BoxCop has no
  approval step, so do not show held or approved actions.
- If the brand files change, copy them again from `../brand/` into `assets/`.
