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
- Do not call BoxCop open source until the repository is public and has a license.
- If the brand files change, copy them again from `../brand/` into `assets/`.
