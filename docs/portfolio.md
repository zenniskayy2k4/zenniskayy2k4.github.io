# Optional portfolio pages

The original Chirpy blog remains at `/`, with its original avatar, backgrounds, colors, navigation controls, About content, and post URLs.

Only two tabs are added: `/portfolio/` and `/research/`. Their content lives in `_tabs/portfolio.html` and `_tabs/research.html`, with shared data in `_data/research.yml` and `_data/security_work.yml`.

`_includes/metadata-hook.html` loads `assets/css/portfolio-page.scss` only for the new portfolio layout. `_sass/portfolio.scss` does not change the existing blog UI. The upstream sidebar, topbar, pagination, and home layouts are used unchanged.

Portfolio typography follows Chirpy: Source Sans Pro body text and Lato headings. Headings wrap naturally without manual line breaks. Research entries share one responsive row layout, with the critical Incus advisory emphasized; project and experience sections use spacing and separators. The Impeccable font detector's Lato warning is an intentional exception to keep these additive pages consistent with the existing site.

## Light mode

`_sass/light-mode.scss` refines only the light palette: a dark illustrated sidebar with clear artwork and light text, paired with muted blue-gray content and softly tinted cards. It is imported by the shared theme stylesheet. The explicit theme toggle and automatic OS preference use the same values. The original layout, identity, images, and dark palette remain in place.

## Local development

```bash
bundle exec jekyll serve --host 0.0.0.0 --port 4000 --livereload --force_polling
```

Open http://localhost:4000. Jekyll rebuilds after edits and LiveReload refreshes the browser. Restart the command after editing `_config.yml`. In a remote workspace, forward port 4000; LiveReload uses port 35729, which may also need forwarding.

To build without serving:

```bash
bundle exec jekyll build
```

## CV privacy

There is no public resume link or automatic resume-file detection. Use the email contact to share a CV privately. Do not put a private CV in this public repository or its assets directory. A separately redacted public CV can be added later if desired.

## Validation

```bash
env -u DEBUG bundle exec jekyll build
env -u DEBUG bundle exec htmlproofer _site --disable-external
```

Unsetting DEBUG avoids this container's optional-debugger issue with HTMLProofer. Local `AGENTS.md` instructions are excluded from the published output.
