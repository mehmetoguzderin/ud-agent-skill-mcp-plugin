# Offline preview and rendering

`documentation_preview` (089) uses selected files, context and `output_dir_path`.
`guideline_example_preview` (090) takes `example_markup_path`. `sentence_render`
(091) takes exact `sentence_conllu`, `output_format` and `output_path`. Verified
bytes must reach the authorized requested host destination; a managed resource
is supplementary when an explicit output path was requested.

SVG/HTML use offline core assets. PNG/PDF need the verified lazy browser/font/
asset pack. JPEG/WebP are schema-compatible formats but the current profile
returns a concrete prerequisite failure; do not claim those were produced.
Browser presence is not readiness: sandbox, resource limits, glyph coverage and
an actual output probe must work.

Do not use a CDN, remote renderer, ambient browser profile or `--no-sandbox` to
bypass missing dependencies. Project markup remains confined input. Inspect
nonempty output, MIME/magic, hashes, offline resolution and required glyphs.
Crashes, blanks or missing glyphs are not successful previews. Return the artifact
URI/hash, exported path, format, scope and limitations. Publication is separate.
