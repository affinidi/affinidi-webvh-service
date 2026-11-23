### Security — `url` 2.5.9 for RUSTSEC-2026-0592

The lockfiles now take `url` 2.5.9 (and `form_urlencoded` 1.2.3), which fixes
a stack overflow in `Url::origin()` on nested `blob:` URLs.
