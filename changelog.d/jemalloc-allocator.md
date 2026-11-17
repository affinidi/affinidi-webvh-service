### Changed — the service binaries return freed memory to the OS

`did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`,
`webvh-witness` and `webvh-watcher` now use jemalloc as their global
allocator. With glibc malloc, memory freed after a burst of requests stayed
resident, so RSS ratcheted up to its high-water mark and never came down —
which looks like a leak on a memory graph. jemalloc (with
`background_thread:true`, `dirty_decay_ms:5000`, `muzzy_decay_ms:5000`,
exported as `_rjem_malloc_conf` because tikv-jemalloc-sys prefixes jemalloc's
symbols) returns freed pages to the OS, so RSS tracks the live heap.

It is behind a new default-on `jemalloc` feature on each of those crates and
installed only by the binaries (`main.rs`), never the libraries, so a program
embedding them keeps its own allocator. Build with `--no-default-features` (and
the features you need) to use the system allocator; MSVC targets always do.
