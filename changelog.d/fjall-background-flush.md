### Changed — a fjall store flushes its writes in the background, holding at most 8 MiB in memory by default

Every service that opens a local fjall store (control, server, witness,
watcher, and the daemon's two stores) now runs a background flusher. fjall
3.1 records `max_write_buffer_size` but does not enforce it, so before this
change buffered writes stayed in memory, and in the journal replayed at
startup, until fjall flushed on its own schedule. The flusher seals the
memtables once the unflushed bytes across all keyspaces reach
`[fjall].write_buffer` (env `STORAGE_FJALL_WRITE_BUFFER`; default **8 MiB**,
previously effectively unbounded), and flushes anything older than five
minutes however small, which also keeps the journal short. Memory use and
flush behaviour change for every fjall deployment; raise
`[fjall].write_buffer` if a write-heavy service now flushes more often than
you want. (#340)
