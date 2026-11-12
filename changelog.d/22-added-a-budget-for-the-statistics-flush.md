### Added — a budget for the statistics flush

The control plane and the daemon flush per-DID statistics every 10 seconds:
at most 200 rows, each a read and a write, all at once. On a small DynamoDB
table that burst could take most of the capacity.
`[stats_flush] max_rows_per_second` (env
`CONTROL_STATS_FLUSH_MAX_ROWS_PER_SECOND`, `DAEMON_STATS_FLUSH_MAX_ROWS_PER_SECOND`)
now sets the rate, from 1 to 10,000, and the flush is paced at it across the
interval instead of written in one burst. The default, 20, keeps today's
volume. Rows past the budget wait for the next flush; as before, time-series
buckets older than an hour and rows past the collector's caps are dropped
with a warning, so a budget below the rows produced loses series data.
Shutdown stops the pacing, and the final flush writes the rest.
