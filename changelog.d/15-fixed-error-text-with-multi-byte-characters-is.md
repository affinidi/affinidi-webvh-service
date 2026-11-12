### Fixed — error text with multi-byte characters is truncated safely

The control plane's outbox cut a failed delivery's error text at a fixed byte
offset; text with a multi-byte character across that offset (an edge's own
error message, or one of this service's messages containing `—`) stopped the
outbox worker. User-facing error messages capped in `did-hosting-common` had the
same problem. Both now cut on a character boundary.
