### Fixed — outbound HTTP clients keep their timeouts and redirect policy

The client `did-hosting-common` uses to resolve a DID log from a hosting URL
and to send a Trust Task over HTTPS has a 30-second total timeout, a
10-second connect timeout, and refuses redirects. If that client could not be
built (the TLS backend or the platform certificate verifier failed to
initialise), it was silently replaced by a default client with no timeouts
that follows redirects. The failure is now returned to the caller as an error
instead: `WebVHClient::resolve_did` returns `WebVHError::Http`, and a Trust
Task HTTPS send fails like any other transport error. The client is now
public as `did_hosting_common::outbound_client`.

Two other clients now follow the same policy:

- `did-hosting-daemon setup` authenticates to a VTA's REST URL, taken from
  the VTA's DID document, with this client. Before, it used a default client
  with no timeouts that followed redirects.
- The health check's reachability probe (`check_url_reachable`) adds a
  5-second connect timeout to its 5-second total timeout and no longer
  follows redirects, so a 3xx is reported as that status. If its client
  cannot be built, the check fails with the reason instead of panicking.

Behaviour change: on a host whose TLS setup cannot initialise, these calls now
fail instead of running without timeouts or redirect refusal. The health
check reports a redirecting URL as reachable with its 3xx status, as it
already does for other non-success statuses, instead of following it.
