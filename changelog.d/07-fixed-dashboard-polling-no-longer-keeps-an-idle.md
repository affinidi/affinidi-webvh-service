### Fixed — dashboard polling no longer keeps an idle console signed in

The console's dashboard refreshed itself every five seconds, and each refresh
counted as activity, so a console left open on the dashboard never reached
`auth.admin_idle_timeout`. Requests the console sends on a timer now carry
`X-Background-Request: 1`. The control plane authenticates and answers them
as before, but does not record them as session activity. The dashboard refresh
and the pending-approval log check on a DID's page are marked this way, as are
the agent-name and DID reloads they trigger, and both polls pause while the
browser tab is hidden. A request without the header counts as
activity, as before.
