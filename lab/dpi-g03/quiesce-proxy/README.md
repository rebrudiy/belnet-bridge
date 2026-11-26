# CONNECT proxy with quiesce control

Future tooling only; current B1 controls/runtime/traffic are unchanged. This
nested module imports the frozen `../controls/connectproxy` via local replace.
It adds lifecycle control without changing proxy forwarding/policy code.

CLI keeps `-listen` and `-config`, plus optional
`-control 127.0.0.1:8091`. Control address must be a literal loopback with a
nonzero explicit port; wildcard, hostname and private/public binds are rejected.
Admin requests additionally require a loopback remote address. Control should
stay inside the Docker namespace, without publishing the admin port.

- `POST /quiesce`: permanently calls existing `Proxy.Shutdown` once, using its
  own3s deadline, independent of the HTTP request cancellation. Closes existing
  upstream/client tunnels and rejects every subsequent CONNECT with503.
- `GET /state`: `quiesced` means irreversible quiesce requested;
  `shutdown_completed` distinguishes successful joining from timeout.
- Neither endpoint stops HTTP listeners, sends signals or exits the process.
  The namespace stays alive. Only normal OS SIGTERM/interrupt or listener failure
  initiates final process shutdown. Quiesce is irreversible; repeated POST
  returns the same original result/timestamps rather than restarting forwarding.

Response: `started_unix_micros`, `finished_unix_micros`,
`accepted_tunnels_closed`, `accepted_tunnels_closed_total`, `result` (`ok` or
`shutdown_timeout`; timeout HTTP504). Timestamps use the helper process UTC clock,
which is Linux VM UTC when the pinned Linux binary runs in Docker. Counts are
accepted proxy tunnel completion events during the operation and lifetime,
respectively. They are not distinct BelNet identities/disconnects and are not
PCAP TCP FIN acknowledgements. On timeout the forwarding gate remains closed;
never treat timeout as a complete capture drain.

Collector integration must be separately declared/frozen before future B2:
observe full80s+2s prefix grace, POST quiesce and save exact response, keep the
namespace/proxy process alive for the declared packet drain, reconcile raw PCAP
counters/cap, stop capture, then SIGTERM/stop own processes normally. This helper
alone does not implement a packet drain delay or prove capture completeness.
No current B1 data, policy, assignment or container is changed by this module.

Validation: `GOWORK=off GOPROXY=off go test -race ./...` and `go vet ./...`.
The active-tunnel test uses bounded localhost TCP fixtures only: independent
server message, quiesce→EOF, new CONNECT503 while both servers stay reachable,
state and idempotence. Other tests reject unsafe admin binds/remotes/methods.
No Docker/public/browser/native acquisition has been run with this helper.

`TOOLING.json` pins source/dependency/binary/check hashes. Linux ARM64 executable
is versioned under `bin/`; do not replace old frozen helper paths silently.
