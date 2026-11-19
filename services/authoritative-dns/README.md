# Optional authoritative DNS observation service

This is a real, independent Node 24+ service. It is **not deployed by the base website**. Starting it requires `enabled: true` through the module API, or `ENABLE_DNS_SERVICE=true` through environment variables. Its default listener is loopback, UDP/TCP 5353 and HTTP 8789. No public listener or cloud account is provisioned.

## Existing resources required for public use

1. An already owned domain: delegate a child such as `probe.example.com` with NS records to an authoritative nameserver on an already available host. Configure parent/glue A/AAAA records where necessary. Keep these DNS-only, without an HTTP proxy. This service serves an unsigned child zone; do not publish a parent DS record for it unless a separately verified signing deployment is added. `workers.dev` is not a user-controlled DNS zone.
2. A host with public UDP **and** TCP 53, and controlled HTTPS 443. Permit both DNS transports through the host firewall and any upstream security list. Do not open a recursive resolver.
3. A valid wildcard certificate for `*.probe.example.com` plus a certificate for any API hostname. The generated probe names have exactly one random label. Use an existing TLS reverse proxy, or provide `TLS_KEY_FILE` and `TLS_CERT_FILE`; certificate issuance/renewal must be arranged separately. A private key never belongs in Git.
4. A high-entropy private API key of at least 32 characters, provided only to the Worker and this service. Do not put it in Vite/public environment variables. With a TLS proxy, leave Node on loopback and forward `/v1/*` and the wildcard `/probe` route. Disable proxy/access/body logs. `TRUSTED_TLS_PROXY=true` explicitly records that deployment choice; it does not create the proxy.

For loopback development, copy `.env.example` into a git-ignored local file in this project, fill the address/zone/key, explicitly enable it, and invoke Node's built-in environment loader:

```powershell
node --env-file=services/authoritative-dns/.env services/authoritative-dns/server.mjs
```

Use port 53 only after reviewing binding privileges. Prefer an OS capability or a restricted service account rather than running the whole application as root. IPv4 and IPv6 interfaces can be bound using the appropriate `LISTEN_HOST`; verify actual reachability of every address you publish. A certificate and real delegation cannot be validated by loopback tests.

## Worker integration contract

The independent API is server-to-server. All API calls use HTTPS in public deployment, `Content-Type: application/json`, `Authorization: Bearer <private DNS_API_KEY>`, and `Cache-Control: no-store`. No CORS allow-any response is emitted. A browser `Origin`, if present, must match `ORIGIN_ALLOWLIST` exactly. `worker/api/dns.ts` provides the same-origin proxy handler; the root Worker invokes it after the common origin/rate/concurrency checks. Configure `DNS_SERVICE_URL` as the fixed service origin and `DNS_SERVICE_SECRET` as a Worker secret (the same value as the independent `DNS_API_KEY`). No visitor-provided endpoint is accepted. Only HTTPS service origins are accepted publicly; explicit localhost HTTP is supported for local verification. Inputs are limited to 1 KB and upstream JSON to 16 KB. Neither service-key values nor arbitrary upstream fields are returned to the browser. Do not announce capability until health and deployment prerequisites have been verified.

| Request | JSON body | Response |
|---|---|---|
| POST `/v1/session` | `{}` | `{id, secret, expiresAt, probeUrls}` |
| POST `/v1/results` | `{id, secret}` | `{id, expiresAt, resolvers, verdict:"undetermined", explanation}` |
| POST `/v1/delete` | `{id, secret}` | deleted status |

The browser-facing proxy equivalents are POST `/api/dns/start`, `/api/dns/results` and `/api/dns/delete`. Missing/invalid service configuration or unavailable upstream yields a genuine `DNS_SERVICE_UNAVAILABLE` response. A syntactically configured service is not proof of verified deployment; an operator must still check actual delegation, TLS and packet reachability.

Read credentials stay in browser memory only. Do not place them in a URL, history, localStorage or logging context. Each public random query name is different from the result secret, so a resolver observing the query cannot read the session. The service stores only a secret hash. Missing, invalid, expired or unauthorized read credentials all receive the same unavailable response.

After explicit user consent, the browser fetches the four returned HTTPS `/probe` URLs with `credentials:"omit"`, `referrerPolicy:"no-referrer"`, `cache:"no-store"`, `mode:"no-cors"`, and an AbortSignal. The resource returns 204. An opaque success is not the DNS evidence; only actual incoming authority queries are evidence. Query types A, AAAA, HTTPS/SVCB and other valid questions can differ by browser. Poll results with the private per-session secret, display real observed resolvers, and delete the session on completion/cancel. The service does not resolve ASN or geolocation through external APIs; enrich resolver addresses in the project's own offline intelligence engine.

`src/features/dns.ts` implements this browser lifecycle as `runDnsLeakTest({signal?,onProgress?})`. It validates the returned session and four same-zone single-label HTTPS probe URLs, dispatches probes only after invocation, polls only the same-origin proxy, and always attempts deletion with an independent short timeout even if the original operation was cancelled. It returns only real resolver observations, an `undetermined` privacy verdict, probe counts and `cleanupConfirmed`. An opaque response never becomes a resolver observation. If a create response is lost or deletion fails, the client cannot claim immediate deletion; the server's bounded in-memory TTL is the fallback. Abort the feature's signal when its UI is unmounted.

## Privacy, limits and interpretation

The default in-memory session TTL is 150 seconds, capped at 180 seconds by code; reads enforce expiry and a one-second sweep clears expired maps. Non-finite retention settings are rejected. Session/query state is also deleted on explicit completion or shutdown. Default capacity is 256 sessions, four random probe names, 16 distinct resolvers per session and 32 observed query types per resolver. Unknown numeric QTYPEs remain honest `TYPEn` observations; they cannot corrupt the response schema or grow a set without bound. IPv4-mapped transport addresses are normalized to IPv4. Source rate counters expire after 10 seconds and are periodically removed. No visitor HTTP address is added to a session; no EDNS Client Subnet is recorded. Do not enable external access logs in the host, reverse proxy or process supervisor without revising the privacy statement.

The DNS server sets RA=0, answers only its delegated zone, refuses out-of-zone questions, ANY and transfers, and has no forwarding/recursion implementation. Packet counts are checked before codec allocations. UDP responses are limited to 512 bytes, TCP frames to 4096 bytes, simultaneous TCP sockets to 64, idle TCP to three seconds, absolute TCP lifetime to five seconds and per-connection queries to 32. HTTP headers/requests have five-second timeouts checked every second, headers are limited to 8 KB and bodies to 2 KB. Anonymous/probe traffic has a separate budget from the authenticated session API; authenticated deletion is not blocked by that API's creation/read budget. All bucket maps are cleared on shutdown. Per-source and global rate limits mitigate reflection and resource exhaustion. Small authoritative answers can still be reflected when UDP source spoofing is possible; host/upstream source filtering and bandwidth limits remain necessary. Do not describe the service as immune to UDP reflection.

Resolvers can be shared, geographically distributed, anycast, forwarded, DoH/DoT-backed or split by policy. A different resolver ASN/country is not proof of a leak. A matching resolver does not prove all DNS is protected. Without the user's intended VPN/DNS policy, return `undetermined`. No result establishes the user's precise location, identity or malicious behavior.

The browser does not expose the certificate chain or a general TLS interception verdict to this application. HTTPS resource success/failure cannot confirm or rule out “SSL hijacking”. This limitation applies to the connectivity module too.

## Verification status

`tests/network/dns.test.mjs` includes synthetic-clock credential/expiry/capacity tests, packet tests, and **real loopback UDP/TCP/HTTP integration**. `tests/network/dns-feature.test.ts` separately marks Mock Worker-upstream and browser-fetch tests; these cover unavailable configuration, endpoint injection, limits, safe forwarding, observation-only verdicts, cancellation and deletion. These are separate from public deployment verification. No public NS delegation, certificate, recursive resolver observation or cloud deployment is asserted by those tests.

## Sources, licenses and cost

- [dns-packet](https://github.com/mafintosh/dns-packet) is MIT; retain its copyright/license through the dependency distribution. It is a codec, not a paid service.
- [Cloudflare protocols](https://developers.cloudflare.com/workers/reference/protocols/) and [Connect Handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/connect/) do not offer public UDP/TCP DNS hosting in a Free Worker. Advanced DNS remains independent.
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) explains DNS-over-TCP requirements. Both transports are implemented here.
- [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm), checked 2026-10-28: A1 allowance is currently 1,500 OCPU-hours / 9,000 GB-hours monthly (about 2 OCPU / 12 GB), with capacity limits and idle reclamation. It is optional, not provisioned. [Oracle signup guidance](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier.htm) says most users need a phone and card, and no charge occurs unless the account is upgraded. A temporary card authorization can still occur. Do not upgrade to paid status or consume paid trial resources for this project.

This source costs nothing. Public operation costs zero only when the operator has a genuinely free host and an existing domain/certificate route whose network, address, storage and request allowances have been verified. If those resources are absent, the truthful production state is **not deployed**.
