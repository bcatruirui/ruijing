# Optional STUN Binding service

The Node service implements a restricted STUN Binding endpoint, independently of the Worker. It handles IPv4 and IPv6 `XOR-MAPPED-ADDRESS`, transaction IDs and optional validated `FINGERPRINT`. IPv4-mapped peers from a dual-stack UDP6 listener are encoded as their actual IPv4 transport endpoints; scoped IPv6 input is rejected safely. It does not provide TURN allocations, relaying, NAT-type discovery, authentication, media transport or a complete RFC 8489 server. Authenticated/unsupported comprehension-required requests, address-changing extensions and malformed packets are dropped rather than treated as successful. It is suitable for this site's opt-in server-reflexive observation; it must not be advertised as a full TURN/ICE server.

Nothing starts without `ENABLE_STUN_SERVICE=true`. The default binding is `127.0.0.1:3478`; a non-loopback listener additionally requires `ALLOW_PUBLIC_LISTEN=true`. `.env.example` is a disabled template. Run only on an already available, verified free host:

```powershell
node --env-file=services/stun/.env services/stun/server.mjs
```

For IPv6 use an IPv6 listener such as `::1` for local tests. Before publishing an address, verify the UDP firewall, public routing and IPv4/IPv6 listener behavior. The module API `startStunService({enabled:true, host, port, allowPublic})` supports local high-port integration tests and returns an explicit `close()` method. No logging of addresses, packet data or transaction IDs is implemented.

Accepted packets are at most 512 bytes and replies are at most 52 bytes. Source buckets are bounded to 2048 short-lived entries (20 packets per source per 10 seconds), with a global 1000-packet/10-second limit. A one-second timer clears expired rate entries. These limit resource use but cannot eliminate UDP source spoofing or reflection. [RFC 8489 §16.1.2](https://www.rfc-editor.org/rfc/rfc8489#section-16.1.2) explicitly describes small reply-size amplification in anonymous Binding. Apply host and upstream source filtering/bandwidth limits before public use.

For an established production daemon, review [coturn](https://github.com/coturn/coturn) (BSD-3-Clause) and the disabled-by-default `turnserver.conf.example`. Use `stun-only`, disable its software-version attribute and connection logs, do not open relay port ranges, and apply firewall limits. The configuration is only a starting point; it is not an automatic installer. Installation is not attempted on this Windows environment.

## Browser integration and truthful results

`src/features/webrtc.ts` defaults to `iceServers: []`. It uses a data channel to gather host/mDNS candidates without requesting microphone/camera access. Candidate data stays in browser memory. Success, initialization errors, timeout, cancellation and component teardown must all close the data channel/peer connection and remove listeners/timers. The function handles its own completion/cancel cleanup; the UI must abort on unmount.

Only after this self-hosted server has been deployed and separately verified may an operator supply an ICE configuration such as `{urls:"stun:stun.<existing-domain>:3478"}`. No third-party server is contacted by default. The UI must explain this extra network request before starting. STUN provides srflx observation; relay candidates require a TURN server, which this project does not enable. Lack of srflx or relay candidates is not proof of privacy.

Local host addresses, `.local` mDNS names, srflx, relay and unknown candidates are distinguished. Public/special-use classification uses the shared project's IP parser. Merely configuring STUN without observing a server-reflexive candidate remains a limited result. Relay addresses belong to TURN infrastructure and are excluded from claimed visitor-public-IP exposure. A public host/srflx candidate different from the observed HTTP egress is a potential extra address exposure, whose meaning depends on the user's expected routing/VPN policy. Same or absent addresses cannot guarantee that all traffic is protected. The candidate list is not a browser fingerprint and must never be persisted/uploaded.

The [W3C WebRTC specification](https://www.w3.org/TR/webrtc/) defines ICE configuration and candidates. [Cloudflare Workers protocols](https://developers.cloudflare.com/workers/reference/protocols/) do not provide this raw UDP listener: the base Worker remains usable when STUN is not deployed.

## Connectivity, dual-stack and routing boundaries

The connectivity feature requires explicit `consent:true` before requesting Baidu, Taobao, WeChat, Google, GitHub, Cloudflare, YouTube or TikTok. Each check loads one selected HTTPS image; it sends no application query history, but the destination (and any redirect destination) necessarily sees the request metadata/IP. Under the browser's cookie policy an image request may also carry that destination's existing cookies; disclose this in the consent prompt. Referrers are suppressed. For strict credential omission use the optional fetch mechanism, with the weaker interpretation below. Setting image `crossOrigin="anonymous"` would require CORS and conflate CORS failures with resource reachability, so it is deliberately not used. Image completion proves only that the selected resource loaded. Failure may mean resource changes, unsupported image decoding, browser policy, DNS, network, TLS, timeout or another cause. It is not proof of censorship/blocking. The request duration includes all these layers and possible cache behavior; it is **not ping**, packet loss, bandwidth or general site performance.

The optional `fetch-no-cors` mechanism treats opaque responses as unreadable: it does not claim HTTP success, content integrity or a site-specific exit IP. Browsers do not expose generic certificate-chain inspection; do not label these requests as conclusive SSL-interception tests.

`checkRoutingNodes` compares only explicitly configured, controlled HTTPS JSON echo nodes. It uses GET with CORS and omitted credentials, validates the response IP and a declared node address family, refuses query strings/fragments/redirects, bounds JSON response reads to 4 KB before buffering, and reports failures without inferring why. Operators must allow the site's exact origin on the node (`Access-Control-Allow-Origin`, `Vary: Origin`); no credential-sharing header is needed. No nodes means `not-deployed`. A node must return its actually observed client address, using only its hosting platform's trustworthy client-address field. Caller-controlled forwarding headers are never evidence. Country/ASN differences do not themselves prove leaks or intentional split routing.

An IPv4/IPv6 connectivity claim requires independently controlled A-only / AAAA-only domains and HTTPS listeners, plus observed responses with the declared family. `workers.dev` paths do not force browser address families. Cloudflare's free proxy is normally dual-stack and does not provide per-host family selection: [official IPv6 compatibility](https://developers.cloudflare.com/network/ipv6-compatibility/). Translation such as NAT64 can also affect the interpretation; show the server-observed family rather than claiming the user's physical access technology.

The `PublicCorsEgressAdapter` interface is an optional extension only. No third-party IP API is configured or called. Any later adapter requires verified public-use permission and explicit consent; an opaque resource can never supply a genuine site egress IP.

## Tests and cost

`tests/network/stun.test.mjs` tests packet processing, IPv4/IPv6 XOR addresses, invalid messages and a real loopback UDP Binding exchange. `tests/network/browser.test.ts` is explicitly synthetic browser/ICE testing. Neither establishes a real public STUN deployment or a user's network privacy. Those require separate manual checks against the configured real service.

All code is free. Running publicly is free only with already available, verified free raw-UDP compute/network capacity. No account, public server, paid API, domain or billing option is automatically created. Without that capacity, show **STUN not deployed; public WebRTC detection limited**.
