# Security model

## Where TLS ends

**Oracle mode:** the browser authenticates NPM's publicly trusted certificate. HAProxy forwards the encrypted TCP stream without loading a TLS private key. TLS continues through the home firewall and ends at NPM. Encryption from NPM to each application depends on your existing upstream configuration; this project does not change it.

**Cloudflare backup:** the browser authenticates a Cloudflare edge certificate. Cloudflare decrypts HTTP, then opens a separate TLS connection to NPM using Full (strict). Cloudflare can read requests, responses, cookies, and credentials carried in HTTP. Its ability to inspect traffic is inherent to the standard proxy. [Cloudflare's connection model](https://developers.cloudflare.com/ssl/get-started/).

An orange-cloud record pointing at Oracle still terminates browser TLS at Cloudflare. Adding a TCP relay after Cloudflare cannot undo that termination. If hiding application contents from Cloudflare is a requirement, the Cloudflare HTTP proxy cannot serve as that application's fallback in this design. Application-level end-to-end encryption would be a separate feature of the application, not a feature provided here.

## What each party can see

| Party | Visibility / authority |
| --- | --- |
| Oracle relay operator | Client/home IPs, ports, timing, connection sizes, and ordinary visible TLS SNI; can drop or disrupt traffic |
| Cloudflare in normal mode | Authoritative DNS/control-plane information; no normal application HTTP connection through its proxy |
| Cloudflare in backup mode | HTTP plaintext at its edge plus network metadata |
| Home NPM | HTTP plaintext after TLS termination in either mode |
| Application | Its own requests and whatever NPM forwards |
| Home watchdog | Local token/config/state and health results; authority to edit the scoped zone's DNS through its token |

“Oracle sees nothing” is incorrect. The narrower claim is that a relay without an accepted certificate/private key cannot normally decrypt a properly verified TLS session. This is not protection against compromised clients, NPM, certificate authorities, DNS control, or stolen signing keys. Cloudflare remains a trusted DNS control-plane provider even when its proxy is bypassed. [HAProxy TCP/TLS routing controls](https://docs.haproxy.org/2.8/configuration.html).

## Network boundaries

- Home WAN 443 accepts the Oracle source IP and Cloudflare source ranges permanently. The existing forward still ends at NPM.
- This is a network source restriction. Cloudflare's shared address ranges **do not authenticate your specific zone or account**. Do not treat them as per-tenant origin authentication.
- Oracle accepts public TCP 443. Its SNI allowlist only checks a public hostname and is not authentication. Anyone can send an allowed SNI.
- Oracle is a fixed-destination TCP relay; clients cannot choose an arbitrary Internet forwarding destination.
- The optional Oracle firewall restricts new SSH to the current administrator `/32`, blocks other new TCP services, preserves OCI OUTPUT protections, and stages changes with a rollback timer. It retains existing established connections.
- The installer refuses supported signs of conflicting firewall managers before package changes. This is a conservative compatibility guard, not a complete audit of every possible host configuration.
- Public TCP 443 traffic in Oracle mode bypasses Cloudflare WAF, Access, bot checks, and HTTP rate limiting. Protect applications with authentication that works at NPM/the application on both routes.

Keep home allowlists current using [Cloudflare's official IP lists](https://www.cloudflare.com/ips/). Additional per-zone origin authentication needs a separately designed policy compatible with direct Oracle traffic. Requiring Cloudflare client certificates unconditionally on NPM would break ordinary clients arriving through the passthrough relay. This project does not silently install shared-header or mTLS authentication.

## Client IP handling

The relay opens a new TCP connection to NPM, so NPM sees Oracle as the source in normal mode. The configuration deliberately does not enable PROXY protocol because an ordinary NPM HTTPS listener does not accept it automatically.

Do not trust client-supplied `X-Forwarded-For` or `CF-Connecting-IP` just because a request arrived from Oracle. Attackers can send those HTTP headers through the relay. Cloudflare real-IP handling must trust only actual Cloudflare peers using correctly maintained ranges. This kit does not change your existing real-IP policy. Per-user application authentication should not depend on NPM seeing the original client IP.

## Certificates and transport

- NPM requires valid, publicly trusted certificates for direct clients and all probe hostnames. Cloudflare Origin CA alone is not browser trust. [Origin CA documentation](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/).
- Use Full (strict) for fallback, never Flexible or verification-disabled probing. [Full (strict) requirements](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/).
- The watchdog uses the system CA store, validates hostname/SNI, requires TLS 1.2 or newer for its connections, and does not follow HTTP redirects.
- Set application TLS policy and certificate renewal at NPM. The relay does not impose a TLS version policy on client sessions.
- The SNI parser expects an ordinary TLS ClientHello. Missing SNI or encrypted-client-hello combinations that hide the allowed name may be rejected. Public HTTP/3/QUIC is not relayed. Check inherited HTTPS/SVCB records and alternative-service advertisements before relying on clients that use those features.

## Watchdog safeguards and their limits

The controller checks exact record identities, rejects conflicting address records, and updates only the configured application A records in the documented fixed-IP mode. Unexpected identities or mixed startup state stop the writer. It requires explicit `--apply`, verifies candidate routes, persists intent atomically, and reads the API back after changes.

The backup probe uses authenticated public DNS-over-HTTPS instead of local DNS overrides. It requires the correct health body, a noncached response, and Cloudflare response headers. These are operational route checks, not cryptographic attestation of the entire application. A static health marker proves NPM and that route are responding; an individual app can still be broken.

DNS responses and Cloudflare's API remain trusted inputs. API readback does not prove all resolver caches have converged. Batch changes may become visible at different times across Cloudflare's distributed DNS. [Batch behavior](https://developers.cloudflare.com/dns/manage-dns-records/how-to/batch-record-changes/).

Timeouts, backoff, hysteresis, a process lock, and conservative restart handling reduce accidental switching. They do not create a distributed consensus system. Run one writer per configuration. A home-side measurement can mistake a path-specific home-to-Oracle problem for a general outage. There is no independent external quorum.

## Secrets and publication

The Oracle VM needs no Cloudflare token and no application TLS private keys. The home watchdog's token should have DNS-edit permission for one zone only. Its record checks do not constrain a stolen token outside the program.

Local configuration lives in `runtime/` with a mode-0700 directory and mode-0600 files. The optional systemd deployment uses root-owned credentials and a separate service account. Root and the relevant local user still have access; file permissions do not protect a compromised host.

Runtime/config files, certificates, keys, logs, backups, and environment files are ignored by Git. Logs intentionally omit tokens and API response bodies but can contain hostnames, IP addresses, and paths. Redact them before sharing. The source examples use placeholders; tests use synthetic names/IDs and mock all external traffic.

Before publishing, review staged files and Git history. A `.gitignore` cannot remove data already committed. If a real token is exposed, revoke it; deleting the visible text does not revoke the credential.

## Availability and policy

This setup retains a public home port-forward. It does not hide your home address from Oracle, Cloudflare, historical DNS, or every possible application leak. It does not provide Cloudflare's DDoS protection on the Oracle path, eliminate single points of failure, or guarantee uninterrupted streams.

Choose fallback-eligible services according to the applicable Cloudflare product and plan. A wildcard can include large downloads or video unintentionally; select explicit application records when needed. TLS passthrough at Oracle does not bypass Cloudflare's policies during backup. [Cloudflare's video/non-HTML guidance](https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/).

## Reporting vulnerabilities

Do not post secrets or deployment identifiers in public issues. If the repository owner enables private vulnerability reporting, use the repository's **Security → Report a vulnerability** feature. Otherwise request a private contact method before sending sensitive details. This repository includes automated regression checks, not a third-party security audit or guarantee.
