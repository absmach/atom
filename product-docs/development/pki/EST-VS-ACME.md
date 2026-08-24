# EST and ACME — why Atom uses EST for device enrollment

This note explains what enrollment protocol Atom uses to hand out
certificates, which standard defines it, and how it compares to ACME (the
protocol that powers Let's Encrypt). Read this before touching anything under
[../../../src/certs/enrollment/](../../../src/certs/enrollment/) or before
adding a new enrollment surface.

## The one-line difference

> **EST (RFC 7030)** — "I already know this device belongs to me. Give it a cert."
>
> **ACME (RFC 8555)** — "Prove to me you actually control this domain name. Then I'll give you a cert."

Everything below is a longer version of those two lines.

## The problem an enrollment protocol solves

A certificate is only useful if it ends up on the machine that needs it, with
the private key generated on that same machine (so it never travels). At scale
that means the device has to *ask* the CA for a cert over the network, prove
who it is, and receive a signed cert in response — automatically, without a
human.

Doing this by hand does not scale:

1. Operator SSHs into the device.
2. Runs `openssl req` to generate a private key and CSR.
3. Copies the CSR out.
4. Emails it to the CA operator.
5. CA operator signs it and mails the cert back.
6. Operator SSHs back in and installs the cert.

Fine for three servers. Impossible for ten thousand meters.

An enrollment protocol replaces steps 3–6 with an HTTPS round-trip the device
does for itself. Both EST and ACME are that HTTPS round-trip; they differ only
in **how the CA convinces itself the requester is who they claim to be**.

## EST — RFC 7030

**Standard:** [RFC 7030 — Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7030), published 2013.

**Trust model:** The CA operator provisioned the device ahead of time. There
is already a bootstrap credential on the device — a factory-installed
certificate, an mTLS client cert, a shared secret, an operator-issued bearer
token — and the CA already knows what to expect. Enrollment is: *authenticate
with that credential, submit a CSR, receive a cert.* That's it.

**Wire shape:** boring HTTPS with fixed URLs under `/.well-known/est/`. The
whole surface is five endpoints:

| Endpoint | What it does |
|---|---|
| `GET /.well-known/est/cacerts` | Fetch the CA trust bundle |
| `POST /.well-known/est/simpleenroll` | Submit a CSR, receive a cert |
| `POST /.well-known/est/simplereenroll` | Renew using the existing cert as proof of identity |
| `POST /.well-known/est/serverkeygen` | Ask the server to generate the key **and** cert (returned together in a multipart body) |
| `GET /.well-known/est/csrattrs` | Fetch the CSR attribute template the server expects |

Media types are CMS-based (`application/pkcs10` in, `application/pkcs7-mime`
out) so the payload is a standard signed-blob format any TLS-aware
language can produce and parse.

**Where you see it in the wild:**

- IoT device fleets (smart meters, sensors, industrial gateways).
- Enterprise VPN endpoints and corporate device management.
- DOCSIS cable/telco modems — the ISP-facing side of your home internet has
  been enrolling via EST-style flows for years.
- mTLS between microservices in a private cluster: each pod EST-enrolls at
  startup, gets a short-lived cert (hours to a day), rotates continuously.
- Cisco / networking gear firmware.

**Where Atom fits:** Atom is the identity and PKI service for a platform whose
customers ship devices. Those devices belong to the customer, the customer
already registered them in Atom's identity system, and the bootstrap
credential (an entity ID plus password, an existing cert, or an
operator-issued session) lives on the device. That matches EST's model
exactly. See PR-014 and PR-014b in the release description.

## ACME — RFC 8555

**Standard:** [RFC 8555 — Automatic Certificate Management Environment](https://datatracker.ietf.org/doc/html/rfc8555), published 2019 by the same people who ran Let's Encrypt.

**Trust model:** The CA has no prior relationship with the requester. Anyone
on the internet can ask for a cert for `blog.example.com`. So the protocol is
built around exactly one question: *does the requester actually control the
thing the cert names?* That question is answered by a **challenge** the client
must satisfy before the CA will sign anything.

**How a Let's Encrypt enrollment actually runs** (this is what
`certbot`, `acme.sh`, and Caddy's built-in do under the hood):

1. **Create an account** — client generates an account key pair, POSTs the
   public key to the ACME directory URL; every subsequent request is signed
   with that account key.
2. **Request an order** — "I want a cert for `blog.example.com`." The CA
   responds with a list of challenges the client must solve.
3. **Solve a challenge** — pick one of:
   - **HTTP-01** — put a random token at
     `http://blog.example.com/.well-known/acme-challenge/<token>`; the CA
     fetches it from the public internet.
   - **DNS-01** — publish a `_acme-challenge.blog.example.com` TXT record with
     the token. The only challenge that supports wildcard certs
     (`*.example.com`).
   - **TLS-ALPN-01** — respond to a special TLS handshake on port 443 with
     the token embedded.
4. **Tell the CA to verify** — CA validation servers hit the endpoint from
   several vantage points, look for the token, mark the challenge valid.
5. **Submit the CSR** — separate from the account key; the cert will bind
   this CSR's public key.
6. **Download the signed cert chain.**

Four to eight HTTPS round-trips, 5–30 seconds. Let's Encrypt certs are
90-day, by design, to force automation of renewal.

**Where you see it in the wild:** every modern public-facing web server
(Caddy does it automatically, nginx via certbot, Kubernetes via cert-manager),
CDNs (Cloudflare, Fastly), anything with a public DNS name that terminates
TLS.

## Side-by-side

| | EST (RFC 7030) | ACME (RFC 8555) |
|---|---|---|
| Who's the client? | A device the operator owns and pre-provisioned | Anyone on the internet |
| How is identity established? | Bootstrap credential the CA operator embedded ahead of time (device cert, shared secret, mTLS) | Proof-of-control over a domain name via HTTP/DNS/TLS challenge |
| Cert subject | Whatever the operator chose — device serial, tenant ID, service account | The domain name(s) being validated |
| Who's the CA? | Private, owned by the operator (or a platform like Atom) | Public, trusted by every browser via WebPKI |
| Typical validity | Weeks to years, operator's choice | 90 days, hard-coded |
| Wire shape | HTTPS, CSR in POST body, cert in response | HTTPS + JSON-signed requests, multi-step challenge flow |
| Volume model | Thousands to millions of devices in one operator's fleet | Hundreds of millions of certs across the whole internet |
| Renewal path | `simplereenroll` — present the existing cert to authenticate the renewal request | New order, new challenge each time |

## Why not use ACME for device fleets?

ACME assumes the requester has a public DNS name and a public web server that
can answer an HTTP-01 challenge. That is absurd for a sensor, a meter, or a
service running inside a private cluster. There is no `blog.example.com` to
control — there is `device-serial-4A7F91` that the operator already registered
in the identity system. The relevant question is not "do you control a DNS
name?" but "are you the device the operator provisioned this bootstrap
credential onto?" — which is precisely EST's model.

## Why not use EST for the public web?

EST assumes the CA already trusts the requester via a bootstrap credential.
Let's Encrypt has no such relationship with the millions of unknown people who
ask it for certs every day. To use EST for the public web you would first
have to bolt on a "prove you control this domain name" layer, at which point
you have reinvented ACME. Which is what happened — ACME exists because EST
did not fit the public-CA case.

## They coexist

Most large organizations run both:

- **ACME** for their public-facing endpoints (getting certs from Let's Encrypt
  or a commercial public CA).
- **EST** for their internal device fleet or service mesh (getting certs from
  their own private CA — which is what Atom is).

They solve different problems and there is no reason to pick one over the
other. Atom's job is the second bullet.

## Where this lives in the code

- Server implementation: [src/certs/enrollment/est.rs](../../../src/certs/enrollment/est.rs) — the five RFC 7030 endpoints, wire encoding only.
- Business logic (subject, scope, profile, issuer, lifecycle, rate-limit, audit): [src/certs/enrollment/service.rs](../../../src/certs/enrollment/service.rs).
- Dedicated TLS listener for enrollment: [src/certs/enrollment/tls.rs](../../../src/certs/enrollment/tls.rs).
- Interop test using an independent EST client: [tests/m41_pki_est.rs](../../../tests/m41_pki_est.rs).
- Per-PR design notes: [pr-014-enrollment.md](pr-014-enrollment.md) and [pr-014b-est-adapter.md](pr-014b-est-adapter.md).

Atom does **not** ship an EST client. Devices bring their own — embedded
firmware, an OS package, or a language library. The integration test uses
GlobalSign's `estclient` (v1.0.7) as an independent client, so the test proves
Atom's server is RFC-conformant against something the Atom team did not
write. See the "EST client" section of [RELEASE-TESTING.md](RELEASE-TESTING.md)
for how to install it.
