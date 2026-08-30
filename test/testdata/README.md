# Test captures

## investigation.pcap

Synthetic HTTP and TLS 1.2 traffic between two containers on a private bridge,
captured 2026-08-30. It exists so the Zeek integration tests can assert what
Zeek writes rather than what Trawl's configuration appears to say.

It is generated rather than borrowed because the properties under test need
specific things present at once:

- **TLS 1.2, not 1.3.** TLS 1.3 encrypts the certificate, so a 1.3 capture
  produces no `x509.log` and cannot exercise the certificate parser at all.
- **A cleartext HTTP exchange**, so `http.log` and `files.log` appear alongside
  `conn.log` and `ssl.log`. `community_id` has to be asserted on every one of
  them, and a TLS-only capture covers two.
- **A self-signed certificate** with a subject and issuer that are stable, so
  assertions about parsed certificate fields do not depend on a public CA's
  rotation schedule.

Running Trawl's `images/zeek/local.zeek` over it yields conn (10), http (6),
files (6), ssl (3) and x509 (1) records. The private key is not in the
repository, and nothing here carries a credential: the endpoints are RFC 1918
container addresses and the payloads are the test server's own source file.
