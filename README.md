# shelf_letsencrypt

[![pub package](https://img.shields.io/pub/v/shelf_letsencrypt.svg?logo=dart&logoColor=00b9fc)](https://pub.dev/packages/shelf_letsencrypt)
[![Null Safety](https://img.shields.io/badge/null-safety-brightgreen)](https://dart.dev/null-safety)
[![Codecov](https://img.shields.io/codecov/c/github/gmpassos/shelf_letsencrypt)](https://app.codecov.io/gh/gmpassos/shelf_letsencrypt)
[![Dart CI](https://github.com/gmpassos/shelf_letsencrypt/actions/workflows/dart.yml/badge.svg?branch=master)](https://github.com/gmpassos/shelf_letsencrypt/actions/workflows/dart.yml)
[![GitHub Tag](https://img.shields.io/github/v/tag/gmpassos/shelf_letsencrypt?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/releases)
[![New Commits](https://img.shields.io/github/commits-since/gmpassos/shelf_letsencrypt/latest?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/network)
[![Last Commits](https://img.shields.io/github/last-commit/gmpassos/shelf_letsencrypt?logo=git&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/commits/master)
[![Pull Requests](https://img.shields.io/github/issues-pr/gmpassos/shelf_letsencrypt?logo=github&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt/pulls)
[![Code size](https://img.shields.io/github/languages/code-size/gmpassos/shelf_letsencrypt?logo=github&logoColor=white)](https://github.com/gmpassos/shelf_letsencrypt)
[![License](https://img.shields.io/github/license/gmpassos/shelf_letsencrypt?logo=open-source-initiative&logoColor=green)](https://github.com/gmpassos/shelf_letsencrypt/blob/master/LICENSE)

`shelf_letsencrypt` brings support for [Let's Encrypt][letsencrypt] to the [shelf][shelf_package] package.

[shelf_package]: https://pub.dev/packages/shelf

[letsencrypt]: https://letsencrypt.org/

`dns-persist-01` is the recommended challenge type when your ACME CA supports
it. It avoids serving transient HTTP challenge files and is designed for a
stable delegated DNS TXT record tied to your ACME account.

# Developing with shelf_letsencrypt
ACME certificate authorities use challenges to prove that you control the
domain before they issue a certificate. `shelf_letsencrypt` supports two
challenge mechanisms, and the right choice changes what your development
environment needs to expose.

## A word of caution
Let's Encrypt rate-limits the issuing of production certificates.
It is very easy to get locked out of Let's Encrypt for an extended period of time (days),
leaving you in the situation where you can't issue a production certificate.

CRITICAL: you could end up with your production systems down for days!!!!

I would advise you to read up on the Let's Encrypt rate limits:

https://letsencrypt.org/docs/rate-limits/

To avoid this potentially major issue, make certain that you test with a STAGING
certificate.


Do this by passing in 'production: false' (the default) when creating
the LetsEncrypt certificate.
Staging certificates still have rate limits, but they are much more generous.

```dart 
final LetsEncrypt letsEncrypt = LetsEncrypt(certificatesHandler, production: false);
```


## Challenge mechanisms

### http-01

`http-01` is the default challenge type. The ACME server validates the request
by fetching a token from:

```text
http://<domain>/.well-known/acme-challenge/<token>
```

Development implications:

- The domain's public DNS must resolve to the machine, router, or load balancer
  that can reach your development server.
- Port 80 must be reachable from the public internet. If your app listens on a
  high port such as 8080, your router or firewall needs to forward public port
  80 to that local port.
- On Linux, binding directly to ports below 1024 usually requires root
  privileges, `sudo`, or a capability such as `CAP_NET_BIND_SERVICE`.
- This mode is convenient when your development machine is deliberately exposed
  to the internet, but it is awkward behind carrier-grade NAT, restrictive
  firewalls, or networks where inbound port forwarding is unavailable.

For local testing with `http-01`, I normally use a cheap test domain and point
its A record at my development router. The router then forwards port 80 to the
local server port used by the example app.

### dns-persist-01

`dns-persist-01` proves control of the domain with a stable delegated DNS TXT
record rather than an inbound HTTP request. Use it when your ACME CA supports
the challenge and you can publish the required TXT record.

Development implications:

- Your development server does not need to be reachable from the public internet
  for certificate issuance.
- NAT and inbound port forwarding are not required for the ACME challenge.
- You need control of the domain's DNS, or a delegated validation name, so the
  TXT record can be published.
- DNS publication can be automated with `dnsPersistChallengePublisher`, or you
  can use `prepareDnsPersistCertificateRequest(...)` for a manual operator flow.
- The issued certificate is still for the requested domain, so your application
  DNS and routing still need to make sense for however you plan to serve the app
  after the certificate is issued.

This mode is the better fit for most development environments because the laptop
or workstation can stay private. It also avoids coupling certificate issuance to
home-router NAT, public Wi-Fi, or temporary firewall rules.

## Multi-Domain Support
Starting with `shelf_letsencrypt: 2.0.0`, support for multiple domains on the
same HTTPS port has been introduced. This enhancement allows
`shelf_letsencrypt` to manage certificate requests and automatically serve
multiple domains seamlessly.

This functionality is powered by the
[multi_domain_secure_server][pub_multi_domain_secure_server] package (developed
by [gmpassos][github_gmpassos]), specifically created for
`shelf_letsencrypt`. It enables a `SecureServerSocket` to handle different
`SecurityContext` instances (certificates) on the same listening port. For more
details, check out the source code on [GitHub][github_multi_domain_secure_server].

[pub_multi_domain_secure_server]: https://pub.dev/packages/multi_domain_secure_server
[github_multi_domain_secure_server]: https://github.com/gmpassos/multi_domain_secure_server

# Usage

Choose the challenge mechanism first, then wire `LetsEncrypt` for that flow.
Use `production: false` while testing so certificate requests go to the staging
ACME endpoint.

### http-01 server flow (default)

Use `http-01` when the ACME server can reach your app over public HTTP. This is
the default `LetsEncrypt` mode and is the simplest production setup when port 80
already routes to the server.

The example below starts HTTP and HTTPS servers, serves ACME challenge responses
from `/.well-known/acme-challenge/...`, and checks for certificate renewal:

```dart
import 'dart:io';

import 'package:cron/cron.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';

/// Start the example with a list of domains and the corresponding
/// email address for each domain admin:
/// ```dart
/// dart shelf_letsencrypt_example.dart \
///     www.domain.com:www2.domain.com \
///     info@domain.com:info2@domain.com
/// ```
void main(List<String> args) async {
  final domainNamesArg = args[0]; // Domains for the HTTPS certificate.
  final domainEmailsArg = args[1]; // The domains' email addresses.

  var certificatesDirectory = args.length > 2
      ? args[2] // Optional argument.
      : '/tmp/shelf-letsencrypt-example/'; // Default directory.

  final domains =
  Domain.fromDomainsNamesAndEmailsArgs(domainNamesArg, domainEmailsArg);

  // The certificate handler, storing at `certificatesDirectory`.
  final certificatesHandler =
  CertificatesHandlerIO(Directory(certificatesDirectory));

  // The Let's Encrypt integration tool in `staging` mode:
  final letsEncrypt = LetsEncrypt(
    certificatesHandler,
    production: false, // If `true` uses Let's Encrypt production API.
    port: 80,
    securePort: 443,
  );

  var servers = await _startServer(letsEncrypt, domains);

  await _startRenewalService(letsEncrypt, domains, servers.http, servers.https);
}

Future<({HttpServer http, HttpServer https})> _startServer(
    LetsEncrypt letsEncrypt, List<Domain> domains) async {
  // Build `shelf` Pipeline:
  final pipeline = const Pipeline().addMiddleware(logRequests());
  final handler = pipeline.addHandler(_processRequest);

  // Start the HTTP and HTTPS servers:
  final servers = await letsEncrypt.startServer(
    handler,
    domains,
    loadAllHandledDomains: true,
  );

  var server = servers.http; // HTTP Server.
  var serverSecure = servers.https; // HTTPS Server.

  // Enable gzip:
  server.autoCompress = true;
  serverSecure.autoCompress = true;

  print('Serving at http://${server.address.host}:${server.port}');
  print('Serving at https://${serverSecure.address.host}:${serverSecure.port}');

  return servers;
}

/// Check every hour if any of the certificates need to be renewed.
Future<void> _startRenewalService(LetsEncrypt letsEncrypt, List<Domain> domains,
    HttpServer server, HttpServer secureServer) async {
  Cron().schedule(
      Schedule(hours: '*/1'), // every hour
          () => refreshIfRequired(letsEncrypt, domains, server, secureServer));
}

Future<void> refreshIfRequired(
    LetsEncrypt letsEncrypt,
    List<Domain> domains,
    HttpServer server,
    HttpServer secureServer,
    ) async {
  print('-- Checking if any certificates need to be renewed');

  var restartRequired = false;

  for (final domain in domains) {
    final result =
    await letsEncrypt.checkCertificate(domain, requestCertificate: true);

    if (result.isOkRefreshed) {
      print('** Certificate for ${domain.name} was renewed');
      restartRequired = true;
    } else {
      print('-- Renewal not required');
    }
  }

  if (restartRequired) {
    // Restart the servers:
    await Future.wait<void>([server.close(), secureServer.close()]);
    await _startServer(letsEncrypt, domains);
    print('** Services restarted');
  }
}

Response _processRequest(Request request) =>
    Response.ok('Requested: ${request.requestedUri}');

```

### Automated dns-persist-01

Use automated `dns-persist-01` when your ACME CA supports the challenge and your
application can publish DNS TXT records through your DNS provider's API. In this
mode, `shelf_letsencrypt` prepares the ACME challenge and calls your
`dnsPersistChallengePublisher` callback with the TXT record that must exist
before validation continues.

```dart
final letsEncrypt = LetsEncrypt(
  certificatesHandler,
  production: false,
  challengeType: LetsEncryptChallengeType.dnsPersist,
  dnsPersistChallengePublisher: (domainName, proof) async {
    await publishTxtRecord(
      proof.txtRecordName,
      proof.txtRecordValue,
    );
  },
);
```

`publishTxtRecord` is application code that you provide. It should create or
update the TXT record through your DNS provider and return only when the record
is ready for validation.

### Manual dns-persist-01 API flow

Use the manual API when a human operator needs to publish the DNS TXT record.
Prepare the request first, show the TXT record to the operator, and only call
`complete()` once the record has been published:

```dart
final pending = await letsEncrypt.prepareDnsPersistCertificateRequest(
  const Domain(name: 'example.com', email: 'contact@example.com'),
);

print(pending.proof.txtRecordName);
print(pending.proof.txtRecordValue);
print(pending.proof.toBindString());

// Wait for the operator to publish the TXT record...
final ok = await pending.complete();
```

`complete()` validates the challenge, finalizes the order, fetches the
certificate chain, and stores it through the configured `CertificatesHandler`.

### CLI helper for dns-persist-01

The package ships a CLI for the same manual `dns-persist-01` flow:

```sh
dart run shelf_letsencrypt_dns_persist \
  --domain example.com \
  --email contact@example.com \
  --cert-dir ./certs
```

The CLI prepares the request, prints the TXT record details, prints a BIND-style
record line, and waits for confirmation before it asks the ACME server to
validate the challenge. It does not publish DNS records itself; publish the TXT
record with your DNS provider before pressing ENTER.

Useful options:

- `--cert-dir <path>` chooses the certificate directory used by
  `CertificatesHandlerIO`. Use the same directory your app will read from.
- `--acme-dir <url>` targets a custom ACME directory, such as a local Pebble
  server.
- `--production` uses the Let's Encrypt production endpoint.
- `--yes` skips the ENTER prompt. Use this only when automation has already
  published the required TXT record.

## Renewals

Each time you call `startServer`, it will check if any certificates need to
be renewed in the next 5 days (or if they are expired) and renew the
certificates.

This, however, isn't sufficient for any long-running service.

The example includes a renewal service that does a daily check to see if any
certificates need renewing.
If a cert needs to be renewed, it will renew it and then gracefully restart
the server with the new certs.

## Source

The official source code is [hosted @ GitHub][github_shelf_letsencrypt]:

- https://github.com/gmpassos/shelf_letsencrypt

[github_shelf_letsencrypt]: https://github.com/gmpassos/shelf_letsencrypt

# Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/gmpassos/shelf_letsencrypt/issues

# Contribution

Any help from the open-source community is always welcome and needed:

- Found an issue?
    - Please file a bug report with details.
- Want a feature?
    - Open a feature request with use cases.
- Are you using and liking the project?
    - Promote the project: create an article, do a post or make a donation.
- Are you a developer?
    - Fix a bug and send a pull request.
    - Implement a new feature.
    - Improve the Unit Tests.
- Have you already helped in any way?
    - **Many thanks from me, the contributors and everybody that uses this project!**

*If you donate 1 hour of your time, you can contribute a lot. Others will do
the same; just be part of it and start with your 1 hour.*

# TODO

- Add support for multiple HTTPS domains and certificates.
- Add helper to generate self-signed certificates (for local tests).

# Author

Graciliano M. Passos: [gmpassos@GitHub][github_gmpassos].
Brett Sutton: [bsutton@GitHub][github_bsutton].

[github_gmpassos]: https://github.com/gmpassos
[github_bsutton]: https://github.com/bsutton

## Sponsor

Don't be shy, show some love, and become our GitHub Sponsor ([gmpassos][sponsor_gmpassos], [bsutton][sponsor_bsutton]).
Your support means the world to us, and it keeps the code caffeinated! ☕✨

Thanks a million! 🚀😄

[sponsor_gmpassos]: https://github.com/sponsors/gmpassos
[sponsor_bsutton]: https://github.com/sponsors/bsutton

## License

[Apache License - Version 2.0][apache_license]

[apache_license]: https://www.apache.org/licenses/LICENSE-2.0.txt
