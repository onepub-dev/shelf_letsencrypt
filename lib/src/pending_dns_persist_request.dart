import 'package:acme_client/acme_client.dart';

import 'letsencrypt.dart';

/// A prepared `dns-persist-01` request waiting for the caller to publish the
/// TXT record before certificate issuance can continue.
///
/// Typical flow:
///
/// 1. Call [LetsEncrypt.prepareDnsPersistCertificateRequest].
/// 2. Show [proof] to an operator or publish it through your DNS automation.
/// 3. Once the TXT record is live, call [complete].
class PendingDnsPersistRequest {
  PendingDnsPersistRequest.internal({
    required this.domainName,
    required this.proof,
    required this.complete,
  });

  /// The domain being validated.
  final String domainName;

  /// The persistent TXT record the user must publish.
  final DnsPersistChallengeProof proof;

  /// Completes validation, finalizes the order, and stores the certificate.
  ///
  /// Call this only after the TXT record from [proof] has been published.
  final Future<bool> Function() complete;
}
