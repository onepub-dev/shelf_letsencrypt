// Integration-style test setup keeps long environment names and URLs intact.
// ignore_for_file: lines_longer_than_80_chars

import 'dart:convert';
import 'dart:io';

import 'package:acme_client/acme_client.dart' show AcmeConnection;
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:path/path.dart' as pack_path;
import 'package:shelf_letsencrypt/shelf_letsencrypt.dart';
import 'package:test/test.dart';

const _pebbleEnabledEnv = 'ACME_PEBBLE_ENABLE_TESTS';
const _pebbleBaseUrlEnv = 'ACME_PEBBLE_BASE_URL';
const _pebbleManagementUrlEnv = 'ACME_PEBBLE_MANAGEMENT_URL';
const _pebbleIdentifierEnv = 'ACME_PEBBLE_IDENTIFIER';
const _pebbleTrustedRootEnv = 'ACME_PEBBLE_TRUSTED_ROOT';

void main() {
  final enabled = Platform.environment[_pebbleEnabledEnv] == 'true';
  final baseUrl =
      Platform.environment[_pebbleBaseUrlEnv] ?? 'https://localhost:14000/dir';
  final managementUrl =
      Platform.environment[_pebbleManagementUrlEnv] ?? 'http://localhost:8055';
  final identifier =
      Platform.environment[_pebbleIdentifierEnv] ?? 'example.com';
  final trustedRootPath = Platform.environment[_pebbleTrustedRootEnv];

  late Directory tmpDir;

  setUp(() {
    tmpDir = Directory.systemTemp.createTempSync(
      'shelf-letsencrypt-pebble-',
    );
  });

  tearDown(() {
    if (tmpDir.existsSync()) {
      tmpDir.deleteSync(recursive: true);
    }
  });

  test(
    'Pebble dns-persist-01 end-to-end',
    () async {
      final certificatesHandler = CertificatesHandlerIO(
        Directory(pack_path.join(tmpDir.path, 'certs')),
      );
      final letsEncrypt = LetsEncrypt(
        certificatesHandler,
        selfTest: false,
        challengeType: LetsEncryptChallengeType.dnsPersist,
        acmeDirectoryUrl: baseUrl,
        acmeConnection: AcmeConnection(
          baseUrl: baseUrl,
          dio: _buildPebbleDio(trustedRootPath),
        ),
        dnsPersistChallengePublisher: (domainName, proof) async {
          expect(domainName, identifier);
          await _publishTxtRecord(
            managementUrl,
            proof.txtRecordName,
            proof.txtRecordValue,
          );
        },
      );

      final ok = await letsEncrypt.requestCertificate(
        Domain(name: identifier, email: 'contact@$identifier'),
      );

      expect(ok, isTrue);
      final fullChainFile = certificatesHandler.fileDomainFullChainPEM(
        identifier,
      );
      expect(fullChainFile.existsSync(), isTrue);
      expect(fullChainFile.readAsStringSync(), contains('BEGIN CERTIFICATE'));
    },
    skip: enabled
        ? false
        : 'Set $_pebbleEnabledEnv=true to run against the local Pebble harness.',
  );
}

Future<void> _publishTxtRecord(
  String managementUrl,
  String host,
  String value,
) async {
  final managementClient = Dio();
  await managementClient.post<void>(
    '$managementUrl/set-txt',
    data: json.encode({'host': host, 'value': value}),
    options: Options(headers: {'Content-Type': 'application/json'}),
  );
}

Dio _buildPebbleDio(String? trustedRootPath) => Dio()
  ..httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () {
      final context = SecurityContext();
      if (trustedRootPath != null && trustedRootPath.isNotEmpty) {
        context.setTrustedCertificates(trustedRootPath);
      }
      final client = HttpClient(context: context);
      if (trustedRootPath == null || trustedRootPath.isEmpty) {
        client.badCertificateCallback = (certificate, host, port) => true;
      }
      return client;
    },
  );
