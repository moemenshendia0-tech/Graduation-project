import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:network_traffic_dashboard/services/api_client.dart';

void main() {
  test(
    'client calls health, filtered alert list, detail, and stats routes',
    () async {
      final paths = <String>[];
      final client = ApiClient(
        baseUrl: 'http://example.test/',
        client: MockClient((request) async {
          paths.add(request.url.path);
          if (request.url.path == '/health') {
            return http.Response(
              jsonEncode({'status': 'ok', 'alerts_file_available': true}),
              200,
            );
          }
          if (request.url.path == '/api/alerts') {
            expect(request.url.queryParameters['severity'], 'high');
            expect(request.url.queryParameters['source_tool'], 'Suricata');
            expect(request.url.queryParameters['q'], 'POST');
            return http.Response(
              jsonEncode({
                'alerts': [],
                'pagination': {
                  'page': 1,
                  'page_size': 20,
                  'total': 0,
                  'total_pages': 0,
                },
              }),
              200,
            );
          }
          if (request.url.path == '/api/alerts/alert-000001') {
            return http.Response(jsonEncode({'alert': _alertJson()}), 200);
          }
          if (request.url.path == '/api/stats') {
            return http.Response(
              jsonEncode({
                'stats': {
                  'total_alerts': 129,
                  'severity_counts': {'high': 1, 'medium': 58, 'low': 70},
                  'source_counts': {'Suricata': 127, 'Zeek': 2},
                  'rule_counts': {'NET-005': 2},
                },
              }),
              200,
            );
          }
          return http.Response('{}', 404);
        }),
      );

      expect((await client.getHealth()).isAvailable, isTrue);
      await client.getAlerts(
        severity: 'high',
        sourceTool: 'Suricata',
        query: 'POST',
      );
      expect((await client.getAlert('alert-000001')).sourceTool, 'Suricata');
      expect((await client.getStats()).totalAlerts, 129);
      expect(paths, [
        '/health',
        '/api/alerts',
        '/api/alerts/alert-000001',
        '/api/stats',
      ]);
      client.close();
    },
  );

  test('API errors retain status and backend error message', () async {
    final client = ApiClient(
      client: MockClient(
        (_) async => http.Response(
          jsonEncode({
            'error': {
              'code': 'alerts_file_unavailable',
              'message': 'Alerts missing',
            },
          }),
          503,
        ),
      ),
    );

    await expectLater(
      client.getStats(),
      throwsA(
        isA<ApiException>()
            .having((error) => error.statusCode, 'statusCode', 503)
            .having((error) => error.code, 'code', 'alerts_file_unavailable')
            .having((error) => error.message, 'message', 'Alerts missing'),
      ),
    );
    client.close();
  });

  test(
    'MalwareBazaar lookup normalizes the hash and parses metadata',
    () async {
      final paths = <String>[];
      final sha256 = List.filled(64, 'a').join();
      final client = ApiClient(
        baseUrl: 'http://example.test',
        client: MockClient((request) async {
          paths.add(request.url.path);
          if (request.url.path == '/api/malware/intel/$sha256') {
            return http.Response(
              jsonEncode({
                'intelligence': {
                  'provider': 'MalwareBazaar',
                  'lookup_time': '2026-11-25T12:00:00Z',
                  'queried_hash': sha256,
                  'queried_algorithm': 'sha256',
                  'api_status': 'ok',
                  'match_status': 'found',
                  'identifiers': {'sha256_hash': sha256},
                  'metadata': {
                    'file_name': 'fixture.bin',
                    'tags': ['fixture'],
                  },
                },
              }),
              200,
            );
          }
          if (request.url.path == '/api/malware/samples/$sha256') {
            return http.Response(
              jsonEncode({
                'sha256': sha256,
                'analyses': [
                  {
                    'analysis_id': 'case-fixture',
                    'hash_status': 'verified',
                    'sample': {'original_file_name': 'fixture.bin'},
                  },
                ],
              }),
              200,
            );
          }
          return http.Response('{}', 404);
        }),
      );

      final intel = await client.lookupMalwareHash(' ${sha256.toUpperCase()} ');
      final local = await client.getMalwareSample(' ${sha256.toUpperCase()} ');

      expect(intel.matchStatus, 'found');
      expect(intel.metadata['file_name'], 'fixture.bin');
      expect(intel.metadata['tags'], ['fixture']);
      expect(local.analyses.single.analysisId, 'case-fixture');
      expect(paths, [
        '/api/malware/intel/$sha256',
        '/api/malware/samples/$sha256',
      ]);
      client.close();
    },
  );

  test('invalid MalwareBazaar hashes are rejected before a request', () async {
    var requests = 0;
    final client = ApiClient(
      client: MockClient((_) async {
        requests++;
        return http.Response('{}', 200);
      }),
    );

    await expectLater(
      client.lookupMalwareHash('not-a-hash'),
      throwsA(
        isA<ApiException>().having(
          (error) => error.code,
          'code',
          'invalid_hash',
        ),
      ),
    );
    expect(requests, 0);
    client.close();
  });
}

Map<String, Object?> _alertJson() => {
  'alert_id': 'alert-000001',
  'timestamp_utc': '2024-11-26T04:49:38.458138+00:00',
  'rule_id': 'SURICATA-2013926',
  'severity': 'medium',
  'confidence': 'high',
  'title': 'HTTP traffic on port 443',
  'src_ip': '10.11.26.183',
  'dst_ip': '194.180.191.64',
  'dst_port': 443,
  'uid': '',
  'correlation': '',
  'related_rule_id': '',
  'related_fuid': '',
  'related_uid': '',
  'evidence': '{"signature":"sample"}',
  'source_tool': 'Suricata',
};
