import 'dart:convert';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:network_traffic_dashboard/screens/dashboard_screen.dart';
import 'package:network_traffic_dashboard/services/api_client.dart';

void main() {
  testWidgets('missing API count maps render unavailable instead of zero', (
    tester,
  ) async {
    final client = ApiClient(
      client: MockClient((request) async {
        if (request.url.path == '/health') {
          return http.Response(
            jsonEncode({'status': 'ok', 'alerts_file_available': true}),
            200,
          );
        }
        if (request.url.path == '/api/stats') {
          return http.Response(
            jsonEncode({
              'stats': {'total_alerts': 3},
            }),
            200,
          );
        }
        if (request.url.path == '/api/alerts') {
          return http.Response(
            jsonEncode({
              'alerts': [],
              'pagination': {
                'page': 1,
                'page_size': 500,
                'total': 0,
                'total_pages': 0,
              },
            }),
            200,
          );
        }
        return http.Response('{}', 404);
      }),
    );
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: client)),
    );
    await tester.pumpAndSettle();
    expect(find.text('—'), findsNWidgets(6));
    expect(
      find.text('Source counts unavailable · severity counts unavailable'),
      findsOneWidget,
    );
    await _scrollTo(tester, find.text('Severity distribution'));
    expect(
      find.text('Severity counts are unavailable in the API response.'),
      findsOneWidget,
    );
    expect(
      find.text('Source counts are unavailable in the API response.'),
      findsOneWidget,
    );
    client.close();
  });
  testWidgets('dashboard shows dataset totals and candidate alert table', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    expect(find.text('SOC Dashboard'), findsOneWidget);
    expect(find.text('API connected'), findsOneWidget);
    expect(find.text('Total alerts'), findsOneWidget);
    expect(find.textContaining('not live monitoring'), findsOneWidget);
    expect(find.text('129'), findsOneWidget);
    expect(find.text('58'), findsOneWidget);
    expect(find.text('70'), findsOneWidget);
    await _scrollTo(tester, find.text('Alert queue'));
    await _scrollTo(tester, find.text('Candidate HTTP alert'));
    expect(find.text('Alert queue'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
  });

  testWidgets('responsive navigation opens the existing intelligence screen', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('open-navigation')), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('open-navigation')));
    await tester.pumpAndSettle();
    expect(find.text('Dashboard'), findsOneWidget);
    expect(find.text('Threat intelligence'), findsOneWidget);
    expect(find.text('Incidents'), findsNothing);

    await tester.tap(find.byKey(const ValueKey('nav-threat-intelligence')));
    await tester.pumpAndSettle();
    expect(find.text('Malware Intelligence'), findsOneWidget);
    expect(find.byKey(const ValueKey('malware-hash-field')), findsOneWidget);
  });

  testWidgets(
    'tablet alert queue switches to cards instead of clipping columns',
    (tester) async {
      tester.view.physicalSize = const Size(768, 1024);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        MaterialApp(home: DashboardScreen(apiClient: _client())),
      );
      await tester.pumpAndSettle();
      await _scrollTo(
        tester,
        find.byKey(const ValueKey('alert-row-alert-000001')),
      );
      expect(
        find.byKey(const ValueKey('alert-row-alert-000001')),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );
  testWidgets(
    'desktop shell shows only real destinations and historical context',
    (tester) async {
      tester.view.physicalSize = const Size(1440, 960);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        MaterialApp(home: DashboardScreen(apiClient: _client())),
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('nav-dashboard')), findsOneWidget);
      expect(
        find.byKey(const ValueKey('nav-threat-intelligence')),
        findsOneWidget,
      );
      expect(find.text('Incidents'), findsNothing);
      expect(find.text('Historical analysis'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('desktop alert selection populates the investigation inspector', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1440, 960);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    expect(
      find.byKey(const ValueKey('investigation-inspector')),
      findsOneWidget,
    );
    await _scrollTo(tester, find.text('SMB enumeration candidate'));
    await tester.tap(find.text('SMB enumeration candidate').first);
    await tester.pumpAndSettle();

    expect(find.text('Investigation focus'), findsOneWidget);
    expect(
      find.descendant(
        of: find.byKey(const ValueKey('investigation-inspector')),
        matching: find.text('zeek/dce_rpc.log#line=22'),
      ),
      findsOneWidget,
    );
    expect(
      find.byKey(const ValueKey('open-inspector-details')),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });
  testWidgets('rule ID filter narrows to the selected ProjectDetector rule', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 2200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const ValueKey('rule-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('rule-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('NET-009').last);
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.text('Alert queue'));
    expect(find.text('SMB enumeration candidate'), findsWidgets);
    expect(find.text('NET-009').last, findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsNothing);
  });

  testWidgets('CSV export uses the current filtered result set', (
    tester,
  ) async {
    String? csv;
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardScreen(
          apiClient: _client(),
          onCsvExport: (value) => csv = value,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('alerts-search')));
    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'NET-005',
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('export-alerts-csv')));
    expect(csv, isNotNull);
    expect(csv, contains('alert-000002'));
    expect(csv, isNot(contains('alert-000001')));
  });

  testWidgets('CSV export contains all currently filtered alerts', (
    tester,
  ) async {
    String? exported;
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardScreen(
          apiClient: _client(),
          onCsvExport: (csv) => exported = csv,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('alerts-search')));
    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'NET-005',
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('export-alerts-csv')));
    await tester.tap(find.byKey(const ValueKey('export-alerts-csv')));
    expect(exported, isNotNull);
    expect(exported, contains('alert-000002'));
    expect(exported, isNot(contains('alert-000001')));
  });

  testWidgets('CSV export contains matching results across all pages', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    String? csv;
    final rows = List.generate(25, (i) => _manyAlert(i));
    final client = ApiClient(
      client: MockClient((request) async {
        if (request.url.path == '/health') {
          return http.Response(
            jsonEncode({'status': 'ok', 'alerts_file_available': true}),
            200,
          );
        }
        if (request.url.path == '/api/stats') {
          return http.Response(
            jsonEncode({
              'stats': {
                'total_alerts': 25,
                'severity_counts': {'low': 25},
                'source_counts': {'Suricata': 25},
                'rule_counts': {'TEST-001': 25},
              },
            }),
            200,
          );
        }
        if (request.url.path == '/api/alerts') {
          final page = int.parse(request.url.queryParameters['page'] ?? '1');
          final start = (page - 1) * 20;
          final selected = rows.skip(start).take(20).toList();
          return http.Response(
            jsonEncode({
              'alerts': selected,
              'pagination': {
                'page': page,
                'page_size': 20,
                'total': 25,
                'total_pages': 2,
              },
            }),
            200,
          );
        }
        return http.Response('{}', 404);
      }),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: DashboardScreen(
          apiClient: client,
          onCsvExport: (value) => csv = value,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const ValueKey('export-alerts-csv')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('export-alerts-csv')));
    expect(csv, contains('fixture-24'));
    expect(RegExp(r'fixture-\d+').allMatches(csv!).length, 25);
    client.close();
  });

  testWidgets('alert row opens details from the detail endpoint', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.text('Candidate HTTP alert'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Candidate HTTP alert'));
    await tester.pumpAndSettle();

    expect(find.text('Alert details'), findsOneWidget);
    expect(find.text('Confidence: high'), findsWidgets);
    expect(find.text('Evidence'), findsOneWidget);
    expect(
      find.text('Candidate alert for investigation; not proof of compromise.'),
      findsOneWidget,
    );
  });

  testWidgets(
    'severity sorting promotes high severity without changing meaning',
    (tester) async {
      final client = _client();
      await tester.pumpWidget(
        MaterialApp(home: DashboardScreen(apiClient: client)),
      );
      await tester.pumpAndSettle();
      await _scrollTo(tester, find.byKey(const ValueKey('sort-filter')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('sort-filter')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Severity (high first)'));
      await tester.pumpAndSettle();

      final highTop = tester
          .getTopLeft(find.text('High severity candidate'))
          .dy;
      final mediumTop = tester.getTopLeft(find.text('Candidate HTTP alert')).dy;
      expect(highTop, lessThan(mediumTop));
    },
  );

  testWidgets('search with no matches displays the empty state', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('alerts-search')));
    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'no-match',
    );
    await tester.pump(const Duration(milliseconds: 400));
    await tester.pumpAndSettle();

    expect(
      find.text('No alerts match the current search and filters.'),
      findsOneWidget,
    );
  });

  testWidgets('search is immediate, field-based, and makes no API request', (
    tester,
  ) async {
    var alertsRequests = 0;
    final client = _client(onAlertsRequest: () => alertsRequests++);
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: client)),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('alerts-search')));
    expect(alertsRequests, 1);

    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'nEt-005',
    );
    await tester.pump();
    expect(find.text('Repeated DNS query candidate'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsNothing);
    expect(find.text('1 matching of 129 total alerts'), findsOneWidget);
    expect(alertsRequests, 1);

    await tester.ensureVisible(find.byKey(const ValueKey('clear-search')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('clear-search')));
    await tester.pump();
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
    expect(alertsRequests, 1);
  });

  testWidgets('search and severity/source filters combine and clear together', (
    tester,
  ) async {
    final client = _client();
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: client)),
    );
    await tester.pumpAndSettle();
    await _scrollTo(tester, find.byKey(const ValueKey('alerts-search')));
    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'suricata',
    );
    await tester.pump();
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
    expect(find.text('High severity candidate'), findsOneWidget);

    await _scrollTo(tester, find.byKey(const ValueKey('severity-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('severity-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('High').last);
    await tester.pump();
    expect(find.text('High severity candidate'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsNothing);

    await _scrollTo(tester, find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Zeek').last);
    await tester.pump();
    expect(
      find.text('No alerts match the current search and filters.'),
      findsOneWidget,
    );

    await _scrollTo(tester, find.byKey(const ValueKey('clear-all-filters')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('clear-all-filters')));
    await tester.pump();
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
    expect(find.text('High severity candidate'), findsOneWidget);

    await _scrollTo(tester, find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Project detector').last);
    await tester.pump();
    expect(find.text('SMB enumeration candidate'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsNothing);
  });

  testWidgets('backend unavailable is clearly reported', (tester) async {
    final client = ApiClient(
      client: MockClient((request) async {
        if (request.url.path == '/health') {
          return http.Response(
            jsonEncode({'status': 'degraded', 'alerts_file_available': false}),
            200,
          );
        }
        return http.Response('{}', 503);
      }),
    );
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: client)),
    );
    await tester.pumpAndSettle();

    expect(find.text('Backend unavailable'), findsOneWidget);
    expect(find.textContaining('alerts file is unavailable'), findsOneWidget);
    client.close();
  });
}

Future<void> _scrollTo(WidgetTester tester, Finder target) async {
  if (target.evaluate().isNotEmpty) {
    await tester.scrollUntilVisible(
      target.first,
      250,
      scrollable: find.byType(Scrollable).first,
    );
    return;
  }
  await tester.scrollUntilVisible(
    target,
    250,
    scrollable: find.byType(Scrollable).first,
  );
}

ApiClient _client({VoidCallback? onAlertsRequest}) => ApiClient(
  client: MockClient((request) async {
    if (request.url.path == '/health') {
      return http.Response(
        jsonEncode({'status': 'ok', 'alerts_file_available': true}),
        200,
      );
    }
    if (request.url.path == '/api/stats') {
      return http.Response(
        jsonEncode({
          'stats': {
            'total_alerts': 129,
            'severity_counts': {'high': 1, 'medium': 58, 'low': 70},
            'source_counts': {'Suricata': 127, 'Zeek': 2},
            'rule_counts': {'NET-005': 2, 'SURICATA-2013926': 1, 'NET-009': 1},
          },
        }),
        200,
      );
    }
    if (request.url.path == '/api/alerts/alert-000001') {
      return http.Response(jsonEncode({'alert': _alert()}), 200);
    }
    if (request.url.path == '/api/alerts') {
      onAlertsRequest?.call();
      final rows = [_alert(), _zeekAlert(), _highAlert(), _projectFinding()];
      return http.Response(
        jsonEncode({
          'alerts': rows,
          'pagination': {
            'page': 1,
            'page_size': 500,
            'total': 129,
            'total_pages': 1,
          },
        }),
        200,
      );
    }
    return http.Response('{}', 404);
  }),
);

Map<String, Object?> _alert() => {
  'alert_id': 'alert-000001',
  'timestamp_utc': '2024-11-26T04:49:38.458138+00:00',
  'rule_id': 'SURICATA-2013926',
  'severity': 'medium',
  'confidence': 'high',
  'title': 'Candidate HTTP alert',
  'src_ip': '10.11.26.183',
  'dst_ip': '194.180.191.64',
  'dst_port': 443,
  'uid': '',
  'correlation': '',
  'related_rule_id': '',
  'related_fuid': '',
  'related_uid': '',
  'src_port': 51515,
  'evidence': '{"signature":"HTTP signature","category":"Potentially Bad Traffic","protocol":"TCP","http_url":"http://example.test/path","hostname":"example.test","src_port":51515,"flow_id":8899}',
  'source_tool': 'Suricata',
};

Map<String, Object?> _zeekAlert() => {
  'alert_id': 'alert-000002',
  'timestamp_utc': '2024-11-26T04:50:00Z',
  'rule_id': 'NET-005',
  'severity': 'low',
  'confidence': 'low',
  'title': 'Repeated DNS query candidate',
  'src_ip': '10.11.26.184',
  'dst_ip': '',
  'dst_port': '',
  'uid': '',
  'correlation': '',
  'related_rule_id': '',
  'related_fuid': '',
  'related_uid': '',
  'evidence': 'query=wpad.example.test; count=24',
  'source_tool': 'Zeek',
};

Map<String, Object?> _highAlert() => {
  'alert_id': 'alert-000003',
  'timestamp_utc': '2024-11-26T04:48:00Z',
  'rule_id': 'SURICATA-900001',
  'severity': 'high',
  'confidence': 'medium',
  'title': 'High severity candidate',
  'src_ip': '10.11.26.185',
  'dst_ip': '192.0.2.10',
  'dst_port': 443,
  'uid': '',
  'correlation': '',
  'related_rule_id': '',
  'related_fuid': '',
  'related_uid': '',
  'evidence': '{"signature":"Unusual TLS activity","protocol":"TCP","category":"Policy"}',
  'source_tool': 'Suricata',
};

Map<String, Object?> _projectFinding() => {
  'alert_id': 'alert-000004',
  'timestamp_utc': '2024-11-26T04:51:00Z',
  'rule_id': 'NET-009',
  'severity': 'medium',
  'confidence': 'medium',
  'title': 'SMB enumeration candidate',
  'src_ip': '10.11.26.186',
  'dst_ip': '10.11.26.187',
  'dst_port': 445,
  'uid': 'SMB1',
  'evidence': '{"rpc_operations":["NetrShareEnum"]}',
  'source_tool': 'ProjectDetector',
  'alert_origin': 'project_generated',
  'detection_engine': 'project-network-findings',
  'evidence_refs': ['zeek/dce_rpc.log#line=22'],
  'related_events': [
    {'uid': 'SMB1', 'evidence_ref': 'zeek/dce_rpc.log#line=22'},
  ],
};

Map<String, Object?> _manyAlert(int index) => {
  'alert_id': 'fixture-$index',
  'timestamp_utc':
      '2026-11-22T18:${(index % 60).toString().padLeft(2, '0')}:00Z',
  'rule_id': 'TEST-001',
  'severity': 'low',
  'confidence': 'unknown',
  'title': 'Synthetic test row $index',
  'source_tool': 'Suricata',
};
