import 'dart:convert';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:network_traffic_dashboard/screens/dashboard_screen.dart';
import 'package:network_traffic_dashboard/services/api_client.dart';

void main() {
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
    expect(find.text('129'), findsOneWidget);
    expect(find.text('58'), findsNWidgets(2));
    expect(find.text('70'), findsNWidgets(2));
    expect(find.text('Alert queue'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
  });

  testWidgets('alert row opens details from the detail endpoint', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(home: DashboardScreen(apiClient: _client())),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Candidate HTTP alert'));
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
      await tester.ensureVisible(find.byKey(const ValueKey('sort-filter')));
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
    await tester.enterText(
      find.byKey(const ValueKey('alerts-search')),
      'suricata',
    );
    await tester.pump();
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
    expect(find.text('High severity candidate'), findsOneWidget);

    await tester.ensureVisible(find.byKey(const ValueKey('severity-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('severity-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('High').last);
    await tester.pump();
    expect(find.text('High severity candidate'), findsOneWidget);
    expect(find.text('Candidate HTTP alert'), findsNothing);

    await tester.ensureVisible(find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('source-filter')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Zeek').last);
    await tester.pump();
    expect(
      find.text('No alerts match the current search and filters.'),
      findsOneWidget,
    );

    await tester.ensureVisible(find.byKey(const ValueKey('clear-all-filters')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('clear-all-filters')));
    await tester.pump();
    expect(find.text('Candidate HTTP alert'), findsOneWidget);
    expect(find.text('High severity candidate'), findsOneWidget);
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
            'rule_counts': {'NET-005': 2},
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
      final rows = [_alert(), _zeekAlert(), _highAlert()];
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
