import 'package:flutter_test/flutter_test.dart';
import 'package:network_traffic_dashboard/models/alert.dart';
import 'package:network_traffic_dashboard/models/alerts_page.dart';
import 'package:network_traffic_dashboard/models/dashboard_stats.dart';

void main() {
  test('Alert parses the unified schema and preserves evidence as a string', () {
    const evidence =
        '{"source_tool":"Suricata","signature":"HTTP signature","protocol":"TCP","category":"Potentially Bad Traffic","http_url":"http://example.test/path","hostname":"example.test","src_port":51515,"flow_id":8899}';
    final alert = Alert.fromJson({
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
      'evidence': evidence,
      'source_tool': 'Suricata',
    });

    expect(alert.alertId, 'alert-000001');
    expect(alert.dstPort, 443);
    expect(alert.evidence, evidence);
    expect(alert.parsedTimestamp, isNotNull);
    expect(alert.severity, 'medium');
    expect(alert.confidence, 'high');
    expect(alert.ruleName, 'HTTP signature');
    expect(alert.protocol, 'TCP');
    expect(alert.category, 'Potentially Bad Traffic');
    expect(alert.srcPort, 51515);
    expect(alert.matchesSearch('hTtP sIgNaTuRe'), isTrue);
    expect(alert.matchesSearch('10.11.26.183'), isTrue);
    expect(alert.matchesSearch('example.test'), isTrue);
    expect(alert.matchesSearch('flow_id'), isFalse);
    expect(alert.matchesSearch('8899'), isFalse);
  });

  test('AlertsPage parses the list envelope and pagination', () {
    final page = AlertsPage.fromJson({
      'alerts': [
        {
          'alert_id': 'alert-000001',
          'timestamp_utc': '',
          'rule_id': 'NET-005',
          'severity': 'low',
          'confidence': 'low',
          'title': 'Repeated DNS query candidate',
          'src_ip': '10.0.0.1',
          'dst_ip': '',
          'dst_port': null,
          'uid': '',
          'correlation': '',
          'related_rule_id': '',
          'related_fuid': '',
          'related_uid': '',
          'evidence': 'query=sample.test; count=20',
          'source_tool': 'Zeek',
        },
      ],
      'pagination': {'page': 1, 'page_size': 20, 'total': 1, 'total_pages': 1},
    });

    expect(page.alerts, hasLength(1));
    expect(page.pagination.pageSize, 20);
    expect(page.pagination.totalPages, 1);
    expect(page.alerts.single.matchesSearch('wpad.example.test'), isFalse);
  });

  test('DashboardStats parses real summary count maps', () {
    final stats = DashboardStats.fromJson({
      'stats': {
        'total_alerts': 129,
        'severity_counts': {'high': 1, 'medium': 58, 'low': 70},
        'source_counts': {'Suricata': 127, 'Zeek': 2},
        'rule_counts': {'NET-005': 2},
      },
    });

    expect(stats.totalAlerts, 129);
    expect(stats.severityCount('HIGH'), 1);
    expect(stats.severityCount('medium'), 58);
    expect(stats.sourceCounts['Suricata'], 127);
    expect(stats.ruleCounts['NET-005'], 2);
  });
}
