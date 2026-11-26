import 'package:flutter_test/flutter_test.dart';
import 'package:network_traffic_dashboard/models/alert.dart';
import 'package:network_traffic_dashboard/models/alerts_page.dart';
import 'package:network_traffic_dashboard/models/dashboard_stats.dart';
import 'package:network_traffic_dashboard/models/malware_analysis.dart';

void main() {
  test('correlation model distinguishes absent matching from empty result', () {
    final unavailable = MalwareCorrelations.fromJson({
      'findings': [],
      'event_relationships': [],
    });
    final completedWithoutMatches = MalwareCorrelations.fromJson({
      'findings': [],
      'event_relationships': [],
      'indicator_matches': [],
    });

    expect(unavailable.indicatorMatchingAvailable, isFalse);
    expect(unavailable.indicatorMatches, isEmpty);
    expect(completedWithoutMatches.indicatorMatchingAvailable, isTrue);
    expect(completedWithoutMatches.indicatorMatches, isEmpty);
  });

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
      'alert_origin': 'engine_alert',
      'detection_engine': 'suricata-eve-adapter',
      'evidence_refs': ['suricata/eve.json#line=12'],
      'related_events': [
        {'uid': 'C1', 'evidence_ref': 'zeek/conn.log#uid=C1'},
      ],
    });

    expect(alert.alertId, 'alert-000001');
    expect(alert.dstPort, 443);
    expect(alert.evidence, evidence);
    expect(alert.parsedTimestamp, isNotNull);
    expect(alert.severity, 'medium');
    expect(alert.confidence, 'high');
    expect(alert.alertOrigin, 'engine_alert');
    expect(alert.detectionEngine, 'suricata-eve-adapter');
    expect(alert.evidenceRefs, ['suricata/eve.json#line=12']);
    expect(alert.relatedEvents.single['uid'], 'C1');
    expect(alert.ruleName, 'HTTP signature');
    expect(alert.protocol, 'TCP');
    expect(alert.category, 'Potentially Bad Traffic');
    expect(alert.srcPort, 51515);
    expect(alert.matchesSearch('hTtP sIgNaTuRe'), isTrue);
    expect(alert.matchesSearch('10.11.26.183'), isTrue);
    expect(alert.matchesSearch('example.test'), isTrue);
    expect(alert.matchesSearch('flow_id'), isTrue);
    expect(alert.matchesSearch('8899'), isTrue);
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

  test('DashboardStats marks missing metric maps as unavailable', () {
    final stats = DashboardStats.fromJson({
      'stats': {'total_alerts': 3},
    });
    expect(stats.totalAlertsAvailable, isTrue);
    expect(stats.severityCountsAvailable, isFalse);
    expect(stats.sourceCountsAvailable, isFalse);
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

  test(
    'MalwareAnalysis and telemetry preserve classification and evidence',
    () {
      final analysis = MalwareAnalysis.fromJson({
        'analysis_id': 'fixture-case',
        'analysis_status': 'static_complete',
        'sample': {
          'sha256': List.filled(64, 'a').join(),
          'hash_status': 'verified',
          'original_file_name': 'fixture.exe',
          'size_bytes': 4,
          'detected_type': 'PE candidate',
        },
        'provenance': {'evidence_classification': 'synthetic_fixture'},
        'static_analysis': {
          'status': 'complete',
          'results': {
            'pe': {'format': 'PE32'},
          },
        },
        'dynamic_analysis': null,
        'observations': {'telemetry_events': []},
        'related_detection_findings': [],
        'assessment': {
          'limitations': ['Not executed'],
        },
      });
      expect(analysis.sha256, List.filled(64, 'a').join());
      expect(analysis.classification, 'synthetic_fixture');
      expect(analysis.limitations, ['Not executed']);
      final event = MalwareEvent.fromJson({
        'event_type': 'network_connection',
        'source_tool': 'Sandbox',
        'classification': 'synthetic_fixture',
        'data': {'dst_port': 443},
        'evidence_refs': ['sandbox/events.json#record=1'],
      });
      expect(event.data['dst_port'], 443);
      expect(event.evidenceRefs, ['sandbox/events.json#record=1']);
    },
  );
}
