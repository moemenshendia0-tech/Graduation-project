import 'package:flutter_test/flutter_test.dart';
import 'package:network_traffic_dashboard/models/alert.dart';
import 'package:network_traffic_dashboard/services/alerts_csv.dart';

void main() {
  test('CSV includes useful identifiers and safely quotes evidence refs', () {
    final alert = Alert.fromJson({
      'alert_id': 'a-1',
      'timestamp_utc': '2026-11-22T18:00:00Z',
      'rule_id': 'NET-009',
      'rule_name': 'SMB, enumeration',
      'severity': 'medium',
      'confidence': 'medium',
      'title': 'Candidate "share"\nobserved',
      'source_tool': 'ProjectDetector',
      'evidence_refs': ['zeek/dce_rpc.log#line=22', 'zeek/notice.log#line=4'],
    });

    final csv = buildAlertsCsv([alert]);
    expect(csv, contains('"alert_id"'));
    expect(csv, contains('"a-1"'));
    expect(csv, contains('"SMB, enumeration"'));
    expect(csv, contains('"Candidate ""share""\nobserved"'));
    expect(csv, contains('zeek/dce_rpc.log#line=22 | zeek/notice.log#line=4'));
    expect(csv.toLowerCase(), isNot(contains('evidence,"')));
  });

  test('CSV prevents spreadsheet formula interpretation', () {
    final alert = Alert.fromJson({
      'alert_id': '=HYPERLINK("bad")',
      'rule_id': 'NET-001',
      'title': 'safe',
      'source_tool': 'ProjectDetector',
    });
    expect(buildAlertsCsv([alert]), contains("'=HYPERLINK("));
  });

  test('CSV preserves the supplied sorted order and all rows', () {
    final alerts = [
      Alert.fromJson({'alert_id': 'newest', 'timestamp_utc': '2026-02-02Z'}),
      Alert.fromJson({'alert_id': 'older', 'timestamp_utc': '2026-02-01Z'}),
    ];
    final csv = buildAlertsCsv(alerts);
    expect(csv.indexOf('newest'), lessThan(csv.indexOf('older')));
    expect('"older"'.allMatches(csv).length, 1);
  });
}
