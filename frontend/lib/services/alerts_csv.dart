import '../models/alert.dart';

const alertCsvHeaders = <String>[
  'alert_id',
  'timestamp_utc',
  'rule_id',
  'rule_name',
  'title',
  'severity',
  'confidence',
  'source_tool',
  'alert_origin',
  'detection_engine',
  'src_ip',
  'src_port',
  'dst_ip',
  'dst_port',
  'protocol',
  'category',
  'hostname',
  'url',
  'uid',
  'evidence_refs',
];

String buildAlertsCsv(List<Alert> alerts) {
  final rows = <List<String>>[alertCsvHeaders];
  for (final alert in alerts) {
    rows.add([
      alert.alertId,
      alert.timestampUtc,
      alert.ruleId,
      alert.ruleName,
      alert.title,
      alert.severity,
      alert.confidence,
      alert.sourceTool,
      alert.alertOrigin,
      alert.detectionEngine,
      alert.srcIp,
      alert.srcPort?.toString() ?? '',
      alert.dstIp,
      alert.dstPort?.toString() ?? '',
      alert.protocol,
      alert.category,
      alert.hostname,
      alert.url,
      alert.uid,
      alert.evidenceRefs.join(' | '),
    ]);
  }
  return '${rows.map((row) => row.map(_escapeCsv).join(',')).join('\r\n')}\r\n';
}

String _escapeCsv(String input) {
  final safe = RegExp(r'^\s*[=+@-]').hasMatch(input) ? "'$input" : input;
  return '"${safe.replaceAll('"', '""')}"';
}
