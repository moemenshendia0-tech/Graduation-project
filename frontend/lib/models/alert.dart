import 'dart:convert';

class Alert {
  const Alert({
    required this.alertId,
    required this.timestampUtc,
    required this.ruleId,
    required this.ruleName,
    required this.severity,
    required this.confidence,
    required this.title,
    required this.srcIp,
    required this.srcPort,
    required this.dstIp,
    required this.dstPort,
    required this.protocol,
    required this.category,
    required this.hostname,
    required this.url,
    required this.uid,
    required this.correlation,
    required this.relatedRuleId,
    required this.relatedFuid,
    required this.relatedUid,
    required this.evidence,
    required this.sourceTool,
    required this.alertOrigin,
    required this.detectionEngine,
    required this.evidenceRefs,
    required this.relatedEvents,
  });

  final String alertId, timestampUtc, ruleId, ruleName, severity, confidence;
  final String title, srcIp, dstIp, protocol, category, hostname, url;
  final Object? srcPort, dstPort;
  final String uid, correlation, relatedRuleId, relatedFuid, relatedUid;
  // Evidence stays a string; structured values are read only when valid JSON.
  final String evidence, sourceTool, alertOrigin, detectionEngine;
  final List<String> evidenceRefs;
  final List<Map<String, dynamic>> relatedEvents;

  factory Alert.fromJson(Map<String, dynamic> json) {
    final evidence = _string(json['evidence']);
    final fields = _parseEvidenceFields(evidence);
    Object? field(String name, [String? evidenceName]) =>
        json[name] ?? fields[evidenceName ?? name];
    return Alert(
      alertId: _string(json['alert_id'], 'unknown'),
      timestampUtc: _string(json['timestamp_utc']),
      ruleId: _string(json['rule_id'], 'unknown'),
      ruleName: _string(
        json['rule_name'] ?? fields['rule_name'] ?? fields['signature'],
      ),
      severity: _string(json['severity'], 'unknown'),
      confidence: _string(json['confidence'], 'unknown'),
      title: _string(json['title'], 'Untitled alert'),
      srcIp: _string(json['src_ip']),
      srcPort: field('src_port'),
      dstIp: _string(json['dst_ip']),
      dstPort: field('dst_port'),
      protocol: _string(field('protocol')),
      category: _string(field('category')),
      hostname: _string(field('hostname')),
      url: _string(field('url', 'http_url')),
      uid: _string(json['uid']),
      correlation: _string(json['correlation']),
      relatedRuleId: _string(json['related_rule_id']),
      relatedFuid: _string(json['related_fuid']),
      relatedUid: _string(json['related_uid']),
      evidence: evidence,
      sourceTool: _string(json['source_tool'], 'unknown'),
      alertOrigin: _string(json['alert_origin']),
      detectionEngine: _string(json['detection_engine']),
      evidenceRefs: _stringList(json['evidence_refs']),
      relatedEvents: _eventList(json['related_events']),
    );
  }

  DateTime? get parsedTimestamp => DateTime.tryParse(timestampUtc);

  bool matchesSearch(String query) {
    final normalizedQuery = query.trim().toLowerCase();
    if (normalizedQuery.isEmpty) return true;
    final fields = [
      alertId,
      timestampUtc,
      title,
      ruleId,
      ruleName,
      severity,
      confidence,
      sourceTool,
      srcIp,
      srcPort,
      dstIp,
      dstPort,
      protocol,
      category,
      hostname,
      url,
      uid,
      correlation,
      relatedRuleId,
      relatedFuid,
      relatedUid,
      alertOrigin,
      detectionEngine,
      ...evidenceRefs,
      evidence,
      jsonEncode(relatedEvents),
    ];
    return fields.any(
      (value) =>
          value != null &&
          value.toString().toLowerCase().contains(normalizedQuery),
    );
  }

  static Map<String, dynamic> _parseEvidenceFields(String evidence) {
    if (evidence.isEmpty) return const {};
    try {
      final decoded = jsonDecode(evidence);
      return decoded is Map<String, dynamic> ? decoded : const {};
    } on FormatException {
      return const {};
    }
  }

  static String _string(Object? value, [String fallback = '']) =>
      value == null ? fallback : value.toString();

  static List<String> _stringList(Object? value) => value is List
      ? value.whereType<String>().toList(growable: false)
      : const [];

  static List<Map<String, dynamic>> _eventList(Object? value) => value is List
      ? value
            .whereType<Map>()
            .map((event) => Map<String, dynamic>.from(event))
            .toList(growable: false)
      : const [];
}
