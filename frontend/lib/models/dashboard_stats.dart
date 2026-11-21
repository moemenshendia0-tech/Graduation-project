class DashboardStats {
  const DashboardStats({
    required this.totalAlerts,
    required this.severityCounts,
    required this.sourceCounts,
    required this.ruleCounts,
  });

  final int totalAlerts;
  final Map<String, int> severityCounts;
  final Map<String, int> sourceCounts;
  final Map<String, int> ruleCounts;

  factory DashboardStats.fromJson(Map<String, dynamic> envelope) {
    final raw = envelope['stats'];
    if (raw is! Map<String, dynamic>) {
      throw const FormatException('Invalid statistics response');
    }
    return DashboardStats(
      totalAlerts: _int(raw['total_alerts']),
      severityCounts: _countMap(raw['severity_counts']),
      sourceCounts: _countMap(raw['source_counts']),
      ruleCounts: _countMap(raw['rule_counts']),
    );
  }

  int severityCount(String severity) =>
      severityCounts[severity.toLowerCase()] ?? 0;

  static Map<String, int> _countMap(Object? value) {
    if (value is! Map) return const {};
    return value.map<String, int>(
      (key, count) => MapEntry(key.toString(), _int(count)),
    );
  }

  static int _int(Object? value) => value is num ? value.toInt() : 0;
}
