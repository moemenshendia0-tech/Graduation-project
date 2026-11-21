class HealthStatus {
  const HealthStatus({required this.status, required this.alertsFileAvailable});

  final String status;
  final bool alertsFileAvailable;

  bool get isAvailable => status == 'ok' && alertsFileAvailable;

  factory HealthStatus.fromJson(Map<String, dynamic> json) => HealthStatus(
    status: json['status']?.toString() ?? 'unknown',
    alertsFileAvailable: json['alerts_file_available'] == true,
  );
}
