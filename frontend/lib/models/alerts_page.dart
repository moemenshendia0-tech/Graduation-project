import 'alert.dart';

class Pagination {
  const Pagination({
    required this.page,
    required this.pageSize,
    required this.total,
    required this.totalPages,
  });

  final int page;
  final int pageSize;
  final int total;
  final int totalPages;

  factory Pagination.fromJson(Map<String, dynamic> json) => Pagination(
    page: _int(json['page']),
    pageSize: _int(json['page_size']),
    total: _int(json['total']),
    totalPages: _int(json['total_pages']),
  );
}

class AlertsPage {
  const AlertsPage({required this.alerts, required this.pagination});

  final List<Alert> alerts;
  final Pagination pagination;

  factory AlertsPage.fromJson(Map<String, dynamic> json) {
    final rawAlerts = json['alerts'];
    final rawPagination = json['pagination'];
    if (rawAlerts is! List || rawPagination is! Map<String, dynamic>) {
      throw const FormatException('Invalid alerts response');
    }
    return AlertsPage(
      alerts: rawAlerts
          .whereType<Map<String, dynamic>>()
          .map(Alert.fromJson)
          .toList(growable: false),
      pagination: Pagination.fromJson(rawPagination),
    );
  }
}

int _int(Object? value) => value is num ? value.toInt() : 0;
