import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/alert.dart';
import '../models/alerts_page.dart';
import '../models/dashboard_stats.dart';
import '../models/health_status.dart';

const defaultApiBaseUrl = 'http://127.0.0.1:8000';
const apiBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: defaultApiBaseUrl,
);

class ApiException implements Exception {
  const ApiException(this.message, {this.statusCode, this.code});

  final String message;
  final int? statusCode;
  final String? code;

  @override
  String toString() => message;
}

class ApiClient {
  ApiClient({http.Client? client, String baseUrl = apiBaseUrl})
    : _client = client ?? http.Client(),
      _baseUrl = baseUrl.replaceFirst(RegExp(r'/+$'), '');

  final http.Client _client;
  final String _baseUrl;

  void close() => _client.close();

  Future<HealthStatus> getHealth() async {
    final json = await _getJson('/health');
    return HealthStatus.fromJson(json);
  }

  Future<AlertsPage> getAlerts({
    int page = 1,
    int pageSize = 20,
    String? severity,
    String? sourceTool,
    String? query,
  }) async {
    final parameters = <String, String>{
      'page': '$page',
      'page_size': '$pageSize',
      if (_hasValue(severity)) 'severity': severity!,
      if (_hasValue(sourceTool)) 'source_tool': sourceTool!,
      if (_hasValue(query)) 'q': query!,
    };
    final json = await _getJson('/api/alerts', queryParameters: parameters);
    return AlertsPage.fromJson(json);
  }

  Future<Alert> getAlert(String alertId) async {
    final json = await _getJson('/api/alerts/${Uri.encodeComponent(alertId)}');
    final alert = json['alert'];
    if (alert is! Map<String, dynamic>) {
      throw const ApiException('The API returned an invalid alert response.');
    }
    return Alert.fromJson(alert);
  }

  Future<DashboardStats> getStats() async =>
      DashboardStats.fromJson(await _getJson('/api/stats'));

  Future<Map<String, dynamic>> _getJson(
    String path, {
    Map<String, String>? queryParameters,
  }) async {
    final uri = Uri.parse('$_baseUrl$path')
        .replace(queryParameters: queryParameters);
    late final http.Response response;
    try {
      response = await _client.get(
        uri,
        headers: const {'Accept': 'application/json'},
      );
    } on Exception catch (error) {
      throw ApiException('Cannot reach the backend: $error');
    }
    final decoded = _decode(response);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final error = decoded['error'];
      final message = error is Map ? error['message']?.toString() : null;
      final code = error is Map ? error['code']?.toString() : null;
      throw ApiException(
        message ?? 'Backend request failed (${response.statusCode}).',
        statusCode: response.statusCode,
        code: code,
      );
    }
    return decoded;
  }

  Map<String, dynamic> _decode(http.Response response) {
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) return decoded;
    } on FormatException {
      // Report the response as a service error below.
    }
    throw ApiException(
      'The backend returned an invalid JSON response.',
      statusCode: response.statusCode,
    );
  }

  bool _hasValue(String? value) => value != null && value.trim().isNotEmpty;
}
