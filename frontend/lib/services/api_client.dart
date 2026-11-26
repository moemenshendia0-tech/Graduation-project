import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/alert.dart';
import '../models/alerts_page.dart';
import '../models/dashboard_stats.dart';
import '../models/health_status.dart';
import '../models/malware_analysis.dart';
import '../models/malware_intelligence.dart';

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

  Future<List<MalwareAnalysis>> getMalwareAnalyses({
    int page = 1,
    int pageSize = 20,
  }) async {
    final result = await _getJson(
      '/api/malware/analyses',
      queryParameters: {'page': '$page', 'page_size': '$pageSize'},
    );
    final values = result['analyses'];
    if (values is! List) {
      throw const ApiException(
        'The API returned an invalid malware analysis list.',
      );
    }
    return values
        .whereType<Map<String, dynamic>>()
        .map(MalwareAnalysis.fromJson)
        .toList();
  }

  Future<MalwareAnalysis> getMalwareAnalysis(String analysisId) async {
    return MalwareAnalysis.fromJson(
      await _getJson(
        '/api/malware/analyses/${Uri.encodeComponent(analysisId)}',
      ),
    );
  }

  Future<MalwareIntelRecord> lookupMalwareHash(String value) async {
    final hash = value.trim();
    if (!RegExp(r'^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$')
        .hasMatch(hash)) {
      throw const ApiException(
        'Enter a valid MD5 (32), SHA-1 (40), or SHA-256 (64) hexadecimal hash.',
        statusCode: 422,
        code: 'invalid_hash',
      );
    }
    final json = await _getJson(
      '/api/malware/intel/${Uri.encodeComponent(hash.toLowerCase())}',
    );
    final record = json['intelligence'];
    if (record is! Map<String, dynamic>) {
      throw const ApiException(
        'The API returned an invalid MalwareBazaar response.',
      );
    }
    return MalwareIntelRecord.fromJson(record);
  }

  Future<MalwareSampleLookup> getMalwareSample(String sha256) async {
    final hash = sha256.trim();
    if (!RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(hash)) {
      throw const ApiException(
        'A valid SHA-256 is required to search local analysis records.',
        statusCode: 422,
        code: 'invalid_hash',
      );
    }
    return MalwareSampleLookup.fromJson(
      await _getJson(
        '/api/malware/samples/${Uri.encodeComponent(hash.toLowerCase())}',
      ),
    );
  }

  Future<List<MalwareEvent>> getMalwareEvents(String analysisId) async {
    final result = await _getJson(
      '/api/malware/analyses/${Uri.encodeComponent(analysisId)}/events',
    );
    final values = result['events'];
    if (values is! List) {
      throw const ApiException('The API returned invalid telemetry events.');
    }
    return values
        .whereType<Map<String, dynamic>>()
        .map(MalwareEvent.fromJson)
        .toList();
  }

  Future<MalwareCorrelations> getMalwareFindings(String analysisId) async {
    final result = await _getJson(
      '/api/malware/analyses/${Uri.encodeComponent(analysisId)}/findings',
    );
    final values = result['findings'];
    final relationships = result['event_relationships'];
    if (values is! List || relationships is! List) {
      throw const ApiException('The API returned invalid correlated findings.');
    }
    return MalwareCorrelations.fromJson(result);
  }

  Future<Map<String, dynamic>> _getJson(
    String path, {
    Map<String, String>? queryParameters,
  }) async {
    final uri = Uri.parse('$_baseUrl$path')
        .replace(queryParameters: queryParameters);
    late final http.Response response;
    try {
      response = await _client
          .get(uri, headers: const {'Accept': 'application/json'})
          .timeout(const Duration(seconds: 15));
    } on TimeoutException {
      throw const ApiException(
        'The request timed out. Check the API and retry.',
        code: 'request_timeout',
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
