import 'dart:math' as math;

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../models/alert.dart';
import '../models/alerts_page.dart';
import '../models/dashboard_stats.dart';
import '../models/health_status.dart';
import '../services/api_client.dart';

enum _AlertSort { newest, severity }

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.apiClient});
  final ApiClient apiClient;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  static const _pageSize = 20;
  static const _fetchPageSize = 500;
  final _search = TextEditingController();
  DashboardStats? _stats;
  HealthStatus? _health;
  List<Alert> _allAlerts = const [];
  List<Alert> _matchingAlerts = const [];
  List<Alert> _visibleAlerts = const [];
  String? _severity;
  String? _source;
  String? _error;
  bool _loading = true;
  bool _backendUnavailable = false;
  int _page = 1;
  _AlertSort _sort = _AlertSort.newest;

  int get _totalAlerts => _stats?.totalAlerts ?? 0;
  bool get _hasFilters =>
      _search.text.trim().isNotEmpty || _severity != null || _source != null;
  Pagination get _pageInfo => Pagination(
    page: _page,
    pageSize: _pageSize,
    total: _matchingAlerts.length,
    totalPages: (_matchingAlerts.length + _pageSize - 1) ~/ _pageSize,
  );

  @override
  void initState() {
    super.initState();
    _loadDashboard();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _loadDashboard() async {
    setState(() {
      _loading = true;
      _error = null;
      _backendUnavailable = false;
    });
    try {
      final health = await widget.apiClient.getHealth();
      if (!mounted) return;
      _health = health;
      if (!health.isAvailable) {
        setState(() {
          _loading = false;
          _backendUnavailable = true;
          _error =
              'The API is running, but the unified alerts file is unavailable.';
        });
        return;
      }
      final result = await Future.wait<Object>([
        widget.apiClient.getStats(),
        _loadAllAlerts(),
      ]);
      if (!mounted) return;
      setState(() {
        _stats = result[0] as DashboardStats;
        _allAlerts = result[1] as List<Alert>;
        _page = 1;
        _applyAlertView();
        _loading = false;
      });
    } on ApiException catch (error) {
      if (!mounted) return;
      setState(() {
        _error = error.message;
        _backendUnavailable = error.statusCode == null;
        _loading = false;
      });
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _error = 'Unable to load dashboard: $error';
        _loading = false;
      });
    }
  }

  Future<List<Alert>> _loadAllAlerts() async {
    final first = await widget.apiClient.getAlerts(
      page: 1,
      pageSize: _fetchPageSize,
    );
    final alerts = [...first.alerts];
    for (var page = 2; page <= first.pagination.totalPages; page++) {
      final next = await widget.apiClient.getAlerts(
        page: page,
        pageSize: _fetchPageSize,
      );
      alerts.addAll(next.alerts);
    }
    return alerts;
  }

  void _applyAlertView() {
    final query = _search.text.trim().toLowerCase();
    final results = _allAlerts.where((alert) {
      final bySeverity =
          _severity == null || alert.severity.toLowerCase() == _severity;
      final bySource =
          _source == null ||
          alert.sourceTool.toLowerCase() == _source!.toLowerCase();
      return bySeverity && bySource && alert.matchesSearch(query);
    }).toList();
    results.sort(
      _sort == _AlertSort.severity ? _compareSeverity : _compareNewest,
    );
    _matchingAlerts = List.unmodifiable(results);
    final pageCount = (_matchingAlerts.length + _pageSize - 1) ~/ _pageSize;
    _page = _page.clamp(1, math.max(pageCount, 1));
    _updateVisiblePage();
  }

  int _compareNewest(Alert a, Alert b) {
    final left = a.parsedTimestamp, right = b.parsedTimestamp;
    if (left == null && right != null) return 1;
    if (left != null && right == null) return -1;
    if (left != null && right != null) {
      final byTime = right.compareTo(left);
      if (byTime != 0) return byTime;
    }
    return a.alertId.compareTo(b.alertId);
  }

  int _compareSeverity(Alert a, Alert b) {
    final bySeverity = _severityRank(a.severity)
        .compareTo(_severityRank(b.severity));
    return bySeverity != 0 ? bySeverity : _compareNewest(a, b);
  }

  int _severityRank(String severity) => switch (severity.toLowerCase()) {
    'high' => 0,
    'medium' => 1,
    'low' => 2,
    _ => 3,
  };

  void _updateVisiblePage() {
    final start = (_page - 1) * _pageSize;
    _visibleAlerts = _matchingAlerts
        .skip(start)
        .take(_pageSize)
        .toList(growable: false);
  }

  void _onSearchChanged(String _) {
    setState(() {
      _page = 1;
      _applyAlertView();
    });
  }

  void _clearSearch() {
    _search.clear();
    _onSearchChanged('');
  }

  void _setFilters({String? severity, String? source}) {
    setState(() {
      _severity = severity == null || severity.isEmpty ? null : severity;
      _source = source == null || source.isEmpty ? null : source;
      _page = 1;
      _applyAlertView();
    });
  }

  void _clearFilters() {
    _search.clear();
    setState(() {
      _severity = null;
      _source = null;
      _page = 1;
      _applyAlertView();
    });
  }

  void _setSort(_AlertSort sort) {
    setState(() {
      _sort = sort;
      _applyAlertView();
    });
  }

  void _goToPage(int page) {
    if (page < 1 || page > _pageInfo.totalPages) return;
    setState(() {
      _page = page;
      _updateVisiblePage();
    });
  }

  void _showDetails(Alert alert) {
    showDialog<void>(
      context: context,
      builder: (_) => AlertDetailsDialog(
        alert: alert,
        loadDetails: () => widget.apiClient.getAlert(alert.alertId),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final wide = constraints.maxWidth >= 760;
            final padding = wide ? 28.0 : 16.0;
            return Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1480),
                child: CustomScrollView(
                  slivers: [
                    SliverPadding(
                      padding: EdgeInsets.fromLTRB(padding, 20, padding, 28),
                      sliver: SliverList.list(
                        children: [
                          _header(wide),
                          const SizedBox(height: 24),
                          if (_loading && _stats == null)
                            const _Loading()
                          else if (_backendUnavailable && _stats == null)
                            _StatusPanel(
                              icon: Icons.cloud_off_outlined,
                              title: 'Backend unavailable',
                              message: _error ?? 'The API cannot be reached.',
                              action: 'Retry connection',
                              onRetry: _loadDashboard,
                            )
                          else if (_error != null && _stats == null)
                            _StatusPanel(
                              icon: Icons.error_outline,
                              title: 'Unable to load dashboard',
                              message: _error!,
                              action: 'Try again',
                              onRetry: _loadDashboard,
                            )
                          else if (_stats != null) ...[
                            _summary(constraints.maxWidth, padding),
                            const SizedBox(height: 18),
                            _distributions(wide),
                            const SizedBox(height: 24),
                            _alertsPanel(wide),
                          ],
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _header(bool wide) {
    final connected = _health?.isAvailable ?? false;
    return Row(
      children: [
        Container(
          width: 46,
          height: 46,
          decoration: BoxDecoration(
            color: const Color(0xFF103440),
            borderRadius: BorderRadius.circular(14),
          ),
          child: const Icon(Icons.shield_outlined, color: Color(0xFF49D3D4)),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'NETWORK TRAFFIC / DETECTION',
                style: TextStyle(
                  color: Color(0xFF91A6BC),
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 3),
              Text(
                'SOC Dashboard',
                style: TextStyle(
                  fontSize: wide ? 25 : 21,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ],
          ),
        ),
        if (wide)
          _Connection(connected: connected, loading: _loading)
        else
          Tooltip(
            message: connected ? 'Backend connected' : 'Backend unavailable',
            child: Icon(
              Icons.circle,
              size: 12,
              color: connected
                  ? const Color(0xFF42D392)
                  : const Color(0xFFEF6B73),
            ),
          ),
        const SizedBox(width: 8),
        IconButton(
          key: const ValueKey('refresh-button'),
          tooltip: 'Refresh dashboard',
          onPressed: _loading ? null : _loadDashboard,
          icon: const Icon(Icons.refresh),
        ),
      ],
    );
  }

  Widget _summary(double width, double padding) {
    final stats = _stats!;
    final available = math.min(width, 1480) - padding * 2;
    final cardWidth = available >= 1000
        ? (available - 36) / 4
        : available >= 560
        ? (available - 12) / 2
        : available;
    final cards = [
      _Metric(
        'Total alerts',
        stats.totalAlerts,
        'candidate alerts',
        const Color(0xFF45C7D1),
        Icons.notifications_active_outlined,
      ),
      _Metric(
        'High severity',
        stats.severityCount('high'),
        'severity',
        const Color(0xFFEF6B73),
        Icons.priority_high_rounded,
      ),
      _Metric(
        'Medium severity',
        stats.severityCount('medium'),
        'severity',
        const Color(0xFFF0AD58),
        Icons.remove_rounded,
      ),
      _Metric(
        'Low severity',
        stats.severityCount('low'),
        'severity',
        const Color(0xFF59C995),
        Icons.keyboard_arrow_down_rounded,
      ),
    ];
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      children: cards
          .map(
            (metric) => SizedBox(
              width: cardWidth,
              child: _MetricCard(metric: metric),
            ),
          )
          .toList(),
    );
  }

  Widget _distributions(bool wide) {
    final stats = _stats!;
    final severity = _Distribution(
      title: 'Severity distribution',
      subtitle: 'Alert counts by severity',
      total: stats.totalAlerts,
      entries: [
        _BarEntry('High', stats.severityCount('high'), const Color(0xFFEF6B73)),
        _BarEntry(
          'Medium',
          stats.severityCount('medium'),
          const Color(0xFFF0AD58),
        ),
        _BarEntry('Low', stats.severityCount('low'), const Color(0xFF59C995)),
      ],
    );
    final sources = _Distribution(
      title: 'Alert sources',
      subtitle: 'Signals from each detection tool',
      total: stats.totalAlerts,
      entries: stats.sourceCounts.entries
          .map(
            (entry) => _BarEntry(
              entry.key,
              entry.value,
              entry.key.toLowerCase() == 'zeek'
                  ? const Color(0xFF9F8BFF)
                  : const Color(0xFF45C7D1),
            ),
          )
          .toList(),
    );
    if (!wide) {
      return Column(children: [severity, const SizedBox(height: 12), sources]);
    }
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: severity),
        const SizedBox(width: 14),
        Expanded(child: sources),
      ],
    );
  }

  Widget _alertsPanel(bool wide) {
    return Card(
      child: Padding(
        padding: EdgeInsets.all(wide ? 20 : 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Alert queue',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      SizedBox(height: 4),
                      Text(
                        'Review candidate alerts and supporting network evidence.',
                        style: TextStyle(
                          color: Color(0xFF91A6BC),
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
                if (_loading && _stats != null)
                  const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
              ],
            ),
            const SizedBox(height: 18),
            _filters(wide),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 6,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  '${_matchingAlerts.length} matching of $_totalAlerts total alerts',
                  key: const ValueKey('matching-alert-count'),
                  style: const TextStyle(
                    color: Color(0xFFB8C7D8),
                    fontSize: 12,
                  ),
                ),
                if (_hasFilters)
                  TextButton.icon(
                    key: const ValueKey('clear-all-filters'),
                    onPressed: _clearFilters,
                    icon: const Icon(Icons.filter_alt_off_outlined, size: 16),
                    label: const Text('Clear all filters'),
                  ),
              ],
            ),
            if (_error != null) ...[
              const SizedBox(height: 14),
              _InlineError(message: _error!, onRetry: _loadDashboard),
            ],
            const SizedBox(height: 14),
            if (_loading && _allAlerts.isEmpty)
              const _Loading(compact: true)
            else if (_visibleAlerts.isEmpty)
              _Empty(
                noAlerts: _allAlerts.isEmpty,
                hasFilters: _hasFilters,
                onClear: _clearFilters,
              )
            else if (wide)
              _table(_visibleAlerts)
            else
              _mobileList(_visibleAlerts),
            if (_matchingAlerts.isNotEmpty) ...[
              const Divider(height: 28, color: Color(0xFF233247)),
              _pagination(_pageInfo),
            ],
          ],
        ),
      ),
    );
  }

  Widget _filters(bool wide) {
    final search = SizedBox(
      width: wide ? 300 : double.infinity,
      child: TextField(
        key: const ValueKey('alerts-search'),
        controller: _search,
        onChanged: _onSearchChanged,
        textInputAction: TextInputAction.search,
        decoration: InputDecoration(
          hintText: 'Search title, rule, IP, port, protocol...',
          prefixIcon: const Icon(Icons.search),
          suffixIcon: _search.text.isEmpty
              ? null
              : IconButton(
                  key: const ValueKey('clear-search'),
                  tooltip: 'Clear search',
                  onPressed: _clearSearch,
                  icon: const Icon(Icons.close, size: 18),
                ),
          isDense: true,
        ),
      ),
    );
    final severity = SizedBox(
      width: wide ? 165 : double.infinity,
      child: DropdownButtonFormField<String>(
        key: const ValueKey('severity-filter'),
        isExpanded: true,
        initialValue: _severity ?? '',
        decoration: const InputDecoration(labelText: 'Severity', isDense: true),
        items: const [
          DropdownMenuItem(value: '', child: Text('All severities')),
          DropdownMenuItem(value: 'high', child: Text('High')),
          DropdownMenuItem(value: 'medium', child: Text('Medium')),
          DropdownMenuItem(value: 'low', child: Text('Low')),
        ],
        onChanged: (value) => _setFilters(severity: value, source: _source),
      ),
    );
    final source = SizedBox(
      width: wide ? 165 : double.infinity,
      child: DropdownButtonFormField<String>(
        key: const ValueKey('source-filter'),
        isExpanded: true,
        initialValue: _source ?? '',
        decoration: const InputDecoration(labelText: 'Source', isDense: true),
        items: const [
          DropdownMenuItem(value: '', child: Text('All sources')),
          DropdownMenuItem(value: 'Suricata', child: Text('Suricata')),
          DropdownMenuItem(value: 'Zeek', child: Text('Zeek')),
        ],
        onChanged: (value) => _setFilters(severity: _severity, source: value),
      ),
    );
    final sorting = SizedBox(
      width: wide ? 190 : double.infinity,
      child: DropdownButtonFormField<_AlertSort>(
        key: const ValueKey('sort-filter'),
        isExpanded: true,
        initialValue: _sort,
        decoration: const InputDecoration(labelText: 'Sort by', isDense: true),
        items: const [
          DropdownMenuItem(
            value: _AlertSort.newest,
            child: Text('Newest first'),
          ),
          DropdownMenuItem(
            value: _AlertSort.severity,
            child: Text('Severity (high first)'),
          ),
        ],
        onChanged: (value) {
          if (value != null) _setSort(value);
        },
      ),
    );
    if (!wide) {
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          search,
          const SizedBox(height: 10),
          severity,
          const SizedBox(height: 10),
          source,
          const SizedBox(height: 10),
          sorting,
        ],
      );
    }
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [search, severity, source, sorting],
    );
  }

  Widget _table(List<Alert> alerts) => LayoutBuilder(
    builder: (context, constraints) => SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: ConstrainedBox(
        constraints: BoxConstraints(minWidth: constraints.maxWidth),
        child: DataTable(
          headingRowHeight: 42,
          dataRowMinHeight: 58,
          dataRowMaxHeight: 70,
          columnSpacing: 24,
          headingTextStyle: const TextStyle(
            color: Color(0xFF91A6BC),
            fontSize: 11,
            fontWeight: FontWeight.w700,
          ),
          columns: const [
            DataColumn(label: Text('SEVERITY')),
            DataColumn(label: Text('SOURCE / RULE')),
            DataColumn(label: Text('SUMMARY')),
            DataColumn(label: Text('SOURCE IP')),
            DataColumn(label: Text('DESTINATION')),
            DataColumn(label: Text('CONFIDENCE')),
          ],
          rows: alerts
              .map(
                (alert) => DataRow(
                  key: ValueKey('alert-row-${alert.alertId}'),
                  onSelectChanged: (_) => _showDetails(alert),
                  cells: [
                    DataCell(_SeverityBadge(severity: alert.severity)),
                    DataCell(
                      SizedBox(
                        width: 150,
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              alert.sourceTool,
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            Text(
                              alert.ruleId,
                              style: const TextStyle(
                                color: Color(0xFF91A6BC),
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    DataCell(
                      SizedBox(
                        width: 290,
                        child: Text(
                          alert.title,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                    DataCell(Text(_missing(alert.srcIp))),
                    DataCell(Text(_destination(alert))),
                    DataCell(_Confidence(confidence: alert.confidence)),
                  ],
                ),
              )
              .toList(),
        ),
      ),
    ),
  );

  Widget _mobileList(List<Alert> alerts) => Column(
    children: alerts
        .map(
          (alert) => Container(
            key: ValueKey('alert-row-${alert.alertId}'),
            margin: const EdgeInsets.only(bottom: 8),
            decoration: BoxDecoration(
              color: const Color(0xFF0B1625),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFF233247)),
            ),
            child: ListTile(
              onTap: () => _showDetails(alert),
              title: Text(
                alert.title,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              subtitle: Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Wrap(
                  spacing: 8,
                  runSpacing: 7,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    _SeverityBadge(severity: alert.severity),
                    Text(
                      alert.sourceTool,
                      style: const TextStyle(color: Color(0xFFB8C7D8)),
                    ),
                    Text(
                      alert.ruleId,
                      style: const TextStyle(color: Color(0xFF91A6BC)),
                    ),
                    Text(
                      alert.srcIp,
                      style: const TextStyle(color: Color(0xFF91A6BC)),
                    ),
                  ],
                ),
              ),
              trailing: const Icon(
                Icons.chevron_right,
                color: Color(0xFF91A6BC),
              ),
            ),
          ),
        )
        .toList(),
  );

  Widget _pagination(Pagination pagination) {
    final first = pagination.total == 0
        ? 0
        : (pagination.page - 1) * pagination.pageSize + 1;
    final last = math.min(
      pagination.page * pagination.pageSize,
      pagination.total,
    );
    return Wrap(
      alignment: WrapAlignment.spaceBetween,
      crossAxisAlignment: WrapCrossAlignment.center,
      runSpacing: 8,
      children: [
        Text(
          'Showing $first-$last of ${pagination.total}',
          style: const TextStyle(color: Color(0xFF91A6BC), fontSize: 12),
        ),
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              tooltip: 'Previous page',
              onPressed: pagination.page > 1
                  ? () => _goToPage(pagination.page - 1)
                  : null,
              icon: const Icon(Icons.chevron_left),
            ),
            Text('${pagination.page} / ${pagination.totalPages}'),
            IconButton(
              tooltip: 'Next page',
              onPressed: pagination.page < pagination.totalPages
                  ? () => _goToPage(pagination.page + 1)
                  : null,
              icon: const Icon(Icons.chevron_right),
            ),
          ],
        ),
      ],
    );
  }

  String _missing(String value) =>
      value.isEmpty || value.toLowerCase() == 'unknown'
      ? 'Not provided'
      : value;

  String _destination(Alert alert) =>
      alert.dstPort == null || alert.dstPort.toString().isEmpty
      ? _missing(alert.dstIp)
      : '${_missing(alert.dstIp)}:${alert.dstPort}';
}

class _Connection extends StatelessWidget {
  const _Connection({required this.connected, required this.loading});
  final bool connected;
  final bool loading;

  @override
  Widget build(BuildContext context) {
    final color = connected ? const Color(0xFF42D392) : const Color(0xFFEF6B73);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          loading
              ? SizedBox(
                  width: 9,
                  height: 9,
                  child: CircularProgressIndicator(
                    strokeWidth: 1.5,
                    color: color,
                  ),
                )
              : Icon(Icons.circle, size: 8, color: color),
          const SizedBox(width: 7),
          Text(
            loading
                ? 'Checking API'
                : connected
                ? 'API connected'
                : 'API unavailable',
            style: TextStyle(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

class _Metric {
  const _Metric(this.title, this.value, this.note, this.color, this.icon);
  final String title;
  final int value;
  final String note;
  final Color color;
  final IconData icon;
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({required this.metric});
  final _Metric metric;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(18),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: metric.color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(metric.icon, color: metric.color, size: 21),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  metric.title,
                  style: const TextStyle(
                    color: Color(0xFFB8C7D8),
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 4),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(
                      metric.value.toString(),
                      style: const TextStyle(
                        fontSize: 26,
                        fontWeight: FontWeight.w700,
                        height: 1,
                      ),
                    ),
                    const SizedBox(width: 7),
                    Padding(
                      padding: const EdgeInsets.only(bottom: 2),
                      child: Text(
                        metric.note,
                        style: const TextStyle(
                          color: Color(0xFF91A6BC),
                          fontSize: 10,
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    ),
  );
}

class _BarEntry {
  const _BarEntry(this.label, this.value, this.color);
  final String label;
  final int value;
  final Color color;
}

class _Distribution extends StatelessWidget {
  const _Distribution({
    required this.title,
    required this.subtitle,
    required this.total,
    required this.entries,
  });
  final String title;
  final String subtitle;
  final int total;
  final List<_BarEntry> entries;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: const TextStyle(fontSize: 11, color: Color(0xFF91A6BC)),
          ),
          const SizedBox(height: 16),
          ...entries.map((entry) {
            final fraction = total == 0
                ? 0.0
                : (entry.value / total).clamp(0.0, 1.0);
            return Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Column(
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Row(
                          children: [
                            Container(
                              width: 7,
                              height: 7,
                              decoration: BoxDecoration(
                                color: entry.color,
                                shape: BoxShape.circle,
                              ),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              entry.label,
                              style: const TextStyle(fontSize: 12),
                            ),
                          ],
                        ),
                      ),
                      Text(
                        entry.value.toString(),
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(5),
                    child: LinearProgressIndicator(
                      value: fraction,
                      minHeight: 5,
                      backgroundColor: const Color(0xFF26364A),
                      valueColor: AlwaysStoppedAnimation(entry.color),
                    ),
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    ),
  );
}

class _SeverityBadge extends StatelessWidget {
  const _SeverityBadge({required this.severity});
  final String severity;

  @override
  Widget build(BuildContext context) {
    final color = switch (severity.toLowerCase()) {
      'high' => const Color(0xFFEF6B73),
      'medium' => const Color(0xFFF0AD58),
      'low' => const Color(0xFF59C995),
      _ => const Color(0xFF91A6BC),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (severity.toLowerCase() == 'high') ...[
            Icon(Icons.priority_high_rounded, size: 12, color: color),
            const SizedBox(width: 2),
          ],
          Text(
            severity.toUpperCase(),
            style: TextStyle(
              color: color,
              fontSize: 9,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.6,
            ),
          ),
        ],
      ),
    );
  }
}

class _Confidence extends StatelessWidget {
  const _Confidence({required this.confidence});
  final String confidence;

  @override
  Widget build(BuildContext context) => Text(
    'Confidence: ${confidence.isEmpty ? 'unknown' : confidence}',
    style: const TextStyle(color: Color(0xFFB8C7D8), fontSize: 11),
  );
}

class _Loading extends StatelessWidget {
  const _Loading({this.compact = false});
  final bool compact;

  @override
  Widget build(BuildContext context) => Padding(
    padding: EdgeInsets.symmetric(vertical: compact ? 36 : 100),
    child: const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircularProgressIndicator(),
          SizedBox(height: 14),
          Text(
            'Loading unified alerts...',
            style: TextStyle(color: Color(0xFF91A6BC)),
          ),
        ],
      ),
    ),
  );
}

class _Empty extends StatelessWidget {
  const _Empty({
    required this.noAlerts,
    required this.hasFilters,
    required this.onClear,
  });
  final bool noAlerts;
  final bool hasFilters;
  final VoidCallback onClear;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 44),
    child: Center(
      child: Column(
        children: [
          Icon(
            noAlerts ? Icons.inbox_outlined : Icons.search_off,
            size: 30,
            color: const Color(0xFF91A6BC),
          ),
          const SizedBox(height: 10),
          Text(
            noAlerts
                ? 'No candidate alerts are available.'
                : 'No alerts match the current search and filters.',
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 4),
          Text(
            noAlerts
                ? 'Check the configured alerts file and refresh.'
                : 'Adjust your search or clear filters to see more alerts.',
            textAlign: TextAlign.center,
            style: const TextStyle(color: Color(0xFF91A6BC), fontSize: 12),
          ),
          if (hasFilters) ...[
            const SizedBox(height: 8),
            TextButton.icon(
              onPressed: onClear,
              icon: const Icon(Icons.filter_alt_off_outlined, size: 16),
              label: const Text('Clear search and filters'),
            ),
          ],
        ],
      ),
    ),
  );
}

class _StatusPanel extends StatelessWidget {
  const _StatusPanel({
    required this.icon,
    required this.title,
    required this.message,
    required this.action,
    required this.onRetry,
  });
  final IconData icon;
  final String title;
  final String message;
  final String action;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 90, horizontal: 20),
    child: Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 440),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: const Color(0xFFF0AD58), size: 38),
            const SizedBox(height: 12),
            Text(
              title,
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Color(0xFF91A6BC)),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: onRetry,
              icon: const Icon(Icons.refresh),
              label: Text(action),
            ),
          ],
        ),
      ),
    ),
  );
}

class _InlineError extends StatelessWidget {
  const _InlineError({required this.message, required this.onRetry});
  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
    decoration: BoxDecoration(
      color: const Color(0xFF5A2A32).withValues(alpha: 0.45),
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: const Color(0xFF8C414B)),
    ),
    child: Row(
      children: [
        const Icon(
          Icons.warning_amber_rounded,
          color: Color(0xFFF18C8C),
          size: 18,
        ),
        const SizedBox(width: 8),
        Expanded(child: Text(message, style: const TextStyle(fontSize: 12))),
        TextButton(onPressed: onRetry, child: const Text('Retry')),
      ],
    ),
  );
}

class AlertDetailsDialog extends StatefulWidget {
  const AlertDetailsDialog({
    super.key,
    required this.alert,
    required this.loadDetails,
  });
  final Alert alert;
  final Future<Alert> Function() loadDetails;

  @override
  State<AlertDetailsDialog> createState() => _AlertDetailsDialogState();
}

class _AlertDetailsDialogState extends State<AlertDetailsDialog> {
  late Future<Alert> _details;

  @override
  void initState() {
    super.initState();
    _details = widget.loadDetails();
  }

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    return AlertDialog(
      backgroundColor: const Color(0xFF111D2D),
      titlePadding: const EdgeInsets.fromLTRB(22, 20, 12, 0),
      contentPadding: const EdgeInsets.fromLTRB(22, 12, 22, 8),
      title: Row(
        children: [
          const Icon(
            Icons.fact_check_outlined,
            color: Color(0xFF45C7D1),
            size: 21,
          ),
          const SizedBox(width: 10),
          const Expanded(
            child: Text('Alert details', style: TextStyle(fontSize: 18)),
          ),
          IconButton(
            tooltip: 'Close details',
            onPressed: () => Navigator.of(context).pop(),
            icon: const Icon(Icons.close, size: 20),
          ),
        ],
      ),
      content: SizedBox(
        width: math.min(width - 64, 700),
        child: FutureBuilder<Alert>(
          future: _details,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const SizedBox(
                height: 160,
                child: Center(child: CircularProgressIndicator()),
              );
            }
            final alert = snapshot.data ?? widget.alert;
            return SingleChildScrollView(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (snapshot.hasError)
                    const Padding(
                      padding: EdgeInsets.only(bottom: 10),
                      child: Text(
                        'Could not refresh details; showing the loaded alert.',
                        style: TextStyle(
                          color: Color(0xFFF0AD58),
                          fontSize: 11,
                        ),
                      ),
                    ),
                  Text(
                    alert.title,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      _SeverityBadge(severity: alert.severity),
                      _Confidence(confidence: alert.confidence),
                    ],
                  ),
                  const SizedBox(height: 18),
                  _DetailRow(
                    label: 'Alert ID',
                    value: alert.alertId,
                    onCopy: () => _copy('Alert ID', alert.alertId),
                  ),
                  _DetailRow(label: 'Source tool', value: alert.sourceTool),
                  _DetailRow(
                    label: 'Rule ID',
                    value: alert.ruleId,
                    onCopy: () => _copy('Rule ID', alert.ruleId),
                  ),
                  _DetailRow(
                    label: 'Rule name / signature',
                    value: alert.ruleName,
                  ),
                  _DetailRow(
                    label: 'Timestamp (UTC)',
                    value: alert.timestampUtc,
                  ),
                  _DetailRow(
                    label: 'Source IP',
                    value: alert.srcIp,
                    onCopy: _canCopy(alert.srcIp)
                        ? () => _copy('Source IP', alert.srcIp)
                        : null,
                  ),
                  _DetailRow(
                    label: 'Source port',
                    value: alert.srcPort?.toString() ?? '',
                  ),
                  _DetailRow(
                    label: 'Destination IP',
                    value: alert.dstIp,
                    onCopy: _canCopy(alert.dstIp)
                        ? () => _copy('Destination IP', alert.dstIp)
                        : null,
                  ),
                  _DetailRow(
                    label: 'Destination port',
                    value: alert.dstPort?.toString() ?? '',
                  ),
                  _DetailRow(label: 'Protocol', value: alert.protocol),
                  _DetailRow(label: 'Category', value: alert.category),
                  _DetailRow(
                    label: 'Hostname',
                    value: alert.hostname,
                    onCopy: _canCopy(alert.hostname)
                        ? () => _copy('Hostname', alert.hostname)
                        : null,
                  ),
                  _DetailRow(
                    label: 'URL',
                    value: alert.url,
                    onCopy: _canCopy(alert.url)
                        ? () => _copy('URL', alert.url)
                        : null,
                  ),
                  _DetailRow(label: 'Connection UID', value: alert.uid),
                  _DetailRow(label: 'Correlation', value: alert.correlation),
                  _DetailRow(label: 'Related rule', value: alert.relatedRuleId),
                  _DetailRow(
                    label: 'Related file UID',
                    value: alert.relatedFuid,
                  ),
                  _DetailRow(
                    label: 'Related connection UID',
                    value: alert.relatedUid,
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      const Expanded(
                        child: Text(
                          'Evidence',
                          style: TextStyle(fontWeight: FontWeight.w700),
                        ),
                      ),
                      if (alert.evidence.isNotEmpty)
                        IconButton(
                          tooltip: 'Copy evidence text',
                          onPressed: () =>
                              _copy('Evidence text', alert.evidence),
                          icon: const Icon(Icons.copy, size: 16),
                        ),
                    ],
                  ),
                  const SizedBox(height: 7),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A1421),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: SelectableText(
                      alert.evidence.isEmpty
                          ? 'No evidence text provided.'
                          : alert.evidence,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                        height: 1.5,
                        color: Color(0xFFC5D3E1),
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Candidate alert for investigation; not proof of compromise.',
                    style: TextStyle(color: Color(0xFF91A6BC), fontSize: 11),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }

  bool _canCopy(String value) =>
      value.isNotEmpty && value.toLowerCase() != 'unknown';

  Future<void> _copy(String label, String value) async {
    try {
      await Clipboard.setData(ClipboardData(text: value));
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('$label copied')));
    } on Exception {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Copy is unavailable in this browser.')),
      );
    }
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value, this.onCopy});
  final String label;
  final String value;
  final VoidCallback? onCopy;

  String get _displayValue => value.isEmpty || value.toLowerCase() == 'unknown'
      ? 'Not provided'
      : value;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 5),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 142,
          child: Text(
            label,
            style: const TextStyle(color: Color(0xFF91A6BC), fontSize: 12),
          ),
        ),
        Expanded(
          child: SelectableText(
            _displayValue,
            style: const TextStyle(fontSize: 12),
          ),
        ),
        if (onCopy != null)
          IconButton(
            tooltip: 'Copy $label',
            onPressed: onCopy,
            visualDensity: VisualDensity.compact,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
            icon: const Icon(Icons.copy, size: 14),
          ),
      ],
    ),
  );
}
