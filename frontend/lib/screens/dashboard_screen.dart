import 'dart:convert';
import 'dart:math' as math;

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../models/alert.dart';
import '../models/alerts_page.dart';
import '../models/dashboard_stats.dart';
import '../models/health_status.dart';
import 'malware_intelligence_screen.dart';
import '../services/alerts_csv.dart';
import '../services/csv_download.dart';
import '../services/api_client.dart';
import '../theme/soc_theme.dart';
import '../widgets/soc_navigation.dart';

enum _AlertSort { newest, severity }

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.apiClient, this.onCsvExport});
  final ApiClient apiClient;
  final ValueChanged<String>? onCsvExport;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final _scaffoldKey = GlobalKey<ScaffoldState>();
  static const _pageSize = 20;
  static const _fetchPageSize = 500;
  final _search = TextEditingController();
  DashboardStats? _stats;
  HealthStatus? _health;
  List<Alert> _allAlerts = const [];
  List<Alert> _matchingAlerts = const [];
  List<Alert> _visibleAlerts = const [];
  Alert? _selectedAlert;
  String? _severity;
  String? _source;
  String? _ruleId;
  String? _error;
  bool _loading = true;
  bool _backendUnavailable = false;
  int _page = 1;
  _AlertSort _sort = _AlertSort.newest;

  int get _totalAlerts => _stats?.totalAlerts ?? 0;
  bool get _hasFilters =>
      _search.text.trim().isNotEmpty ||
      _severity != null ||
      _source != null ||
      _ruleId != null;
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
      final byRule = _ruleId == null || alert.ruleId == _ruleId;
      return bySeverity && bySource && byRule && alert.matchesSearch(query);
    }).toList();
    results.sort(
      _sort == _AlertSort.severity ? _compareSeverity : _compareNewest,
    );
    _matchingAlerts = List.unmodifiable(results);
    if (_selectedAlert != null &&
        !_matchingAlerts.any(
          (alert) => alert.alertId == _selectedAlert!.alertId,
        )) {
      _selectedAlert = _matchingAlerts.isEmpty ? null : _matchingAlerts.first;
    } else if (_selectedAlert == null && _matchingAlerts.isNotEmpty) {
      _selectedAlert = _matchingAlerts.first;
    }
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

  void _setFilters({String? severity, String? source, String? ruleId}) {
    setState(() {
      _severity = severity == null || severity.isEmpty ? null : severity;
      _source = source == null || source.isEmpty ? null : source;
      _ruleId = ruleId == null || ruleId.isEmpty ? null : ruleId;
      _page = 1;
      _applyAlertView();
    });
  }

  void _clearFilters() {
    _search.clear();
    setState(() {
      _severity = null;
      _source = null;
      _ruleId = null;
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

  void _selectAlert(Alert alert) {
    setState(() => _selectedAlert = alert);
  }

  void _exportCsv() {
    if (_matchingAlerts.isEmpty) return;
    final csv = buildAlertsCsv(_matchingAlerts);
    final callback = widget.onCsvExport;
    if (callback != null) {
      callback(csv);
      return;
    }
    downloadCsv('soc-alerts-filtered.csv', csv);
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final desktop = constraints.maxWidth >= 1180;
      return Scaffold(
        key: _scaffoldKey,
        drawer: desktop
            ? null
            : Drawer(
                width: math.min(320, constraints.maxWidth * .86),
                backgroundColor: SocColors.secondary,
                child: SocNavigation(
                  compact: true,
                  selected: 'dashboard',
                  onDashboard: () => Navigator.of(context).pop(),
                  onThreatIntelligence: () =>
                      _openMalwareIntelligence(closeDrawer: true),
                ),
              ),
        body: SafeArea(
          child: desktop
              ? Row(
                  children: [
                    SocNavigation(
                      selected: 'dashboard',
                      onDashboard: () {},
                      onThreatIntelligence: _openMalwareIntelligence,
                    ),
                    Expanded(
                      child: _dashboardContent(
                        constraints.maxWidth - 236,
                        desktop: true,
                      ),
                    ),
                  ],
                )
              : _dashboardContent(constraints.maxWidth, desktop: false),
        ),
      );
    },
  );

  Widget _dashboardContent(double width, {required bool desktop}) =>
      LayoutBuilder(
        builder: (context, constraints) {
          final wide = constraints.maxWidth >= 760;
          final padding = desktop
              ? 30.0
              : wide
              ? 24.0
              : 16.0;
          return Align(
            alignment: Alignment.topCenter,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 1480),
              child: CustomScrollView(
                slivers: [
                  SliverPadding(
                    padding: EdgeInsets.fromLTRB(padding, 24, padding, 32),
                    sliver: SliverList.list(
                      children: [
                        _header(wide, desktop: desktop),
                        const SizedBox(height: 18),
                        _historicalNotice(),
                        const SizedBox(height: 20),
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
                          _summary(width),
                          const SizedBox(height: 18),
                          _workbench(wide),
                          const SizedBox(height: 20),
                          _distributions(wide),
                          const SizedBox(height: 20),
                          _activityAndProjectFindings(wide),
                          const SizedBox(height: 20),
                          _intelligencePanel(),
                          const SizedBox(height: 20),
                          _recentDetections(),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      );

  Widget _header(bool wide, {required bool desktop}) {
    final connected = _health?.isAvailable ?? false;
    return Row(
      children: [
        if (!desktop)
          IconButton(
            key: const ValueKey('open-navigation'),
            tooltip: 'Open navigation',
            onPressed: () => _scaffoldKey.currentState?.openDrawer(),
            icon: const Icon(Icons.menu_rounded),
          )
        else
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: SocColors.elevated,
              borderRadius: BorderRadius.circular(13),
              border: Border.all(color: SocColors.border),
            ),
            child: const Icon(Icons.analytics_outlined, color: SocColors.cyan),
          ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'NETWORK TRAFFIC / DETECTION',
                style: TextStyle(
                  color: SocColors.textSecondary,
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.25,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'SOC Dashboard',
                style: TextStyle(
                  fontSize: wide ? 25 : 20,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -.35,
                ),
              ),
            ],
          ),
        ),
        if (wide)
          _Connection(connected: connected, loading: _loading)
        else
          Tooltip(
            message: connected ? 'API connected' : 'API unavailable',
            child: Icon(
              Icons.circle,
              size: 11,
              color: connected ? SocColors.low : SocColors.high,
            ),
          ),
        if (wide)
          TextButton.icon(
            key: const ValueKey('malware-intelligence-button'),
            onPressed: _openMalwareIntelligence,
            icon: const Icon(Icons.biotech_outlined),
            label: const Text('Malware intelligence'),
          )
        else
          IconButton(
            key: const ValueKey('malware-intelligence-button'),
            tooltip: 'Malware intelligence',
            onPressed: _openMalwareIntelligence,
            icon: const Icon(Icons.biotech_outlined),
          ),
        const SizedBox(width: 4),
        IconButton(
          key: const ValueKey('refresh-button'),
          tooltip: 'Refresh dashboard',
          onPressed: _loading ? null : _loadDashboard,
          icon: const Icon(Icons.refresh),
        ),
      ],
    );
  }

  Widget _historicalNotice() => Container(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    decoration: BoxDecoration(
      color: SocColors.secondary,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: SocColors.border),
    ),
    child: const Row(
      children: [
        Icon(Icons.history, size: 18, color: SocColors.cyan),
        SizedBox(width: 10),
        Expanded(
          child: Text(
            'Historical network analysis · imported PCAP detections · not live monitoring',
            style: TextStyle(color: SocColors.textPrimary, fontSize: 12),
          ),
        ),
      ],
    ),
  );

  Widget _activityAndProjectFindings(bool wide) {
    final projectAlerts =
        _allAlerts
            .where(
              (alert) => alert.sourceTool.toLowerCase() == 'projectdetector',
            )
            .toList()
          ..sort(_compareNewest);
    final activity = _ActivityPanel(alerts: _allAlerts);
    final project = Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'ProjectDetector findings',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 4),
            const Text(
              'Project rules matched in the imported alert dataset.',
              style: TextStyle(fontSize: 11, color: SocColors.textSecondary),
            ),
            const SizedBox(height: 14),
            Row(
              children: [
                Text(
                  '${projectAlerts.length}',
                  style: const TextStyle(
                    fontSize: 30,
                    fontWeight: FontWeight.w700,
                    color: SocColors.cyan,
                  ),
                ),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text(
                    'findings returned by the API',
                    style: TextStyle(
                      fontSize: 12,
                      color: SocColors.textPrimary,
                    ),
                  ),
                ),
              ],
            ),
            const Divider(height: 20),
            if (projectAlerts.isEmpty)
              const Text(
                'No ProjectDetector findings in this dataset.',
                style: TextStyle(fontSize: 12, color: SocColors.textSecondary),
              )
            else
              for (final alert in projectAlerts.take(3))
                ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(
                    Icons.rule_outlined,
                    size: 17,
                    color: SocColors.cyan,
                  ),
                  title: Text(
                    '${alert.ruleId} · ${alert.title}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 12),
                  ),
                  subtitle: Text(
                    '${alert.severity} · ${alert.timestampUtc}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 10),
                  ),
                  onTap: () => _showDetails(alert),
                ),
          ],
        ),
      ),
    );
    if (!wide) {
      return Column(children: [activity, const SizedBox(height: 12), project]);
    }
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(flex: 3, child: activity),
        const SizedBox(width: 14),
        Expanded(flex: 2, child: project),
      ],
    );
  }

  Widget _intelligencePanel() => Card(
    child: Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(16),
        gradient: LinearGradient(
          colors: [SocColors.card, SocColors.primary.withValues(alpha: .10)],
          begin: Alignment.centerLeft,
          end: Alignment.centerRight,
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: SocColors.primary.withValues(alpha: .13),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(
              Icons.travel_explore_outlined,
              color: SocColors.cyan,
            ),
          ),
          const SizedBox(width: 14),
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Threat intelligence',
                  style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700),
                ),
                SizedBox(height: 4),
                Text(
                  'Dashboard statistics do not include reputation matches. Use Malware Intelligence for hash lookups and local analysis records.',
                  style: TextStyle(
                    color: SocColors.textSecondary,
                    fontSize: 11,
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 10),
          IconButton.filledTonal(
            key: const ValueKey('open-threat-intelligence-panel'),
            tooltip: 'Open Malware Intelligence',
            onPressed: _openMalwareIntelligence,
            icon: const Icon(Icons.arrow_forward_rounded),
          ),
        ],
      ),
    ),
  );
  Widget _recentDetections() {
    final recent = [..._allAlerts]..sort(_compareNewest);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Recent detections',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 4),
            const Text(
              'Latest alerts by parsed source timestamp.',
              style: TextStyle(fontSize: 11, color: SocColors.textSecondary),
            ),
            const SizedBox(height: 10),
            if (recent.isEmpty)
              const Text(
                'No alerts are available.',
                style: TextStyle(color: SocColors.textSecondary, fontSize: 12),
              )
            else
              for (final alert in recent.take(5))
                ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: _SeverityBadge(severity: alert.severity),
                  title: Text(
                    '${alert.sourceTool} · ${alert.ruleId}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    alert.timestampUtc,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 10,
                      color: SocColors.textSecondary,
                    ),
                  ),
                  trailing: const Icon(Icons.open_in_new, size: 16),
                  onTap: () => _showDetails(alert),
                ),
          ],
        ),
      ),
    );
  }

  void _openMalwareIntelligence({bool closeDrawer = false}) {
    if (closeDrawer) Navigator.of(context).pop();
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => MalwareIntelligenceScreen(apiClient: widget.apiClient),
      ),
    );
  }

  Widget _summary(double width) {
    final stats = _stats!;
    final compact = width < 760;
    final sources = [
      ('Suricata', SocColors.native),
      ('Zeek', SocColors.zeek),
      ('ProjectDetector', SocColors.project),
    ];
    return Container(
      key: const ValueKey('operational-overview'),
      padding: EdgeInsets.symmetric(
        horizontal: compact ? 14 : 20,
        vertical: 14,
      ),
      decoration: BoxDecoration(
        color: SocColors.secondary,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: SocColors.border),
      ),
      child: Wrap(
        spacing: 22,
        runSpacing: 12,
        crossAxisAlignment: WrapCrossAlignment.center,
        children: [
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.inbox_outlined, color: SocColors.cyan, size: 19),
              const SizedBox(width: 9),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    stats.totalAlertsAvailable ? '${stats.totalAlerts}' : '—',
                    key: const ValueKey('total-alert-value'),
                    style: const TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const Text(
                    'Total alerts',
                    style: TextStyle(
                      fontSize: 10,
                      color: SocColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ],
          ),
          for (final (source, color) in sources)
            _OverviewCount(
              label: source == 'ProjectDetector' ? 'Project findings' : source,
              value: stats.sourceCountsAvailable
                  ? (stats.sourceCounts[source] ?? 0).toString()
                  : '—',
              color: color,
            ),
          Container(width: 1, height: 34, color: SocColors.border),
          _OverviewCount(
            label: 'High',
            value: stats.severityCountsAvailable
                ? '${stats.severityCount('high')}'
                : '—',
            color: SocColors.high,
          ),
          _OverviewCount(
            label: 'Medium',
            value: stats.severityCountsAvailable
                ? '${stats.severityCount('medium')}'
                : '—',
            color: SocColors.medium,
          ),
          _OverviewCount(
            label: 'Low',
            value: stats.severityCountsAvailable
                ? '${stats.severityCount('low')}'
                : '—',
            color: SocColors.low,
          ),
          if (!stats.sourceCountsAvailable || !stats.severityCountsAvailable)
            SizedBox(
              width: compact ? double.infinity : null,
              child: Text(
                [
                  if (!stats.sourceCountsAvailable) 'Source counts unavailable',
                  if (!stats.severityCountsAvailable)
                    'severity counts unavailable',
                ].join(' · '),
                style: const TextStyle(
                  color: SocColors.textSecondary,
                  fontSize: 10,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _workbench(bool wide) => LayoutBuilder(
    builder: (context, constraints) {
      if (constraints.maxWidth < 1060) return _alertsPanel(wide);
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(flex: 7, child: _alertsPanel(wide)),
          const SizedBox(width: 14),
          Expanded(flex: 3, child: _investigationPanel()),
        ],
      );
    },
  );

  Widget _investigationPanel() {
    final alert = _selectedAlert;
    return Card(
      key: const ValueKey('investigation-inspector'),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: alert == null
            ? const _InspectorEmpty()
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(
                        Icons.manage_search,
                        color: SocColors.cyan,
                        size: 19,
                      ),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'Investigation focus',
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                      _SeverityBadge(severity: alert.severity),
                    ],
                  ),
                  const SizedBox(height: 15),
                  Text(
                    alert.title,
                    key: const ValueKey('inspector-alert-title'),
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                      height: 1.35,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 7,
                    runSpacing: 7,
                    children: [
                      _SourceTag(source: alert.sourceTool),
                      _InspectorTag(label: alert.ruleId),
                    ],
                  ),
                  const SizedBox(height: 14),
                  _InspectorField(
                    label: 'Observed at (UTC)',
                    value: alert.timestampUtc,
                  ),
                  _InspectorField(
                    label: 'Source',
                    value: _missing(alert.srcIp),
                  ),
                  _InspectorField(
                    label: 'Destination',
                    value: _destination(alert),
                  ),
                  _InspectorField(
                    label: 'Protocol',
                    value: _missing(alert.protocol),
                  ),
                  const Divider(height: 22),
                  const Text(
                    'Evidence references',
                    style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
                  ),
                  const SizedBox(height: 7),
                  if (alert.evidenceRefs.isEmpty)
                    const Text(
                      'No row-level evidence reference was returned.',
                      style: TextStyle(
                        fontSize: 11,
                        color: SocColors.textSecondary,
                      ),
                    )
                  else
                    for (final reference in alert.evidenceRefs.take(4))
                      Padding(
                        padding: const EdgeInsets.only(bottom: 6),
                        child: SelectableText(
                          reference,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 10,
                            color: SocColors.cyan,
                            height: 1.4,
                          ),
                        ),
                      ),
                  if (alert.evidenceRefs.length > 4)
                    Text(
                      '+${alert.evidenceRefs.length - 4} more references in full details',
                      style: const TextStyle(
                        fontSize: 10,
                        color: SocColors.textSecondary,
                      ),
                    ),
                  const SizedBox(height: 14),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.tonalIcon(
                      key: const ValueKey('open-inspector-details'),
                      onPressed: () => _showDetails(alert),
                      icon: const Icon(Icons.open_in_new, size: 16),
                      label: const Text('Open full investigation'),
                    ),
                  ),
                  const SizedBox(height: 12),
                  const Text(
                    'Source-linked evidence supports review; it does not establish causality or compromise by itself.',
                    style: TextStyle(
                      fontSize: 10,
                      color: SocColors.textSecondary,
                      height: 1.4,
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _distributions(bool wide) {
    final stats = _stats!;
    final severityValues = [
      _BarEntry('High', stats.severityCount('high'), SocColors.high),
      _BarEntry('Medium', stats.severityCount('medium'), SocColors.medium),
      _BarEntry('Low', stats.severityCount('low'), SocColors.low),
      if (stats.severityCounts.containsKey('unknown'))
        _BarEntry(
          'Unknown',
          stats.severityCount('unknown'),
          SocColors.textSecondary,
        ),
    ];
    final severitySum = stats.severityCounts.values.fold<int>(
      0,
      (a, b) => a + b,
    );
    final sourceSum = stats.sourceCounts.values.fold<int>(0, (a, b) => a + b);
    final severity = _Distribution(
      title: 'Severity distribution',
      subtitle: 'Alert counts by severity',
      total: stats.totalAlerts,
      unavailableMessage:
          !stats.totalAlertsAvailable || !stats.severityCountsAvailable
          ? 'Severity counts are unavailable in the API response.'
          : null,
      integrityWarning:
          stats.totalAlertsAvailable &&
              stats.severityCountsAvailable &&
              severitySum != stats.totalAlerts
          ? 'Returned severity counts sum to $severitySum; API total is ${stats.totalAlerts}.'
          : null,
      entries: severityValues,
    );
    final sources = _Distribution(
      title: 'Alert sources',
      subtitle: 'Signals from each detection tool',
      total: stats.totalAlerts,
      unavailableMessage:
          !stats.totalAlertsAvailable || !stats.sourceCountsAvailable
          ? 'Source counts are unavailable in the API response.'
          : null,
      integrityWarning:
          stats.totalAlertsAvailable &&
              stats.sourceCountsAvailable &&
              sourceSum != stats.totalAlerts
          ? 'Returned source counts sum to $sourceSum; API total is ${stats.totalAlerts}.'
          : null,
      entries: stats.sourceCounts.entries
          .map(
            (entry) => _BarEntry(entry.key, entry.value, switch (entry.key
                .toLowerCase()) {
              'suricata' => SocColors.native,
              'zeek' => SocColors.zeek,
              'projectdetector' => SocColors.project,
              _ => SocColors.textSecondary,
            }),
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

  Widget _alertsPanel(bool wide) => LayoutBuilder(
    builder: (context, constraints) {
      final tableLayout = constraints.maxWidth >= 900;
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
                            color: SocColors.textSecondary,
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
                      color: SocColors.textPrimary,
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
                  OutlinedButton.icon(
                    key: const ValueKey('export-alerts-csv'),
                    onPressed: _matchingAlerts.isEmpty ? null : _exportCsv,
                    icon: const Icon(Icons.download_outlined, size: 17),
                    label: Text('Export CSV (${_matchingAlerts.length})'),
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
              else if (tableLayout)
                _table(_visibleAlerts, onSelect: _selectAlert)
              else
                _mobileList(_visibleAlerts),
              if (_matchingAlerts.isNotEmpty) ...[
                const Divider(height: 28, color: SocColors.border),
                _pagination(_pageInfo),
              ],
            ],
          ),
        ),
      );
    },
  );

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
        onChanged: (value) =>
            _setFilters(severity: value, source: _source, ruleId: _ruleId),
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
          DropdownMenuItem(
            value: 'ProjectDetector',
            child: Text('Project detector'),
          ),
        ],
        onChanged: (value) =>
            _setFilters(severity: _severity, source: value, ruleId: _ruleId),
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
    final rules = SizedBox(
      width: wide ? 190 : double.infinity,
      child: DropdownButtonFormField<String>(
        key: const ValueKey('rule-filter'),
        isExpanded: true,
        initialValue: _ruleId ?? '',
        decoration: const InputDecoration(labelText: 'Rule ID', isDense: true),
        items: [
          const DropdownMenuItem(value: '', child: Text('All rules')),
          for (final id
              in (_stats?.ruleCounts.keys.toList() ?? const <String>[])..sort())
            DropdownMenuItem(
              value: id,
              child: Text(id, overflow: TextOverflow.ellipsis),
            ),
        ],
        onChanged: (value) =>
            _setFilters(severity: _severity, source: _source, ruleId: value),
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
          const SizedBox(height: 10),
          rules,
        ],
      );
    }
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [search, severity, source, rules, sorting],
    );
  }

  Widget _table(List<Alert> alerts, {required ValueChanged<Alert> onSelect}) =>
      LayoutBuilder(
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
                color: SocColors.textSecondary,
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
                      selected: alert.alertId == _selectedAlert?.alertId,
                      onSelectChanged: (_) => onSelect(alert),
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
                                    color: SocColors.textSecondary,
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
            child: Material(
              color: SocColors.secondary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
                side: const BorderSide(color: SocColors.border),
              ),
              clipBehavior: Clip.antiAlias,
              child: ListTile(
                onTap: () {
                  _selectAlert(alert);
                  _showDetails(alert);
                },
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
                        style: const TextStyle(color: SocColors.textPrimary),
                      ),
                      Text(
                        alert.ruleId,
                        style: const TextStyle(color: SocColors.textSecondary),
                      ),
                      Text(
                        alert.srcIp,
                        style: const TextStyle(color: SocColors.textSecondary),
                      ),
                    ],
                  ),
                ),
                trailing: const Icon(
                  Icons.chevron_right,
                  color: SocColors.textSecondary,
                ),
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
          style: const TextStyle(color: SocColors.textSecondary, fontSize: 12),
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
    final color = connected ? SocColors.low : SocColors.high;
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

class _OverviewCount extends StatelessWidget {
  const _OverviewCount({
    required this.label,
    required this.value,
    required this.color,
  });
  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Container(
        width: 7,
        height: 7,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
      const SizedBox(width: 7),
      Text(
        value,
        style: TextStyle(
          color: color,
          fontWeight: FontWeight.w800,
          fontSize: 13,
        ),
      ),
      const SizedBox(width: 4),
      Text(
        label,
        style: const TextStyle(color: SocColors.textSecondary, fontSize: 10),
      ),
    ],
  );
}

class _InspectorEmpty extends StatelessWidget {
  const _InspectorEmpty();
  @override
  Widget build(BuildContext context) => const Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(Icons.manage_search, color: SocColors.cyan),
      SizedBox(height: 12),
      Text(
        'Select an alert to inspect',
        style: TextStyle(fontWeight: FontWeight.w700),
      ),
      SizedBox(height: 6),
      Text(
        'Choose a row in the queue to review attribution, network fields, and evidence references.',
        style: TextStyle(
          color: SocColors.textSecondary,
          fontSize: 11,
          height: 1.5,
        ),
      ),
    ],
  );
}

class _SourceTag extends StatelessWidget {
  const _SourceTag({required this.source});
  final String source;
  @override
  Widget build(BuildContext context) {
    final color = switch (source.toLowerCase()) {
      'suricata' => SocColors.native,
      'zeek' => SocColors.zeek,
      'projectdetector' => SocColors.project,
      _ => SocColors.textSecondary,
    };
    return _InspectorTag(label: source, color: color);
  }
}

class _InspectorTag extends StatelessWidget {
  const _InspectorTag({
    required this.label,
    this.color = SocColors.textSecondary,
  });
  final String label;
  final Color color;
  @override
  Widget build(BuildContext context) => Container(
    constraints: const BoxConstraints(maxWidth: 230),
    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
    decoration: BoxDecoration(
      color: color.withValues(alpha: .10),
      borderRadius: BorderRadius.circular(8),
      border: Border.all(color: color.withValues(alpha: .30)),
    ),
    child: Text(
      label,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w700),
    ),
  );
}

class _InspectorField extends StatelessWidget {
  const _InspectorField({required this.label, required this.value});
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 9),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 100,
          child: Text(
            label,
            style: const TextStyle(
              color: SocColors.textSecondary,
              fontSize: 10,
            ),
          ),
        ),
        Expanded(
          child: SelectableText(
            value,
            style: const TextStyle(fontSize: 10, height: 1.4),
          ),
        ),
      ],
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
    this.unavailableMessage,
    this.integrityWarning,
  });
  final String title;
  final String subtitle;
  final int total;
  final List<_BarEntry> entries;
  final String? unavailableMessage;
  final String? integrityWarning;

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
            style: const TextStyle(
              fontSize: 11,
              color: SocColors.textSecondary,
            ),
          ),
          if (integrityWarning != null) ...[
            const SizedBox(height: 10),
            Text(
              integrityWarning!,
              style: const TextStyle(color: SocColors.medium, fontSize: 11),
            ),
          ],
          const SizedBox(height: 16),
          if (unavailableMessage != null)
            Text(
              unavailableMessage!,
              style: const TextStyle(
                color: SocColors.textSecondary,
                fontSize: 12,
              ),
            )
          else
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
                        backgroundColor: SocColors.border,
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

class _ActivityPanel extends StatelessWidget {
  const _ActivityPanel({required this.alerts});
  final List<Alert> alerts;

  @override
  Widget build(BuildContext context) {
    final countsByDay = <DateTime, int>{};
    for (final alert in alerts) {
      final timestamp = alert.parsedTimestamp?.toUtc();
      if (timestamp == null) continue;
      final day = DateTime.utc(timestamp.year, timestamp.month, timestamp.day);
      countsByDay.update(day, (value) => value + 1, ifAbsent: () => 1);
    }
    final days = countsByDay.keys.toList()..sort((a, b) => b.compareTo(a));
    final visibleDays = days.take(7).toList();
    final maximum = visibleDays.isEmpty
        ? 1
        : visibleDays.map((day) => countsByDay[day]!).reduce(math.max);
    final parseableCount = countsByDay.values.fold<int>(0, (a, b) => a + b);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Observed alert volume',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 4),
            const Text(
              'Counts from returned alert timestamps by UTC date · not network traffic volume',
              style: TextStyle(fontSize: 11, color: SocColors.textSecondary),
            ),
            const SizedBox(height: 18),
            if (visibleDays.isEmpty)
              const Text(
                'No parseable alert timestamps are available for this dataset.',
                style: TextStyle(color: SocColors.textSecondary, fontSize: 12),
              )
            else ...[
              SizedBox(
                height: 112,
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    for (final day in visibleDays.reversed)
                      Expanded(
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 4),
                          child: Column(
                            mainAxisAlignment: MainAxisAlignment.end,
                            children: [
                              Text(
                                '${countsByDay[day]}',
                                style: const TextStyle(
                                  fontSize: 10,
                                  color: SocColors.textPrimary,
                                ),
                              ),
                              const SizedBox(height: 5),
                              Container(
                                height: math.max(
                                  4,
                                  66 * countsByDay[day]! / maximum,
                                ),
                                decoration: BoxDecoration(
                                  color: SocColors.primary,
                                  borderRadius: BorderRadius.circular(5),
                                ),
                              ),
                              const SizedBox(height: 7),
                              Text(
                                '${day.month}/${day.day}',
                                style: const TextStyle(
                                  fontSize: 9,
                                  color: SocColors.textSecondary,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
              Text(
                '$parseableCount alerts with parseable timestamps across ${countsByDay.length} observed date${countsByDay.length == 1 ? '' : 's'}',
                style: const TextStyle(
                  fontSize: 11,
                  color: SocColors.textSecondary,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _SeverityBadge extends StatelessWidget {
  const _SeverityBadge({required this.severity});
  final String severity;

  @override
  Widget build(BuildContext context) {
    final color = switch (severity.toLowerCase()) {
      'high' => SocColors.high,
      'medium' => SocColors.medium,
      'low' => SocColors.low,
      _ => SocColors.textSecondary,
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
    style: const TextStyle(color: SocColors.textPrimary, fontSize: 11),
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
            style: TextStyle(color: SocColors.textSecondary),
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
            color: SocColors.textSecondary,
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
            style: const TextStyle(
              color: SocColors.textSecondary,
              fontSize: 12,
            ),
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
            Icon(icon, color: SocColors.medium, size: 38),
            const SizedBox(height: 12),
            Text(
              title,
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              message,
              textAlign: TextAlign.center,
              style: const TextStyle(color: SocColors.textSecondary),
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
      backgroundColor: SocColors.card,
      titlePadding: const EdgeInsets.fromLTRB(22, 20, 12, 0),
      contentPadding: const EdgeInsets.fromLTRB(22, 12, 22, 8),
      title: Row(
        children: [
          const Icon(
            Icons.fact_check_outlined,
            color: SocColors.primary,
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
                        style: TextStyle(color: SocColors.medium, fontSize: 11),
                      ),
                    ),
                  Text(
                    alert.title,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: SocColors.secondary,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: SocColors.border),
                    ),
                    child: Text(
                      alert.sourceTool.toLowerCase() == 'projectdetector'
                          ? 'ProjectDetector heuristic candidate. This rule match requires analyst validation and is not proof of compromise.'
                          : 'Native ${alert.sourceTool} rule observation. A signature match is evidence for review, not by itself proof of compromise or causality.',
                      style: const TextStyle(
                        color: SocColors.textPrimary,
                        fontSize: 12,
                      ),
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
                  _DetailRow(label: 'Alert origin', value: alert.alertOrigin),
                  _DetailRow(
                    label: 'Detection engine',
                    value: alert.detectionEngine,
                  ),
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
                  if (alert.evidenceRefs.isNotEmpty)
                    _DetailRow(
                      label: 'Evidence references',
                      value: alert.evidenceRefs.join('\n'),
                    ),
                  if (alert.relatedEvents.isNotEmpty)
                    _DetailRow(
                      label: 'Related events',
                      value: const JsonEncoder.withIndent('  ')
                          .convert(alert.relatedEvents),
                    ),
                  if (alert.relatedEvents.isNotEmpty)
                    const Padding(
                      padding: EdgeInsets.only(top: 6),
                      child: Text(
                        'Related events are source-linked records; temporal proximity alone does not establish causality.',
                        style: TextStyle(
                          color: SocColors.textSecondary,
                          fontSize: 11,
                        ),
                      ),
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
                      color: SocColors.secondary,
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
                    style: TextStyle(
                      color: SocColors.textSecondary,
                      fontSize: 11,
                    ),
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
            style: const TextStyle(
              color: SocColors.textSecondary,
              fontSize: 12,
            ),
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
