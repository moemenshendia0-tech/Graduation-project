import 'package:material_ui/material_ui.dart';

import '../theme/soc_theme.dart';

class SocNavigation extends StatelessWidget {
  const SocNavigation({
    super.key,
    required this.selected,
    required this.onDashboard,
    required this.onThreatIntelligence,
    this.compact = false,
  });

  final String selected;
  final VoidCallback onDashboard;
  final VoidCallback onThreatIntelligence;
  final bool compact;

  @override
  Widget build(BuildContext context) => Container(
    width: compact ? null : 236,
    decoration: BoxDecoration(
      color: SocColors.secondary,
      border: compact
          ? null
          : const Border(right: BorderSide(color: SocColors.border)),
    ),
    child: SafeArea(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 24, 18, 24),
            child: Row(
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [SocColors.primary, SocColors.cyan],
                    ),
                    borderRadius: BorderRadius.circular(13),
                  ),
                  child: const Icon(
                    Icons.shield_outlined,
                    color: SocColors.background,
                    size: 23,
                  ),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'SOC WORKSPACE',
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1.1,
                        ),
                      ),
                      SizedBox(height: 3),
                      Text(
                        'NETWORK ANALYSIS',
                        style: TextStyle(
                          color: SocColors.textSecondary,
                          fontSize: 9,
                          letterSpacing: 1.2,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const Padding(
            padding: EdgeInsets.fromLTRB(20, 0, 20, 8),
            child: Text(
              'WORKSPACE',
              style: TextStyle(
                color: SocColors.textSecondary,
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.2,
              ),
            ),
          ),
          _NavigationItem(
            label: 'Dashboard',
            icon: Icons.space_dashboard_outlined,
            selected: selected == 'dashboard',
            onPressed: onDashboard,
          ),
          _NavigationItem(
            label: 'Threat intelligence',
            icon: Icons.travel_explore_outlined,
            selected: selected == 'intelligence',
            onPressed: onThreatIntelligence,
          ),
          const Spacer(),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: SocColors.card,
                border: Border.all(color: SocColors.border),
                borderRadius: BorderRadius.circular(14),
              ),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.history, color: SocColors.cyan, size: 17),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Historical analysis',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 8),
                  Text(
                    'Imported PCAP detections. This workspace is not live monitoring.',
                    style: TextStyle(
                      color: SocColors.textSecondary,
                      fontSize: 11,
                      height: 1.45,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    ),
  );
}

class _NavigationItem extends StatelessWidget {
  const _NavigationItem({
    required this.label,
    required this.icon,
    required this.selected,
    required this.onPressed,
  });

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onPressed;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 3),
    child: Material(
      color: selected ? SocColors.elevated : Colors.transparent,
      borderRadius: BorderRadius.circular(11),
      child: InkWell(
        key: ValueKey('nav-${label.toLowerCase().replaceAll(' ', '-')}'),
        onTap: onPressed,
        borderRadius: BorderRadius.circular(11),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(11),
            border: Border.all(
              color: selected
                  ? SocColors.primary.withValues(alpha: .4)
                  : Colors.transparent,
            ),
          ),
          child: Row(
            children: [
              Icon(
                icon,
                size: 19,
                color: selected ? SocColors.cyan : SocColors.textSecondary,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: selected
                        ? SocColors.textPrimary
                        : SocColors.textSecondary,
                    fontSize: 12,
                    fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
                  ),
                ),
              ),
              if (selected) ...[
                const Spacer(),
                Container(
                  width: 5,
                  height: 5,
                  decoration: const BoxDecoration(
                    color: SocColors.cyan,
                    shape: BoxShape.circle,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    ),
  );
}
