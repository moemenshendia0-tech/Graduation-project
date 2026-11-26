import 'package:material_ui/material_ui.dart';

import 'screens/dashboard_screen.dart';
import 'services/api_client.dart';
import 'theme/soc_theme.dart';

void main() {
  runApp(const NetworkTrafficDashboard());
}

class NetworkTrafficDashboard extends StatelessWidget {
  const NetworkTrafficDashboard({super.key});

  @override
  Widget build(BuildContext context) {
    final apiClient = ApiClient();
    return MaterialApp(
      title: 'Network Traffic SOC Dashboard',
      debugShowCheckedModeBanner: false,
      theme: SocTheme.dark,
      home: DashboardScreen(apiClient: apiClient),
    );
  }
}
