import 'package:material_ui/material_ui.dart';

import 'screens/dashboard_screen.dart';
import 'services/api_client.dart';

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
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF08111F),
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF32C5D2),
          brightness: Brightness.dark,
          surface: const Color(0xFF111D2D),
        ),
        cardTheme: CardThemeData(
          color: const Color(0xFF111D2D),
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: Color(0xFF233247)),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFF0B1625),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF2A3B50)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF2A3B50)),
          ),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 14,
            vertical: 12,
          ),
        ),
      ),
      home: DashboardScreen(apiClient: apiClient),
    );
  }
}
