import 'package:material_ui/material_ui.dart';

abstract final class SocColors {
  static const background = Color(0xFF050B16);
  static const secondary = Color(0xFF0A1424);
  static const card = Color(0xFF0D1B2E);
  static const elevated = Color(0xFF12243A);
  static const primary = Color(0xFF168BFF);
  static const cyan = Color(0xFF22D3EE);
  static const purple = Color(0xFF8B5CF6);
  static const textPrimary = Color(0xFFEAF2FF);
  static const textSecondary = Color(0xFF94A3B8);
  static const border = Color(0xFF20334D);
  static const high = Color(0xFFF87171);
  static const medium = Color(0xFFFBBF24);
  static const low = Color(0xFF34D399);
  static const native = primary;
  static const zeek = purple;
  static const project = cyan;
}

abstract final class SocTheme {
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: SocColors.background,
    colorScheme: ColorScheme.fromSeed(
      seedColor: SocColors.primary,
      brightness: Brightness.dark,
      surface: SocColors.card,
      primary: SocColors.primary,
      secondary: SocColors.cyan,
      error: SocColors.high,
    ),
    cardTheme: CardThemeData(
      color: SocColors.card,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: SocColors.border),
      ),
      margin: EdgeInsets.zero,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: SocColors.secondary,
      foregroundColor: SocColors.textPrimary,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      centerTitle: false,
    ),
    dividerTheme: const DividerThemeData(
      color: SocColors.border,
      thickness: 1,
      space: 24,
    ),
    textTheme: const TextTheme(
      headlineSmall: TextStyle(
        color: SocColors.textPrimary,
        fontWeight: FontWeight.w700,
        letterSpacing: -0.3,
      ),
      titleMedium: TextStyle(
        color: SocColors.textPrimary,
        fontWeight: FontWeight.w600,
      ),
      bodyMedium: TextStyle(color: SocColors.textPrimary, height: 1.4),
      bodySmall: TextStyle(color: SocColors.textSecondary, height: 1.35),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: SocColors.secondary,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: SocColors.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: SocColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(12),
        borderSide: const BorderSide(color: SocColors.primary, width: 1.5),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
    ),
  );
}
