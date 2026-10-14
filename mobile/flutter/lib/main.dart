import 'package:flutter/material.dart';

import 'app/login_screen.dart';
import 'app/print_screen.dart';
import 'app/queue_screen.dart';
import 'app/scan_screen.dart';

void main() {
  runApp(const ScannerApp());
}

class ScannerApp extends StatelessWidget {
  const ScannerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Tallowbrook Scanner',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF8A5A00)),
        visualDensity: VisualDensity.comfortable,
      ),
      initialRoute: LoginScreen.route,
      routes: {
        LoginScreen.route: (_) => const LoginScreen(),
        ScanScreen.route: (_) => const ScanScreen(),
        QueueScreen.route: (_) => const QueueScreen(),
        PrintScreen.route: (_) => const PrintScreen(),
      },
    );
  }
}
