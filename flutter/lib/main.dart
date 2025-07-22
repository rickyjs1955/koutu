import 'package:flutter/material.dart';
import 'package:koutu/presentation/screens/splash/enhanced_splash_screen.dart';
import 'package:koutu/presentation/screens/home/home_screen.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        brightness: Brightness.dark,
      ),
      home: const EnhancedSplashScreen(),
      routes: {
        '/home': (context) => const HomeScreen(),
      },
    );
  }
}