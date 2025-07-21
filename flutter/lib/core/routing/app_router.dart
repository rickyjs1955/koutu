import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/routing/route_paths.dart';
import 'package:koutu/presentation/screens/splash/splash_screen.dart';
import 'package:koutu/presentation/screens/auth/login_screen.dart';
import 'package:koutu/presentation/screens/auth/register_screen.dart';
import 'package:koutu/presentation/screens/auth/forgot_password_screen.dart';
import 'package:koutu/presentation/screens/home/home_screen.dart';
import 'package:koutu/presentation/screens/garment/garment_capture_screen.dart';
import 'package:koutu/presentation/screens/wardrobe/digital_wardrobe_screen.dart';
import 'package:koutu/presentation/screens/outfit/ai_outfit_builder_screen.dart';
import 'package:koutu/presentation/screens/analytics/wardrobe_analytics_dashboard.dart';

@singleton
class AppRouter {
  GoRouter config({Listenable? reevaluateListenable}) {
    return GoRouter(
      initialLocation: RoutePaths.splash,
      debugLogDiagnostics: true,
      refreshListenable: reevaluateListenable,
      routes: [
        GoRoute(
          path: RoutePaths.splash,
          name: RoutePaths.splash,
          builder: (context, state) => const SplashScreen(),
        ),
        GoRoute(
          path: RoutePaths.login,
          name: RoutePaths.login,
          builder: (context, state) => const LoginScreen(),
        ),
        GoRoute(
          path: RoutePaths.register,
          name: RoutePaths.register,
          builder: (context, state) => const RegisterScreen(),
        ),
        GoRoute(
          path: RoutePaths.forgotPassword,
          name: RoutePaths.forgotPassword,
          builder: (context, state) => const ForgotPasswordScreen(),
        ),
        GoRoute(
          path: RoutePaths.home,
          name: RoutePaths.home,
          builder: (context, state) => const HomeScreen(),
        ),
        // Garment routes
        GoRoute(
          path: '/garment/capture',
          name: 'garment-capture',
          builder: (context, state) => const GarmentCaptureScreen(),
        ),
        // Wardrobe routes
        GoRoute(
          path: '/wardrobe',
          name: 'wardrobe',
          builder: (context, state) => const DigitalWardrobeScreen(),
        ),
        // Outfit routes
        GoRoute(
          path: '/outfit/ai-builder',
          name: 'ai-outfit-builder',
          builder: (context, state) => const AIOutfitBuilderScreen(),
        ),
        // Analytics routes
        GoRoute(
          path: '/analytics',
          name: 'analytics',
          builder: (context, state) => const WardrobeAnalyticsDashboard(),
        ),
      ],
      errorBuilder: (context, state) => Scaffold(
        body: Center(
          child: Text(
            'Page not found: ${state.uri.path}',
            style: const TextStyle(fontSize: 16),
          ),
        ),
      ),
    );
  }
}