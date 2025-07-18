import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/routing/route_paths.dart';
import 'package:koutu/presentation/screens/splash/splash_screen.dart';

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
        // Additional routes will be added here
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