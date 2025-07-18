import 'package:koutu/env/env.dev.dart';
import 'package:koutu/env/env.prod.dart';
import 'package:koutu/env/env.staging.dart';

/// Abstract class defining the environment configuration interface
abstract class Env {
  /// API base URL
  String get baseUrl;

  /// API version
  String get apiVersion;

  /// Full API URL
  String get apiUrl => '$baseUrl/$apiVersion';

  /// WebSocket URL
  String get wsUrl;

  /// Environment name
  String get environment;

  /// Debug mode flag
  bool get isDebug;

  /// API timeout in seconds
  int get apiTimeout;

  /// Maximum retry attempts for failed requests
  int get maxRetryAttempts;

  /// Image upload max size in MB
  int get maxImageSizeMB;

  /// Cache duration in hours
  int get cacheDurationHours;

  /// Analytics enabled flag
  bool get analyticsEnabled;

  /// Crash reporting enabled flag
  bool get crashReportingEnabled;

  /// Optional API key (if needed)
  String? get apiKey;

  /// Optional encryption key for secure storage
  String? get encryptionKey;

  /// Feature flags
  Map<String, bool> get featureFlags;

  /// Get the current environment based on build configuration
  static Env get current {
    const environment = String.fromEnvironment(
      'ENVIRONMENT',
      defaultValue: 'development',
    );

    switch (environment) {
      case 'development':
        return DevEnv();
      case 'staging':
        return StagingEnv();
      case 'production':
        return ProdEnv();
      default:
        return DevEnv();
    }
  }
}