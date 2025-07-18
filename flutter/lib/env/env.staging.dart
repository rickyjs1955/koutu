import 'package:koutu/env/env.dart';

/// Staging environment configuration
class StagingEnv extends Env {
  @override
  String get baseUrl => 'https://staging-api.koutu.app';

  @override
  String get apiVersion => 'api/v1';

  @override
  String get wsUrl => 'wss://staging-api.koutu.app';

  @override
  String get environment => 'staging';

  @override
  bool get isDebug => true;

  @override
  int get apiTimeout => 30;

  @override
  int get maxRetryAttempts => 3;

  @override
  int get maxImageSizeMB => 8;

  @override
  int get cacheDurationHours => 6;

  @override
  bool get analyticsEnabled => true;

  @override
  bool get crashReportingEnabled => true;

  @override
  String? get apiKey => const String.fromEnvironment('STAGING_API_KEY');

  @override
  String? get encryptionKey => const String.fromEnvironment('STAGING_ENCRYPTION_KEY');

  @override
  Map<String, bool> get featureFlags => {
        'enableBiometricAuth': true,
        'enableSocialLogin': true,
        'enableOfflineMode': true,
        'enableImageCompression': true,
        'enableBackgroundRemoval': true,
        'enableOutfitBuilder': true,
        'enableAnalytics': true,
        'enableCrashReporting': true,
        'showDebugInfo': true,
      };
}