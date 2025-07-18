import 'package:koutu/env/env.dart';

/// Production environment configuration
class ProdEnv extends Env {
  @override
  String get baseUrl => 'https://api.koutu.app';

  @override
  String get apiVersion => 'api/v1';

  @override
  String get wsUrl => 'wss://api.koutu.app';

  @override
  String get environment => 'production';

  @override
  bool get isDebug => false;

  @override
  int get apiTimeout => 20;

  @override
  int get maxRetryAttempts => 2;

  @override
  int get maxImageSizeMB => 5;

  @override
  int get cacheDurationHours => 24;

  @override
  bool get analyticsEnabled => true;

  @override
  bool get crashReportingEnabled => true;

  @override
  String? get apiKey => const String.fromEnvironment('PROD_API_KEY');

  @override
  String? get encryptionKey => const String.fromEnvironment('PROD_ENCRYPTION_KEY');

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
        'showDebugInfo': false,
      };
}