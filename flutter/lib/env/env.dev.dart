import 'package:koutu/env/env.dart';

/// Development environment configuration
class DevEnv extends Env {
  @override
  String get baseUrl => 'http://localhost:3000';

  @override
  String get apiVersion => 'api/v1';

  @override
  String get wsUrl => 'ws://localhost:3000';

  @override
  String get environment => 'development';

  @override
  bool get isDebug => true;

  @override
  int get apiTimeout => 30;

  @override
  int get maxRetryAttempts => 3;

  @override
  int get maxImageSizeMB => 10;

  @override
  int get cacheDurationHours => 1;

  @override
  bool get analyticsEnabled => false;

  @override
  bool get crashReportingEnabled => false;

  @override
  String? get apiKey => 'dev-api-key-12345';

  @override
  String? get encryptionKey => 'dev-encryption-key-67890';

  @override
  Map<String, bool> get featureFlags => {
        'enableBiometricAuth': true,
        'enableSocialLogin': false,
        'enableOfflineMode': true,
        'enableImageCompression': true,
        'enableBackgroundRemoval': false,
        'enableOutfitBuilder': true,
        'enableAnalytics': false,
        'enableCrashReporting': false,
        'showDebugInfo': true,
      };
}