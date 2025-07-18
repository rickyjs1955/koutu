import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/security/encryption_service.dart';
import 'package:koutu/services/security/secure_storage_service.dart';
import 'package:koutu/services/security/biometric_service.dart';
import 'package:koutu/services/security/data_sanitization_service.dart';
import 'package:koutu/services/security/secure_backup_service.dart';
import 'package:koutu/services/security/privacy_service.dart';
import 'package:koutu/services/security/secure_sharing_service.dart';
import 'package:koutu/services/security/compliance_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Provider for encryption service
final encryptionServiceProvider = FutureProvider<EncryptionService>((ref) async {
  return EncryptionService.getInstance();
});

/// Provider for secure storage
final secureStorageProvider = Provider<FlutterSecureStorage>((ref) {
  return const FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
    iOptions: IOSOptions(
      accessibility: IOSAccessibility.first_unlock_this_device,
    ),
  );
});

/// Provider for secure storage service
final secureStorageServiceProvider = FutureProvider<SecureStorageService>((ref) async {
  final encryptionService = await ref.watch(encryptionServiceProvider.future);
  final secureStorage = ref.watch(secureStorageProvider);
  final preferences = await SharedPreferences.getInstance();
  
  return SecureStorageService(
    encryptionService: encryptionService,
    secureStorage: secureStorage,
    preferences: preferences,
  );
});

/// Provider for biometric service
final biometricServiceProvider = FutureProvider<BiometricService>((ref) async {
  final secureStorageService = await ref.watch(secureStorageServiceProvider.future);
  final preferences = await SharedPreferences.getInstance();
  final localAuth = LocalAuthentication();
  
  return BiometricService(
    localAuth: localAuth,
    secureStorage: secureStorageService,
    preferences: preferences,
  );
});

/// Provider for data sanitization service
final dataSanitizationServiceProvider = Provider<DataSanitizationService>((ref) {
  return DataSanitizationService();
});

/// Provider for secure backup service
final secureBackupServiceProvider = FutureProvider<SecureBackupService>((ref) async {
  final encryptionService = await ref.watch(encryptionServiceProvider.future);
  final dataSanitizationService = ref.watch(dataSanitizationServiceProvider);
  final preferences = await SharedPreferences.getInstance();
  
  return SecureBackupService(
    encryptionService: encryptionService,
    sanitizationService: dataSanitizationService,
    database: AppDatabase.instance,
    preferences: preferences,
  );
});

/// Provider for privacy service
final privacyServiceProvider = FutureProvider<PrivacyService>((ref) async {
  final dataSanitizationService = ref.watch(dataSanitizationServiceProvider);
  final secureStorageService = await ref.watch(secureStorageServiceProvider.future);
  final preferences = await SharedPreferences.getInstance();
  
  return PrivacyService(
    sanitizationService: dataSanitizationService,
    secureStorage: secureStorageService,
    database: AppDatabase.instance,
    preferences: preferences,
  );
});

/// Provider for secure sharing service
final secureSharingServiceProvider = FutureProvider<SecureSharingService>((ref) async {
  final encryptionService = await ref.watch(encryptionServiceProvider.future);
  final secureStorageService = await ref.watch(secureStorageServiceProvider.future);
  final biometricService = await ref.watch(biometricServiceProvider.future);
  final preferences = await SharedPreferences.getInstance();
  
  return SecureSharingService(
    encryptionService: encryptionService,
    secureStorage: secureStorageService,
    biometricService: biometricService,
    database: AppDatabase.instance,
    preferences: preferences,
  );
});

/// Provider for compliance service
final complianceServiceProvider = FutureProvider<ComplianceService>((ref) async {
  final privacyService = await ref.watch(privacyServiceProvider.future);
  final dataSanitizationService = ref.watch(dataSanitizationServiceProvider);
  final secureStorageService = await ref.watch(secureStorageServiceProvider.future);
  final preferences = await SharedPreferences.getInstance();
  
  return ComplianceService(
    privacyService: privacyService,
    sanitizationService: dataSanitizationService,
    secureStorage: secureStorageService,
    database: AppDatabase.instance,
    preferences: preferences,
  );
});

/// Provider for biometric capability
final biometricCapabilityProvider = FutureProvider<BiometricCapability>((ref) async {
  final biometricService = await ref.watch(biometricServiceProvider.future);
  final result = await biometricService.checkBiometricCapability();
  
  return result.fold(
    (failure) => BiometricCapability(
      isAvailable: false,
      availableTypes: [],
      reason: failure.message,
    ),
    (capability) => capability,
  );
});

/// Provider for biometric settings
final biometricSettingsProvider = FutureProvider<BiometricSettings>((ref) async {
  final biometricService = await ref.watch(biometricServiceProvider.future);
  return biometricService.getSettings();
});

/// Provider for app lock state
final appLockStateProvider = StateNotifierProvider<AppLockStateNotifier, AppLockState>((ref) {
  return AppLockStateNotifier();
});

/// App lock state notifier
class AppLockStateNotifier extends StateNotifier<AppLockState> {
  AppLockStateNotifier() : super(AppLockState.unlocked);
  
  void lock() {
    state = AppLockState.locked;
  }
  
  void unlock() {
    state = AppLockState.unlocked;
  }
  
  void setAuthenticating() {
    state = AppLockState.authenticating;
  }
}

/// App lock state
enum AppLockState {
  locked,
  unlocked,
  authenticating,
}