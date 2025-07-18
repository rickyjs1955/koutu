/// Storage keys for local storage and secure storage
class StorageKeys {
  StorageKeys._();

  // Secure storage keys
  static const String authToken = 'auth_token';
  static const String refreshToken = 'refresh_token';
  static const String userId = 'user_id';
  static const String userEmail = 'user_email';
  static const String biometricEnabled = 'biometric_enabled';

  // Shared preferences keys
  static const String isFirstLaunch = 'is_first_launch';
  static const String hasSeenOnboarding = 'has_seen_onboarding';
  static const String selectedTheme = 'selected_theme';
  static const String languageCode = 'language_code';
  static const String lastSyncTime = 'last_sync_time';
  static const String offlineMode = 'offline_mode';
  
  // Cache keys
  static const String cachedUserProfile = 'cached_user_profile';
  static const String cachedWardrobes = 'cached_wardrobes';
  static const String cachedGarments = 'cached_garments';
  
  // Settings keys
  static const String notificationsEnabled = 'notifications_enabled';
  static const String autoBackupEnabled = 'auto_backup_enabled';
  static const String imageQuality = 'image_quality';
  static const String defaultWardrobe = 'default_wardrobe';
}