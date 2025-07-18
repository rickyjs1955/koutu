import 'package:injectable/injectable.dart';

/// Cache policy configuration
@lazySingleton
class CachePolicy {
  // Cache durations
  static const Duration userCacheDuration = Duration(hours: 24);
  static const Duration wardrobeCacheDuration = Duration(hours: 12);
  static const Duration garmentCacheDuration = Duration(hours: 6);
  static const Duration imageCacheDuration = Duration(days: 7);
  static const Duration searchCacheDuration = Duration(minutes: 30);

  // Cache size limits
  static const int maxCachedUsers = 10;
  static const int maxCachedWardrobes = 50;
  static const int maxCachedGarments = 500;
  static const int maxCachedImages = 1000;

  // Sync intervals
  static const Duration syncInterval = Duration(minutes: 15);
  static const Duration forceSyncInterval = Duration(hours: 24);

  /// Check if cache is expired
  bool isCacheExpired(DateTime? lastSyncedAt, Duration cacheDuration) {
    if (lastSyncedAt == null) return true;
    return DateTime.now().difference(lastSyncedAt) > cacheDuration;
  }

  /// Get cache duration for entity type
  Duration getCacheDuration(String entityType) {
    switch (entityType) {
      case 'user':
        return userCacheDuration;
      case 'wardrobe':
        return wardrobeCacheDuration;
      case 'garment':
        return garmentCacheDuration;
      case 'image':
        return imageCacheDuration;
      case 'search':
        return searchCacheDuration;
      default:
        return const Duration(hours: 1);
    }
  }

  /// Check if sync is needed
  bool shouldSync(DateTime? lastSyncedAt) {
    if (lastSyncedAt == null) return true;
    return DateTime.now().difference(lastSyncedAt) > syncInterval;
  }

  /// Check if force sync is needed
  bool shouldForceSync(DateTime? lastSyncedAt) {
    if (lastSyncedAt == null) return true;
    return DateTime.now().difference(lastSyncedAt) > forceSyncInterval;
  }

  /// Get expiration time for entity
  DateTime getExpirationTime(String entityType) {
    return DateTime.now().add(getCacheDuration(entityType));
  }

  /// Calculate next sync time
  DateTime getNextSyncTime() {
    return DateTime.now().add(syncInterval);
  }

  /// Get retry delay for failed operations
  Duration getRetryDelay(int failureCount) {
    // Exponential backoff with max delay of 1 hour
    final delay = Duration(seconds: 30 * (1 << failureCount));
    const maxDelay = Duration(hours: 1);
    return delay > maxDelay ? maxDelay : delay;
  }
}