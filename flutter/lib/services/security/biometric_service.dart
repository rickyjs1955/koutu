import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/security/secure_storage_service.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Service for biometric authentication and data protection
class BiometricService {
  final LocalAuthentication _localAuth;
  final SecureStorageService _secureStorage;
  final SharedPreferences _preferences;
  
  // Settings keys
  static const String _biometricEnabledKey = 'biometric_enabled';
  static const String _biometricTypeKey = 'biometric_type';
  static const String _fallbackEnabledKey = 'fallback_enabled';
  static const String _autoLockEnabledKey = 'auto_lock_enabled';
  static const String _autoLockDurationKey = 'auto_lock_duration';
  static const String _lastAuthTimeKey = 'last_auth_time';
  
  // Biometric-protected data prefix
  static const String _biometricDataPrefix = 'biometric_protected_';
  
  BiometricService({
    required LocalAuthentication localAuth,
    required SecureStorageService secureStorage,
    required SharedPreferences preferences,
  })  : _localAuth = localAuth,
        _secureStorage = secureStorage,
        _preferences = preferences;
  
  /// Check if biometric authentication is available
  Future<Either<Failure, BiometricCapability>> checkBiometricCapability() async {
    try {
      // Check if device supports biometrics
      final isDeviceSupported = await _localAuth.isDeviceSupported();
      if (!isDeviceSupported) {
        return const Right(BiometricCapability(
          isAvailable: false,
          availableTypes: [],
          reason: 'Device does not support biometric authentication',
        ));
      }
      
      // Check if biometrics are enrolled
      final canCheckBiometrics = await _localAuth.canCheckBiometrics;
      if (!canCheckBiometrics) {
        return const Right(BiometricCapability(
          isAvailable: false,
          availableTypes: [],
          reason: 'No biometrics are enrolled on this device',
        ));
      }
      
      // Get available biometric types
      final availableBiometrics = await _localAuth.getAvailableBiometrics();
      
      return Right(BiometricCapability(
        isAvailable: true,
        availableTypes: availableBiometrics,
        reason: null,
      ));
    } on PlatformException catch (e) {
      return Left(SecurityFailure('Failed to check biometric capability: ${e.message}'));
    } catch (e) {
      return Left(SecurityFailure('Failed to check biometric capability: $e'));
    }
  }
  
  /// Authenticate using biometrics
  Future<Either<Failure, bool>> authenticate({
    required String reason,
    bool useErrorDialogs = true,
    bool stickyAuth = true,
    bool biometricOnly = false,
  }) async {
    try {
      // Check if biometric is enabled
      if (!isBiometricEnabled()) {
        return Left(SecurityFailure('Biometric authentication is not enabled'));
      }
      
      // Check capability first
      final capabilityResult = await checkBiometricCapability();
      
      return await capabilityResult.fold(
        (failure) => Left(failure),
        (capability) async {
          if (!capability.isAvailable) {
            return Left(SecurityFailure(
              capability.reason ?? 'Biometric authentication not available',
            ));
          }
          
          // Perform authentication
          final authenticated = await _localAuth.authenticate(
            localizedReason: reason,
            options: AuthenticationOptions(
              useErrorDialogs: useErrorDialogs,
              stickyAuth: stickyAuth,
              biometricOnly: biometricOnly,
            ),
          );
          
          if (authenticated) {
            // Update last authentication time
            await _preferences.setString(
              _lastAuthTimeKey,
              DateTime.now().toIso8601String(),
            );
          }
          
          return Right(authenticated);
        },
      );
    } on PlatformException catch (e) {
      if (e.code == 'NotAvailable') {
        return Left(SecurityFailure('Biometric authentication not available'));
      } else if (e.code == 'NotEnrolled') {
        return Left(SecurityFailure('No biometrics enrolled'));
      } else if (e.code == 'LockedOut' || e.code == 'PermanentlyLockedOut') {
        return Left(SecurityFailure('Biometric authentication is locked'));
      }
      
      return Left(SecurityFailure('Authentication failed: ${e.message}'));
    } catch (e) {
      return Left(SecurityFailure('Authentication failed: $e'));
    }
  }
  
  /// Enable biometric authentication
  Future<Either<Failure, void>> enableBiometric({
    required String setupReason,
  }) async {
    try {
      // First authenticate to enable
      final authResult = await authenticate(
        reason: setupReason,
        biometricOnly: false,
      );
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Save biometric settings
          await _preferences.setBool(_biometricEnabledKey, true);
          
          // Get and save biometric type
          final biometrics = await _localAuth.getAvailableBiometrics();
          if (biometrics.isNotEmpty) {
            await _preferences.setString(
              _biometricTypeKey,
              biometrics.first.toString(),
            );
          }
          
          return const Right(null);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to enable biometric: $e'));
    }
  }
  
  /// Disable biometric authentication
  Future<Either<Failure, void>> disableBiometric({
    required String reason,
  }) async {
    try {
      // Authenticate before disabling
      final authResult = await authenticate(reason: reason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Disable biometric
          await _preferences.setBool(_biometricEnabledKey, false);
          
          // Clear biometric-protected data if needed
          // (Optional based on security requirements)
          
          return const Right(null);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to disable biometric: $e'));
    }
  }
  
  /// Check if biometric is enabled
  bool isBiometricEnabled() {
    return _preferences.getBool(_biometricEnabledKey) ?? false;
  }
  
  /// Store data with biometric protection
  Future<Either<Failure, void>> storeBiometricProtectedData({
    required String key,
    required Map<String, dynamic> data,
    required String authReason,
  }) async {
    try {
      // Authenticate first
      final authResult = await authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Store data with biometric protection flag
          final protectedData = {
            ...data,
            '_biometricProtected': true,
            '_protectedAt': DateTime.now().toIso8601String(),
          };
          
          return _secureStorage.storeSecureJson(
            key: '$_biometricDataPrefix$key',
            value: protectedData,
            useSecureStorage: true,
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to store biometric-protected data: $e'));
    }
  }
  
  /// Retrieve data with biometric protection
  Future<Either<Failure, Map<String, dynamic>?>> retrieveBiometricProtectedData({
    required String key,
    required String authReason,
  }) async {
    try {
      // Authenticate first
      final authResult = await authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Retrieve data
          final dataResult = await _secureStorage.getSecureJson(
            key: '$_biometricDataPrefix$key',
            useSecureStorage: true,
          );
          
          return dataResult.fold(
            (failure) => Left(failure),
            (data) {
              if (data == null) {
                return const Right(null);
              }
              
              // Remove protection metadata
              data.remove('_biometricProtected');
              data.remove('_protectedAt');
              
              return Right(data);
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to retrieve biometric-protected data: $e'));
    }
  }
  
  /// Delete biometric-protected data
  Future<Either<Failure, void>> deleteBiometricProtectedData({
    required String key,
    required String authReason,
  }) async {
    try {
      // Authenticate first
      final authResult = await authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          return _secureStorage.deleteSecureData(
            key: '$_biometricDataPrefix$key',
            useSecureStorage: true,
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to delete biometric-protected data: $e'));
    }
  }
  
  /// Configure auto-lock settings
  Future<Either<Failure, void>> configureAutoLock({
    required bool enabled,
    Duration lockDuration = const Duration(minutes: 5),
  }) async {
    try {
      await _preferences.setBool(_autoLockEnabledKey, enabled);
      await _preferences.setInt(
        _autoLockDurationKey,
        lockDuration.inMinutes,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to configure auto-lock: $e'));
    }
  }
  
  /// Check if app should be locked based on auto-lock settings
  bool shouldAutoLock() {
    if (!_preferences.getBool(_autoLockEnabledKey) ?? false) {
      return false;
    }
    
    final lastAuthTimeStr = _preferences.getString(_lastAuthTimeKey);
    if (lastAuthTimeStr == null) {
      return true;
    }
    
    final lastAuthTime = DateTime.parse(lastAuthTimeStr);
    final lockDurationMinutes = _preferences.getInt(_autoLockDurationKey) ?? 5;
    final lockDuration = Duration(minutes: lockDurationMinutes);
    
    return DateTime.now().difference(lastAuthTime) > lockDuration;
  }
  
  /// Enable fallback authentication (PIN/Password)
  Future<Either<Failure, void>> enableFallbackAuth({
    required String pin,
    required String authReason,
  }) async {
    try {
      // Authenticate with biometric first
      final authResult = await authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Store PIN securely
          final storeResult = await _secureStorage.storeCredentials(
            username: 'fallback_user',
            password: pin,
          );
          
          return storeResult.fold(
            (failure) => Left(failure),
            (_) async {
              await _preferences.setBool(_fallbackEnabledKey, true);
              return const Right(null);
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to enable fallback auth: $e'));
    }
  }
  
  /// Authenticate with fallback (PIN)
  Future<Either<Failure, bool>> authenticateWithFallback({
    required String pin,
  }) async {
    try {
      if (!_preferences.getBool(_fallbackEnabledKey) ?? false) {
        return Left(SecurityFailure('Fallback authentication not enabled'));
      }
      
      final verifyResult = await _secureStorage.verifyCredentials(
        username: 'fallback_user',
        password: pin,
      );
      
      return verifyResult.fold(
        (failure) => Left(failure),
        (isValid) async {
          if (isValid) {
            // Update last authentication time
            await _preferences.setString(
              _lastAuthTimeKey,
              DateTime.now().toIso8601String(),
            );
          }
          
          return Right(isValid);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Fallback authentication failed: $e'));
    }
  }
  
  /// Get biometric settings
  BiometricSettings getSettings() {
    return BiometricSettings(
      isEnabled: isBiometricEnabled(),
      biometricType: _preferences.getString(_biometricTypeKey),
      isFallbackEnabled: _preferences.getBool(_fallbackEnabledKey) ?? false,
      isAutoLockEnabled: _preferences.getBool(_autoLockEnabledKey) ?? false,
      autoLockDuration: Duration(
        minutes: _preferences.getInt(_autoLockDurationKey) ?? 5,
      ),
    );
  }
  
  /// Clear all biometric data and settings
  Future<Either<Failure, void>> clearAllBiometricData({
    required String authReason,
  }) async {
    try {
      // Authenticate first
      final authResult = await authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Clear settings
          await _preferences.remove(_biometricEnabledKey);
          await _preferences.remove(_biometricTypeKey);
          await _preferences.remove(_fallbackEnabledKey);
          await _preferences.remove(_autoLockEnabledKey);
          await _preferences.remove(_autoLockDurationKey);
          await _preferences.remove(_lastAuthTimeKey);
          
          // Clear biometric-protected data
          final keysResult = await _secureStorage.getSecureDataKeys();
          
          return keysResult.fold(
            (failure) => Left(failure),
            (keys) async {
              for (final key in keys) {
                if (key.startsWith(_biometricDataPrefix)) {
                  await _secureStorage.deleteSecureData(
                    key: key,
                    useSecureStorage: true,
                  );
                }
              }
              
              return const Right(null);
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to clear biometric data: $e'));
    }
  }
}

/// Biometric capability information
class BiometricCapability {
  final bool isAvailable;
  final List<BiometricType> availableTypes;
  final String? reason;
  
  const BiometricCapability({
    required this.isAvailable,
    required this.availableTypes,
    this.reason,
  });
}

/// Biometric settings
class BiometricSettings {
  final bool isEnabled;
  final String? biometricType;
  final bool isFallbackEnabled;
  final bool isAutoLockEnabled;
  final Duration autoLockDuration;
  
  const BiometricSettings({
    required this.isEnabled,
    this.biometricType,
    required this.isFallbackEnabled,
    required this.isAutoLockEnabled,
    required this.autoLockDuration,
  });
}