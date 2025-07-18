import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/security/encryption_service.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Service for secure storage of sensitive data
class SecureStorageService {
  final EncryptionService _encryptionService;
  final FlutterSecureStorage _secureStorage;
  final SharedPreferences _preferences;
  
  // Storage keys
  static const String _sensitiveDataPrefix = 'secure_';
  static const String _encryptedDataPrefix = 'encrypted_';
  
  SecureStorageService({
    required EncryptionService encryptionService,
    required FlutterSecureStorage secureStorage,
    required SharedPreferences preferences,
  })  : _encryptionService = encryptionService,
        _secureStorage = secureStorage,
        _preferences = preferences;
  
  /// Store sensitive string data
  Future<Either<Failure, void>> storeSecureString({
    required String key,
    required String value,
    bool useSecureStorage = true,
  }) async {
    try {
      final storageKey = '$_sensitiveDataPrefix$key';
      
      if (useSecureStorage) {
        // Store directly in secure storage
        await _secureStorage.write(key: storageKey, value: value);
      } else {
        // Encrypt and store in shared preferences
        final encryptedResult = await _encryptionService.encryptString(value);
        
        return encryptedResult.fold(
          (failure) => Left(failure),
          (encrypted) {
            _preferences.setString('$_encryptedDataPrefix$key', encrypted);
            return const Right(null);
          },
        );
      }
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to store secure data: $e'));
    }
  }
  
  /// Retrieve sensitive string data
  Future<Either<Failure, String?>> getSecureString({
    required String key,
    bool useSecureStorage = true,
  }) async {
    try {
      final storageKey = '$_sensitiveDataPrefix$key';
      
      if (useSecureStorage) {
        // Retrieve from secure storage
        final value = await _secureStorage.read(key: storageKey);
        return Right(value);
      } else {
        // Retrieve and decrypt from shared preferences
        final encrypted = _preferences.getString('$_encryptedDataPrefix$key');
        if (encrypted == null) {
          return const Right(null);
        }
        
        final decryptedResult = await _encryptionService.decryptString(encrypted);
        return decryptedResult.fold(
          (failure) => Left(failure),
          (decrypted) => Right(decrypted),
        );
      }
    } catch (e) {
      return Left(SecurityFailure('Failed to retrieve secure data: $e'));
    }
  }
  
  /// Store sensitive JSON data
  Future<Either<Failure, void>> storeSecureJson({
    required String key,
    required Map<String, dynamic> value,
    bool useSecureStorage = true,
  }) async {
    try {
      final jsonString = json.encode(value);
      return storeSecureString(
        key: key,
        value: jsonString,
        useSecureStorage: useSecureStorage,
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to store secure JSON: $e'));
    }
  }
  
  /// Retrieve sensitive JSON data
  Future<Either<Failure, Map<String, dynamic>?>> getSecureJson({
    required String key,
    bool useSecureStorage = true,
  }) async {
    try {
      final stringResult = await getSecureString(
        key: key,
        useSecureStorage: useSecureStorage,
      );
      
      return stringResult.fold(
        (failure) => Left(failure),
        (value) {
          if (value == null) {
            return const Right(null);
          }
          
          final jsonData = json.decode(value) as Map<String, dynamic>;
          return Right(jsonData);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to retrieve secure JSON: $e'));
    }
  }
  
  /// Delete secure data
  Future<Either<Failure, void>> deleteSecureData({
    required String key,
    bool useSecureStorage = true,
  }) async {
    try {
      if (useSecureStorage) {
        await _secureStorage.delete(key: '$_sensitiveDataPrefix$key');
      } else {
        await _preferences.remove('$_encryptedDataPrefix$key');
      }
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to delete secure data: $e'));
    }
  }
  
  /// Store user credentials securely
  Future<Either<Failure, void>> storeCredentials({
    required String username,
    required String password,
  }) async {
    try {
      // Hash the password
      final passwordHashResult = await _encryptionService.hashPassword(password);
      
      return passwordHashResult.fold(
        (failure) => Left(failure),
        (passwordHash) async {
          // Store username and password hash
          final credentials = {
            'username': username,
            'passwordHash': passwordHash.hash,
            'salt': passwordHash.salt,
          };
          
          return storeSecureJson(
            key: 'user_credentials',
            value: credentials,
            useSecureStorage: true,
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to store credentials: $e'));
    }
  }
  
  /// Verify user credentials
  Future<Either<Failure, bool>> verifyCredentials({
    required String username,
    required String password,
  }) async {
    try {
      final credentialsResult = await getSecureJson(
        key: 'user_credentials',
        useSecureStorage: true,
      );
      
      return credentialsResult.fold(
        (failure) => Left(failure),
        (credentials) {
          if (credentials == null) {
            return const Right(false);
          }
          
          // Check username
          if (credentials['username'] != username) {
            return const Right(false);
          }
          
          // Verify password
          final passwordHash = PasswordHash(
            hash: credentials['passwordHash'],
            salt: credentials['salt'],
          );
          
          final isValid = _encryptionService.verifyPassword(
            password,
            passwordHash,
          );
          
          return Right(isValid);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to verify credentials: $e'));
    }
  }
  
  /// Store API tokens securely
  Future<Either<Failure, void>> storeApiToken({
    required String tokenName,
    required String token,
    DateTime? expiresAt,
  }) async {
    try {
      final tokenData = {
        'token': token,
        'createdAt': DateTime.now().toIso8601String(),
        'expiresAt': expiresAt?.toIso8601String(),
      };
      
      return storeSecureJson(
        key: 'api_token_$tokenName',
        value: tokenData,
        useSecureStorage: true,
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to store API token: $e'));
    }
  }
  
  /// Retrieve API token
  Future<Either<Failure, ApiToken?>> getApiToken({
    required String tokenName,
  }) async {
    try {
      final tokenResult = await getSecureJson(
        key: 'api_token_$tokenName',
        useSecureStorage: true,
      );
      
      return tokenResult.fold(
        (failure) => Left(failure),
        (tokenData) {
          if (tokenData == null) {
            return const Right(null);
          }
          
          final apiToken = ApiToken(
            token: tokenData['token'],
            createdAt: DateTime.parse(tokenData['createdAt']),
            expiresAt: tokenData['expiresAt'] != null
                ? DateTime.parse(tokenData['expiresAt'])
                : null,
          );
          
          // Check if token is expired
          if (apiToken.isExpired) {
            // Delete expired token
            deleteSecureData(
              key: 'api_token_$tokenName',
              useSecureStorage: true,
            );
            return const Right(null);
          }
          
          return Right(apiToken);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to retrieve API token: $e'));
    }
  }
  
  /// Store encrypted user preferences
  Future<Either<Failure, void>> storeSecurePreferences({
    required Map<String, dynamic> preferences,
  }) async {
    return storeSecureJson(
      key: 'user_preferences',
      value: preferences,
      useSecureStorage: false, // Use encrypted shared preferences
    );
  }
  
  /// Retrieve encrypted user preferences
  Future<Either<Failure, Map<String, dynamic>?>> getSecurePreferences() async {
    return getSecureJson(
      key: 'user_preferences',
      useSecureStorage: false,
    );
  }
  
  /// Clear all secure data (use with caution!)
  Future<Either<Failure, void>> clearAllSecureData() async {
    try {
      // Clear secure storage
      await _secureStorage.deleteAll();
      
      // Clear encrypted data from shared preferences
      final keys = _preferences.getKeys();
      for (final key in keys) {
        if (key.startsWith(_encryptedDataPrefix)) {
          await _preferences.remove(key);
        }
      }
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to clear secure data: $e'));
    }
  }
  
  /// Get all secure data keys
  Future<Either<Failure, List<String>>> getSecureDataKeys() async {
    try {
      // Get keys from secure storage
      final secureKeys = await _secureStorage.readAll();
      
      // Get encrypted keys from shared preferences
      final prefKeys = _preferences.getKeys()
          .where((key) => key.startsWith(_encryptedDataPrefix))
          .map((key) => key.replaceFirst(_encryptedDataPrefix, ''))
          .toList();
      
      final allKeys = [
        ...secureKeys.keys.map((key) => key.replaceFirst(_sensitiveDataPrefix, '')),
        ...prefKeys,
      ];
      
      return Right(allKeys.toSet().toList());
    } catch (e) {
      return Left(SecurityFailure('Failed to get secure data keys: $e'));
    }
  }
}

/// API token model
class ApiToken {
  final String token;
  final DateTime createdAt;
  final DateTime? expiresAt;
  
  const ApiToken({
    required this.token,
    required this.createdAt,
    this.expiresAt,
  });
  
  bool get isExpired {
    if (expiresAt == null) return false;
    return DateTime.now().isAfter(expiresAt!);
  }
  
  Duration get timeUntilExpiry {
    if (expiresAt == null) return const Duration(days: 365);
    return expiresAt!.difference(DateTime.now());
  }
}