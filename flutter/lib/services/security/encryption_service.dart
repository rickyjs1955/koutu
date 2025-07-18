import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:math';

/// Service for end-to-end encryption of sensitive data
class EncryptionService {
  static const String _keyAlias = 'koutu_encryption_key';
  static const String _ivAlias = 'koutu_encryption_iv';
  static const String _saltAlias = 'koutu_encryption_salt';
  
  final FlutterSecureStorage _secureStorage;
  
  // Encryption instances
  late final Key _encryptionKey;
  late final IV _iv;
  late final Encrypter _encrypter;
  
  // Singleton instance
  static EncryptionService? _instance;
  
  EncryptionService._({
    required FlutterSecureStorage secureStorage,
  }) : _secureStorage = secureStorage;
  
  /// Get singleton instance
  static Future<EncryptionService> getInstance() async {
    if (_instance == null) {
      const secureStorage = FlutterSecureStorage(
        aOptions: AndroidOptions(
          encryptedSharedPreferences: true,
        ),
        iOptions: IOSOptions(
          accessibility: IOSAccessibility.first_unlock_this_device,
        ),
      );
      
      _instance = EncryptionService._(secureStorage: secureStorage);
      await _instance!._initialize();
    }
    
    return _instance!;
  }
  
  /// Initialize encryption service
  Future<void> _initialize() async {
    try {
      // Try to load existing key
      final existingKey = await _secureStorage.read(key: _keyAlias);
      final existingIv = await _secureStorage.read(key: _ivAlias);
      
      if (existingKey != null && existingIv != null) {
        // Use existing key and IV
        _encryptionKey = Key.fromBase64(existingKey);
        _iv = IV.fromBase64(existingIv);
      } else {
        // Generate new key and IV
        await _generateAndStoreKey();
      }
      
      // Initialize encrypter with AES
      _encrypter = Encrypter(AES(_encryptionKey));
    } catch (e) {
      throw Exception('Failed to initialize encryption service: $e');
    }
  }
  
  /// Generate and store encryption key
  Future<void> _generateAndStoreKey() async {
    // Generate random key (256-bit for AES-256)
    final key = Key.fromSecureRandom(32);
    final iv = IV.fromSecureRandom(16);
    
    // Store securely
    await _secureStorage.write(
      key: _keyAlias,
      value: key.base64,
    );
    await _secureStorage.write(
      key: _ivAlias,
      value: iv.base64,
    );
    
    _encryptionKey = key;
    _iv = iv;
  }
  
  /// Encrypt string data
  Future<Either<Failure, String>> encryptString(String plainText) async {
    try {
      if (plainText.isEmpty) {
        return const Right('');
      }
      
      final encrypted = _encrypter.encrypt(plainText, iv: _iv);
      return Right(encrypted.base64);
    } catch (e) {
      return Left(SecurityFailure('Failed to encrypt data: $e'));
    }
  }
  
  /// Decrypt string data
  Future<Either<Failure, String>> decryptString(String encryptedText) async {
    try {
      if (encryptedText.isEmpty) {
        return const Right('');
      }
      
      final encrypted = Encrypted.fromBase64(encryptedText);
      final decrypted = _encrypter.decrypt(encrypted, iv: _iv);
      return Right(decrypted);
    } catch (e) {
      return Left(SecurityFailure('Failed to decrypt data: $e'));
    }
  }
  
  /// Encrypt JSON data
  Future<Either<Failure, String>> encryptJson(Map<String, dynamic> data) async {
    try {
      final jsonString = json.encode(data);
      return encryptString(jsonString);
    } catch (e) {
      return Left(SecurityFailure('Failed to encrypt JSON: $e'));
    }
  }
  
  /// Decrypt JSON data
  Future<Either<Failure, Map<String, dynamic>>> decryptJson(
    String encryptedText,
  ) async {
    try {
      final decryptedResult = await decryptString(encryptedText);
      
      return decryptedResult.fold(
        (failure) => Left(failure),
        (decrypted) {
          final data = json.decode(decrypted) as Map<String, dynamic>;
          return Right(data);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to decrypt JSON: $e'));
    }
  }
  
  /// Encrypt binary data
  Future<Either<Failure, Uint8List>> encryptBytes(Uint8List plainBytes) async {
    try {
      final plainText = base64Encode(plainBytes);
      final encryptedResult = await encryptString(plainText);
      
      return encryptedResult.fold(
        (failure) => Left(failure),
        (encrypted) => Right(Uint8List.fromList(encrypted.codeUnits)),
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to encrypt bytes: $e'));
    }
  }
  
  /// Decrypt binary data
  Future<Either<Failure, Uint8List>> decryptBytes(Uint8List encryptedBytes) async {
    try {
      final encryptedText = String.fromCharCodes(encryptedBytes);
      final decryptedResult = await decryptString(encryptedText);
      
      return decryptedResult.fold(
        (failure) => Left(failure),
        (decrypted) => Right(base64Decode(decrypted)),
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to decrypt bytes: $e'));
    }
  }
  
  /// Generate secure hash of data
  String generateHash(String data) {
    final bytes = utf8.encode(data);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }
  
  /// Generate secure password hash with salt
  Future<Either<Failure, PasswordHash>> hashPassword(String password) async {
    try {
      // Generate salt
      final salt = _generateSalt();
      
      // Create hash with salt
      final saltedPassword = password + salt;
      final hash = generateHash(saltedPassword);
      
      return Right(PasswordHash(
        hash: hash,
        salt: salt,
      ));
    } catch (e) {
      return Left(SecurityFailure('Failed to hash password: $e'));
    }
  }
  
  /// Verify password against hash
  bool verifyPassword(String password, PasswordHash passwordHash) {
    final saltedPassword = password + passwordHash.salt;
    final hash = generateHash(saltedPassword);
    return hash == passwordHash.hash;
  }
  
  /// Generate random salt
  String _generateSalt() {
    final random = Random.secure();
    final values = List<int>.generate(32, (_) => random.nextInt(256));
    return base64Encode(values);
  }
  
  /// Rotate encryption keys
  Future<Either<Failure, void>> rotateKeys() async {
    try {
      // Generate new keys
      await _generateAndStoreKey();
      
      // Re-initialize encrypter
      _encrypter = Encrypter(AES(_encryptionKey));
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to rotate keys: $e'));
    }
  }
  
  /// Export encryption key (for backup purposes)
  Future<Either<Failure, EncryptionKeyBackup>> exportKey(String password) async {
    try {
      // Encrypt the key with password
      final passwordHashResult = await hashPassword(password);
      
      return passwordHashResult.fold(
        (failure) => Left(failure),
        (passwordHash) {
          // Use password hash as encryption key for backup
          final backupKey = Key.fromBase64(
            base64Encode(utf8.encode(passwordHash.hash.substring(0, 32))),
          );
          final backupIv = IV.fromBase64(
            base64Encode(utf8.encode(passwordHash.salt.substring(0, 16))),
          );
          
          final backupEncrypter = Encrypter(AES(backupKey));
          
          // Encrypt the actual key
          final encryptedKey = backupEncrypter.encrypt(
            _encryptionKey.base64,
            iv: backupIv,
          );
          final encryptedIv = backupEncrypter.encrypt(
            _iv.base64,
            iv: backupIv,
          );
          
          return Right(EncryptionKeyBackup(
            encryptedKey: encryptedKey.base64,
            encryptedIv: encryptedIv.base64,
            salt: passwordHash.salt,
            createdAt: DateTime.now(),
          ));
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to export key: $e'));
    }
  }
  
  /// Import encryption key from backup
  Future<Either<Failure, void>> importKey(
    EncryptionKeyBackup backup,
    String password,
  ) async {
    try {
      // Recreate password hash
      final saltedPassword = password + backup.salt;
      final hash = generateHash(saltedPassword);
      
      // Use password hash as decryption key
      final backupKey = Key.fromBase64(
        base64Encode(utf8.encode(hash.substring(0, 32))),
      );
      final backupIv = IV.fromBase64(
        base64Encode(utf8.encode(backup.salt.substring(0, 16))),
      );
      
      final backupEncrypter = Encrypter(AES(backupKey));
      
      // Decrypt the keys
      final decryptedKey = backupEncrypter.decrypt(
        Encrypted.fromBase64(backup.encryptedKey),
        iv: backupIv,
      );
      final decryptedIv = backupEncrypter.decrypt(
        Encrypted.fromBase64(backup.encryptedIv),
        iv: backupIv,
      );
      
      // Store decrypted keys
      await _secureStorage.write(key: _keyAlias, value: decryptedKey);
      await _secureStorage.write(key: _ivAlias, value: decryptedIv);
      
      // Re-initialize
      _encryptionKey = Key.fromBase64(decryptedKey);
      _iv = IV.fromBase64(decryptedIv);
      _encrypter = Encrypter(AES(_encryptionKey));
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to import key: $e'));
    }
  }
  
  /// Clear all encryption data (use with caution!)
  Future<Either<Failure, void>> clearEncryptionData() async {
    try {
      await _secureStorage.delete(key: _keyAlias);
      await _secureStorage.delete(key: _ivAlias);
      await _secureStorage.delete(key: _saltAlias);
      
      // Re-initialize with new keys
      await _generateAndStoreKey();
      _encrypter = Encrypter(AES(_encryptionKey));
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to clear encryption data: $e'));
    }
  }
}

/// Password hash with salt
class PasswordHash {
  final String hash;
  final String salt;
  
  const PasswordHash({
    required this.hash,
    required this.salt,
  });
  
  Map<String, dynamic> toJson() => {
    'hash': hash,
    'salt': salt,
  };
  
  factory PasswordHash.fromJson(Map<String, dynamic> json) {
    return PasswordHash(
      hash: json['hash'],
      salt: json['salt'],
    );
  }
}

/// Encryption key backup
class EncryptionKeyBackup {
  final String encryptedKey;
  final String encryptedIv;
  final String salt;
  final DateTime createdAt;
  
  const EncryptionKeyBackup({
    required this.encryptedKey,
    required this.encryptedIv,
    required this.salt,
    required this.createdAt,
  });
  
  Map<String, dynamic> toJson() => {
    'encryptedKey': encryptedKey,
    'encryptedIv': encryptedIv,
    'salt': salt,
    'createdAt': createdAt.toIso8601String(),
  };
  
  factory EncryptionKeyBackup.fromJson(Map<String, dynamic> json) {
    return EncryptionKeyBackup(
      encryptedKey: json['encryptedKey'],
      encryptedIv: json['encryptedIv'],
      salt: json['salt'],
      createdAt: DateTime.parse(json['createdAt']),
    );
  }
}

/// Security failure
class SecurityFailure extends Failure {
  const SecurityFailure(String message) : super(message);
}