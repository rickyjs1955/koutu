import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/security/encryption_service.dart';
import 'package:koutu/services/security/secure_storage_service.dart';
import 'package:koutu/services/security/biometric_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

/// Service for secure sharing with access controls
class SecureSharingService {
  final EncryptionService _encryptionService;
  final SecureStorageService _secureStorage;
  final BiometricService _biometricService;
  final AppDatabase _database;
  final SharedPreferences _preferences;
  
  // Sharing settings keys
  static const String _sharingEnabledKey = 'sharing_enabled';
  static const String _shareHistoryKey = 'share_history';
  static const String _accessControlsKey = 'access_controls';
  static const String _sharedContentKey = 'shared_content_';
  static const String _shareTokensKey = 'share_tokens';
  
  SecureSharingService({
    required EncryptionService encryptionService,
    required SecureStorageService secureStorage,
    required BiometricService biometricService,
    required AppDatabase database,
    required SharedPreferences preferences,
  })  : _encryptionService = encryptionService,
        _secureStorage = secureStorage,
        _biometricService = biometricService,
        _database = database,
        _preferences = preferences;
  
  /// Create a secure share for content
  Future<Either<Failure, ShareResult>> createSecureShare({
    required String contentId,
    required String contentType,
    required Map<String, dynamic> content,
    required SharePermissions permissions,
    required String authReason,
  }) async {
    try {
      // Authenticate user
      final authResult = await _biometricService.authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Generate share token
          final shareToken = _generateShareToken();
          
          // Create share metadata
          final shareMetadata = ShareMetadata(
            id: shareToken,
            contentId: contentId,
            contentType: contentType,
            permissions: permissions,
            createdAt: DateTime.now(),
            expiresAt: permissions.expiresAt,
            createdBy: 'current_user', // Would be actual user ID
            accessLog: [],
          );
          
          // Encrypt content
          final encryptedContent = await _encryptionService.encryptJson(content);
          
          return encryptedContent.fold(
            (failure) => Left(failure),
            (encrypted) async {
              // Store encrypted content
              await _secureStorage.storeSecureString(
                key: '$_sharedContentKey$shareToken',
                value: encrypted,
                useSecureStorage: true,
              );
              
              // Store share metadata
              await _storeShareMetadata(shareMetadata);
              
              // Log sharing activity
              await _logShareActivity(
                ShareActivity(
                  id: const Uuid().v4(),
                  shareId: shareToken,
                  action: ShareAction.created,
                  timestamp: DateTime.now(),
                  details: {
                    'contentType': contentType,
                    'permissions': permissions.toJson(),
                  },
                ),
              );
              
              return Right(ShareResult(
                shareToken: shareToken,
                shareUrl: _generateShareUrl(shareToken),
                permissions: permissions,
                expiresAt: permissions.expiresAt,
              ));
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to create secure share: $e'));
    }
  }
  
  /// Access shared content with token
  Future<Either<Failure, SharedContent>> accessSharedContent({
    required String shareToken,
    required String accessorId,
    String? accessPassword,
  }) async {
    try {
      // Validate share token
      final metadataResult = await _getShareMetadata(shareToken);
      
      return metadataResult.fold(
        (failure) => Left(failure),
        (metadata) async {
          // Check if share is expired
          if (metadata.expiresAt != null && DateTime.now().isAfter(metadata.expiresAt!)) {
            return Left(SecurityFailure('Share has expired'));
          }
          
          // Check access permissions
          final accessResult = _checkAccessPermissions(metadata.permissions, accessorId, accessPassword);
          if (accessResult.isLeft()) {
            return accessResult.fold(
              (failure) => Left(failure),
              (r) => Left(SecurityFailure('Unknown access error')),
            );
          }
          
          // Retrieve and decrypt content
          final contentResult = await _secureStorage.getSecureString(
            key: '$_sharedContentKey$shareToken',
            useSecureStorage: true,
          );
          
          return contentResult.fold(
            (failure) => Left(failure),
            (encryptedContent) async {
              if (encryptedContent == null) {
                return Left(SecurityFailure('Shared content not found'));
              }
              
              final decryptedResult = await _encryptionService.decryptJson(encryptedContent);
              
              return decryptedResult.fold(
                (failure) => Left(failure),
                (content) async {
                  // Log access
                  await _logAccessActivity(shareToken, accessorId);
                  
                  return Right(SharedContent(
                    contentId: metadata.contentId,
                    contentType: metadata.contentType,
                    content: content,
                    permissions: metadata.permissions,
                    accessedAt: DateTime.now(),
                  ));
                },
              );
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to access shared content: $e'));
    }
  }
  
  /// Revoke a share
  Future<Either<Failure, void>> revokeShare({
    required String shareToken,
    required String authReason,
  }) async {
    try {
      // Authenticate user
      final authResult = await _biometricService.authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Remove shared content
          await _secureStorage.deleteSecureData(
            key: '$_sharedContentKey$shareToken',
            useSecureStorage: true,
          );
          
          // Remove share metadata
          await _removeShareMetadata(shareToken);
          
          // Log revocation
          await _logShareActivity(
            ShareActivity(
              id: const Uuid().v4(),
              shareId: shareToken,
              action: ShareAction.revoked,
              timestamp: DateTime.now(),
              details: {'reason': 'Manual revocation'},
            ),
          );
          
          return const Right(null);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to revoke share: $e'));
    }
  }
  
  /// Get share history
  Future<Either<Failure, List<ShareMetadata>>> getShareHistory() async {
    try {
      final historyResult = await _secureStorage.getSecureString(
        key: _shareHistoryKey,
        useSecureStorage: true,
      );
      
      return historyResult.fold(
        (failure) => Left(failure),
        (historyJson) {
          if (historyJson == null) {
            return const Right([]);
          }
          
          final historyData = json.decode(historyJson) as List<dynamic>;
          final shares = historyData.map((data) => ShareMetadata.fromJson(data)).toList();
          
          // Sort by creation date (newest first)
          shares.sort((a, b) => b.createdAt.compareTo(a.createdAt));
          
          return Right(shares);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to get share history: $e'));
    }
  }
  
  /// Update share permissions
  Future<Either<Failure, void>> updateSharePermissions({
    required String shareToken,
    required SharePermissions newPermissions,
    required String authReason,
  }) async {
    try {
      // Authenticate user
      final authResult = await _biometricService.authenticate(reason: authReason);
      
      return authResult.fold(
        (failure) => Left(failure),
        (authenticated) async {
          if (!authenticated) {
            return Left(SecurityFailure('Authentication failed'));
          }
          
          // Get current metadata
          final metadataResult = await _getShareMetadata(shareToken);
          
          return metadataResult.fold(
            (failure) => Left(failure),
            (metadata) async {
              // Update permissions
              final updatedMetadata = ShareMetadata(
                id: metadata.id,
                contentId: metadata.contentId,
                contentType: metadata.contentType,
                permissions: newPermissions,
                createdAt: metadata.createdAt,
                expiresAt: newPermissions.expiresAt,
                createdBy: metadata.createdBy,
                accessLog: metadata.accessLog,
              );
              
              // Store updated metadata
              await _storeShareMetadata(updatedMetadata);
              
              // Log permission update
              await _logShareActivity(
                ShareActivity(
                  id: const Uuid().v4(),
                  shareId: shareToken,
                  action: ShareAction.permissionsUpdated,
                  timestamp: DateTime.now(),
                  details: {
                    'oldPermissions': metadata.permissions.toJson(),
                    'newPermissions': newPermissions.toJson(),
                  },
                ),
              );
              
              return const Right(null);
            },
          );
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to update share permissions: $e'));
    }
  }
  
  /// Get sharing settings
  SharingSettings getSharingSettings() {
    return SharingSettings(
      isEnabled: _preferences.getBool(_sharingEnabledKey) ?? false,
      defaultPermissions: _getDefaultPermissions(),
      maxShareDuration: const Duration(days: 30),
      requireAuthentication: true,
    );
  }
  
  /// Update sharing settings
  Future<Either<Failure, void>> updateSharingSettings(SharingSettings settings) async {
    try {
      await _preferences.setBool(_sharingEnabledKey, settings.isEnabled);
      
      // Store default permissions
      await _secureStorage.storeSecureString(
        key: _accessControlsKey,
        value: json.encode(settings.defaultPermissions.toJson()),
        useSecureStorage: true,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(SecurityFailure('Failed to update sharing settings: $e'));
    }
  }
  
  /// Clean up expired shares
  Future<Either<Failure, int>> cleanupExpiredShares() async {
    try {
      final historyResult = await getShareHistory();
      
      return historyResult.fold(
        (failure) => Left(failure),
        (shares) async {
          int cleanedCount = 0;
          final now = DateTime.now();
          
          for (final share in shares) {
            if (share.expiresAt != null && now.isAfter(share.expiresAt!)) {
              // Remove expired share
              await _secureStorage.deleteSecureData(
                key: '$_sharedContentKey${share.id}',
                useSecureStorage: true,
              );
              
              await _removeShareMetadata(share.id);
              cleanedCount++;
            }
          }
          
          return Right(cleanedCount);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to cleanup expired shares: $e'));
    }
  }
  
  // Private methods
  
  String _generateShareToken() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random = const Uuid().v4();
    final tokenData = '$timestamp-$random';
    final bytes = utf8.encode(tokenData);
    final digest = sha256.convert(bytes);
    return digest.toString().substring(0, 32);
  }
  
  String _generateShareUrl(String shareToken) {
    return 'koutu://share/$shareToken';
  }
  
  Future<void> _storeShareMetadata(ShareMetadata metadata) async {
    final historyResult = await getShareHistory();
    
    final shares = historyResult.fold(
      (failure) => <ShareMetadata>[],
      (shares) => shares,
    );
    
    // Update or add metadata
    final existingIndex = shares.indexWhere((s) => s.id == metadata.id);
    if (existingIndex != -1) {
      shares[existingIndex] = metadata;
    } else {
      shares.add(metadata);
    }
    
    // Store updated history
    await _secureStorage.storeSecureString(
      key: _shareHistoryKey,
      value: json.encode(shares.map((s) => s.toJson()).toList()),
      useSecureStorage: true,
    );
  }
  
  Future<Either<Failure, ShareMetadata>> _getShareMetadata(String shareToken) async {
    final historyResult = await getShareHistory();
    
    return historyResult.fold(
      (failure) => Left(failure),
      (shares) {
        try {
          final metadata = shares.firstWhere((s) => s.id == shareToken);
          return Right(metadata);
        } catch (e) {
          return Left(SecurityFailure('Share not found'));
        }
      },
    );
  }
  
  Future<void> _removeShareMetadata(String shareToken) async {
    final historyResult = await getShareHistory();
    
    historyResult.fold(
      (failure) => null,
      (shares) async {
        final updatedShares = shares.where((s) => s.id != shareToken).toList();
        
        await _secureStorage.storeSecureString(
          key: _shareHistoryKey,
          value: json.encode(updatedShares.map((s) => s.toJson()).toList()),
          useSecureStorage: true,
        );
      },
    );
  }
  
  Either<Failure, void> _checkAccessPermissions(
    SharePermissions permissions,
    String accessorId,
    String? accessPassword,
  ) {
    // Check if password is required
    if (permissions.requirePassword && accessPassword == null) {
      return Left(SecurityFailure('Password required'));
    }
    
    // Verify password if provided
    if (permissions.requirePassword && accessPassword != null) {
      if (accessPassword != permissions.password) {
        return Left(SecurityFailure('Invalid password'));
      }
    }
    
    // Check allowed users
    if (permissions.allowedUsers.isNotEmpty) {
      if (!permissions.allowedUsers.contains(accessorId)) {
        return Left(SecurityFailure('Access denied'));
      }
    }
    
    return const Right(null);
  }
  
  Future<void> _logAccessActivity(String shareToken, String accessorId) async {
    await _logShareActivity(
      ShareActivity(
        id: const Uuid().v4(),
        shareId: shareToken,
        action: ShareAction.accessed,
        timestamp: DateTime.now(),
        details: {'accessorId': accessorId},
      ),
    );
  }
  
  Future<void> _logShareActivity(ShareActivity activity) async {
    try {
      // This would typically be stored in a separate activity log
      // For now, we'll add it to the share metadata's access log
      final metadataResult = await _getShareMetadata(activity.shareId);
      
      metadataResult.fold(
        (failure) => null,
        (metadata) async {
          final updatedMetadata = ShareMetadata(
            id: metadata.id,
            contentId: metadata.contentId,
            contentType: metadata.contentType,
            permissions: metadata.permissions,
            createdAt: metadata.createdAt,
            expiresAt: metadata.expiresAt,
            createdBy: metadata.createdBy,
            accessLog: [...metadata.accessLog, activity],
          );
          
          await _storeShareMetadata(updatedMetadata);
        },
      );
    } catch (e) {
      // Log error but don't throw
      debugPrint('Failed to log share activity: $e');
    }
  }
  
  SharePermissions _getDefaultPermissions() {
    return const SharePermissions(
      canView: true,
      canDownload: false,
      canShare: false,
      requirePassword: false,
      allowedUsers: [],
      expiresAt: null,
      maxAccesses: null,
    );
  }
}

/// Share permissions
class SharePermissions {
  final bool canView;
  final bool canDownload;
  final bool canShare;
  final bool requirePassword;
  final String? password;
  final List<String> allowedUsers;
  final DateTime? expiresAt;
  final int? maxAccesses;
  
  const SharePermissions({
    required this.canView,
    required this.canDownload,
    required this.canShare,
    required this.requirePassword,
    this.password,
    required this.allowedUsers,
    this.expiresAt,
    this.maxAccesses,
  });
  
  Map<String, dynamic> toJson() => {
    'canView': canView,
    'canDownload': canDownload,
    'canShare': canShare,
    'requirePassword': requirePassword,
    'password': password,
    'allowedUsers': allowedUsers,
    'expiresAt': expiresAt?.toIso8601String(),
    'maxAccesses': maxAccesses,
  };
  
  factory SharePermissions.fromJson(Map<String, dynamic> json) {
    return SharePermissions(
      canView: json['canView'] ?? true,
      canDownload: json['canDownload'] ?? false,
      canShare: json['canShare'] ?? false,
      requirePassword: json['requirePassword'] ?? false,
      password: json['password'],
      allowedUsers: List<String>.from(json['allowedUsers'] ?? []),
      expiresAt: json['expiresAt'] != null ? DateTime.parse(json['expiresAt']) : null,
      maxAccesses: json['maxAccesses'],
    );
  }
}

/// Share metadata
class ShareMetadata {
  final String id;
  final String contentId;
  final String contentType;
  final SharePermissions permissions;
  final DateTime createdAt;
  final DateTime? expiresAt;
  final String createdBy;
  final List<ShareActivity> accessLog;
  
  const ShareMetadata({
    required this.id,
    required this.contentId,
    required this.contentType,
    required this.permissions,
    required this.createdAt,
    this.expiresAt,
    required this.createdBy,
    required this.accessLog,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'contentId': contentId,
    'contentType': contentType,
    'permissions': permissions.toJson(),
    'createdAt': createdAt.toIso8601String(),
    'expiresAt': expiresAt?.toIso8601String(),
    'createdBy': createdBy,
    'accessLog': accessLog.map((a) => a.toJson()).toList(),
  };
  
  factory ShareMetadata.fromJson(Map<String, dynamic> json) {
    return ShareMetadata(
      id: json['id'],
      contentId: json['contentId'],
      contentType: json['contentType'],
      permissions: SharePermissions.fromJson(json['permissions']),
      createdAt: DateTime.parse(json['createdAt']),
      expiresAt: json['expiresAt'] != null ? DateTime.parse(json['expiresAt']) : null,
      createdBy: json['createdBy'],
      accessLog: (json['accessLog'] as List<dynamic>)
          .map((a) => ShareActivity.fromJson(a))
          .toList(),
    );
  }
}

/// Share result
class ShareResult {
  final String shareToken;
  final String shareUrl;
  final SharePermissions permissions;
  final DateTime? expiresAt;
  
  const ShareResult({
    required this.shareToken,
    required this.shareUrl,
    required this.permissions,
    this.expiresAt,
  });
}

/// Shared content
class SharedContent {
  final String contentId;
  final String contentType;
  final Map<String, dynamic> content;
  final SharePermissions permissions;
  final DateTime accessedAt;
  
  const SharedContent({
    required this.contentId,
    required this.contentType,
    required this.content,
    required this.permissions,
    required this.accessedAt,
  });
}

/// Share activity
class ShareActivity {
  final String id;
  final String shareId;
  final ShareAction action;
  final DateTime timestamp;
  final Map<String, dynamic> details;
  
  const ShareActivity({
    required this.id,
    required this.shareId,
    required this.action,
    required this.timestamp,
    required this.details,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'shareId': shareId,
    'action': action.name,
    'timestamp': timestamp.toIso8601String(),
    'details': details,
  };
  
  factory ShareActivity.fromJson(Map<String, dynamic> json) {
    return ShareActivity(
      id: json['id'],
      shareId: json['shareId'],
      action: ShareAction.values.firstWhere((a) => a.name == json['action']),
      timestamp: DateTime.parse(json['timestamp']),
      details: json['details'],
    );
  }
}

/// Share actions
enum ShareAction {
  created,
  accessed,
  revoked,
  permissionsUpdated,
  expired,
}

/// Sharing settings
class SharingSettings {
  final bool isEnabled;
  final SharePermissions defaultPermissions;
  final Duration maxShareDuration;
  final bool requireAuthentication;
  
  const SharingSettings({
    required this.isEnabled,
    required this.defaultPermissions,
    required this.maxShareDuration,
    required this.requireAuthentication,
  });
}