import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:crypto/crypto.dart';

/// Service for data sanitization and privacy protection
class DataSanitizationService {
  // Patterns for sensitive data detection
  static final RegExp _emailPattern = RegExp(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
  );
  static final RegExp _phonePattern = RegExp(
    r'^\+?[1-9]\d{1,14}$',
  );
  static final RegExp _creditCardPattern = RegExp(
    r'^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$',
  );
  static final RegExp _ssnPattern = RegExp(
    r'^\d{3}-\d{2}-\d{4}$',
  );
  static final RegExp _ipAddressPattern = RegExp(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
  );
  
  // Fields that should be sanitized
  static const List<String> _sensitiveFields = [
    'password',
    'pin',
    'ssn',
    'creditCard',
    'cvv',
    'bankAccount',
    'apiKey',
    'secret',
    'token',
    'privateKey',
  ];
  
  /// Sanitize user data by removing or masking sensitive information
  Either<Failure, Map<String, dynamic>> sanitizeData(
    Map<String, dynamic> data, {
    SanitizationLevel level = SanitizationLevel.standard,
  }) {
    try {
      final sanitized = _sanitizeMap(data, level);
      return Right(sanitized);
    } catch (e) {
      return Left(SecurityFailure('Failed to sanitize data: $e'));
    }
  }
  
  /// Sanitize a map recursively
  Map<String, dynamic> _sanitizeMap(
    Map<String, dynamic> data,
    SanitizationLevel level,
  ) {
    final sanitized = <String, dynamic>{};
    
    for (final entry in data.entries) {
      final key = entry.key;
      final value = entry.value;
      
      // Check if field is sensitive
      if (_isSensitiveField(key)) {
        if (level == SanitizationLevel.strict) {
          // Skip sensitive fields entirely in strict mode
          continue;
        } else {
          // Mask sensitive fields
          sanitized[key] = _maskValue(value);
        }
      } else if (value is Map<String, dynamic>) {
        // Recursively sanitize nested maps
        sanitized[key] = _sanitizeMap(value, level);
      } else if (value is List) {
        // Sanitize lists
        sanitized[key] = _sanitizeList(value, level);
      } else if (value is String) {
        // Check for sensitive patterns in strings
        sanitized[key] = _sanitizeString(value, level);
      } else {
        // Keep non-sensitive primitive values
        sanitized[key] = value;
      }
    }
    
    return sanitized;
  }
  
  /// Sanitize a list
  List<dynamic> _sanitizeList(List<dynamic> list, SanitizationLevel level) {
    return list.map((item) {
      if (item is Map<String, dynamic>) {
        return _sanitizeMap(item, level);
      } else if (item is List) {
        return _sanitizeList(item, level);
      } else if (item is String) {
        return _sanitizeString(item, level);
      } else {
        return item;
      }
    }).toList();
  }
  
  /// Sanitize a string value
  String _sanitizeString(String value, SanitizationLevel level) {
    // Check for email
    if (_emailPattern.hasMatch(value)) {
      return level == SanitizationLevel.strict
          ? '[EMAIL_REMOVED]'
          : _maskEmail(value);
    }
    
    // Check for phone number
    if (_phonePattern.hasMatch(value)) {
      return level == SanitizationLevel.strict
          ? '[PHONE_REMOVED]'
          : _maskPhoneNumber(value);
    }
    
    // Check for credit card
    if (_creditCardPattern.hasMatch(value)) {
      return level == SanitizationLevel.strict
          ? '[CARD_REMOVED]'
          : _maskCreditCard(value);
    }
    
    // Check for SSN
    if (_ssnPattern.hasMatch(value)) {
      return '[SSN_REMOVED]';
    }
    
    // Check for IP address
    if (_ipAddressPattern.hasMatch(value)) {
      return level == SanitizationLevel.strict
          ? '[IP_REMOVED]'
          : _maskIpAddress(value);
    }
    
    return value;
  }
  
  /// Check if field name indicates sensitive data
  bool _isSensitiveField(String fieldName) {
    final lowerField = fieldName.toLowerCase();
    return _sensitiveFields.any((sensitive) => 
        lowerField.contains(sensitive));
  }
  
  /// Mask a value based on its type
  dynamic _maskValue(dynamic value) {
    if (value is String) {
      if (value.isEmpty) return '';
      if (value.length <= 4) return '****';
      
      // Show first and last character only
      return '${value[0]}${'*' * (value.length - 2)}${value[value.length - 1]}';
    } else if (value is num) {
      return '****';
    } else if (value is bool) {
      return '[HIDDEN]';
    } else {
      return '[REMOVED]';
    }
  }
  
  /// Mask email address
  String _maskEmail(String email) {
    final parts = email.split('@');
    if (parts.length != 2) return '[INVALID_EMAIL]';
    
    final username = parts[0];
    final domain = parts[1];
    
    if (username.length <= 2) {
      return '**@$domain';
    }
    
    return '${username[0]}${'*' * (username.length - 2)}${username[username.length - 1]}@$domain';
  }
  
  /// Mask phone number
  String _maskPhoneNumber(String phone) {
    if (phone.length <= 4) return '****';
    
    // Show last 4 digits only
    final masked = '*' * (phone.length - 4) + phone.substring(phone.length - 4);
    return masked;
  }
  
  /// Mask credit card number
  String _maskCreditCard(String card) {
    final cleaned = card.replaceAll(RegExp(r'[\s-]'), '');
    if (cleaned.length != 16) return '[INVALID_CARD]';
    
    // Show first 4 and last 4 digits
    return '${cleaned.substring(0, 4)} **** **** ${cleaned.substring(12)}';
  }
  
  /// Mask IP address
  String _maskIpAddress(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return '[INVALID_IP]';
    
    // Mask last two octets
    return '${parts[0]}.${parts[1]}.***.***';
  }
  
  /// Anonymize user data for analytics
  Either<Failure, Map<String, dynamic>> anonymizeForAnalytics(
    Map<String, dynamic> userData,
  ) {
    try {
      final anonymized = <String, dynamic>{};
      
      // Generate anonymous ID from user data
      final userId = userData['id'] ?? userData['userId'] ?? '';
      anonymized['anonymousId'] = _generateAnonymousId(userId.toString());
      
      // Keep only non-sensitive aggregate data
      final allowedFields = [
        'age',
        'gender',
        'country',
        'city',
        'preferences',
        'settings',
        'stats',
      ];
      
      for (final field in allowedFields) {
        if (userData.containsKey(field)) {
          anonymized[field] = userData[field];
        }
      }
      
      // Add timestamp
      anonymized['timestamp'] = DateTime.now().toIso8601String();
      
      return Right(anonymized);
    } catch (e) {
      return Left(SecurityFailure('Failed to anonymize data: $e'));
    }
  }
  
  /// Generate anonymous ID from user ID
  String _generateAnonymousId(String userId) {
    final bytes = utf8.encode(userId + 'koutu_salt');
    final digest = sha256.convert(bytes);
    return digest.toString().substring(0, 16);
  }
  
  /// Remove all personally identifiable information (PII)
  Either<Failure, Map<String, dynamic>> removePII(
    Map<String, dynamic> data,
  ) {
    try {
      final cleaned = sanitizeData(
        data,
        level: SanitizationLevel.strict,
      );
      
      return cleaned.fold(
        (failure) => Left(failure),
        (sanitized) {
          // Additional PII fields to remove
          final piiFields = [
            'name',
            'firstName',
            'lastName',
            'email',
            'phone',
            'address',
            'dateOfBirth',
            'dob',
            'ssn',
            'nationalId',
            'passport',
            'driverLicense',
          ];
          
          for (final field in piiFields) {
            sanitized.remove(field);
          }
          
          return Right(sanitized);
        },
      );
    } catch (e) {
      return Left(SecurityFailure('Failed to remove PII: $e'));
    }
  }
  
  /// Create data export with privacy protection
  Either<Failure, Map<String, dynamic>> createPrivacyCompliantExport(
    Map<String, dynamic> userData, {
    required bool includePersonalData,
    required bool includeAnalytics,
    required bool includePurchaseHistory,
  }) {
    try {
      final export = <String, dynamic>{
        'exportDate': DateTime.now().toIso8601String(),
        'exportVersion': '1.0',
      };
      
      if (includePersonalData) {
        // Sanitize personal data
        final sanitizedResult = sanitizeData(
          userData,
          level: SanitizationLevel.standard,
        );
        
        sanitizedResult.fold(
          (failure) => throw failure,
          (sanitized) => export['personalData'] = sanitized,
        );
      }
      
      if (includeAnalytics) {
        // Include only anonymized analytics
        final analyticsData = userData['analytics'] ?? {};
        final anonymizedResult = anonymizeForAnalytics(analyticsData);
        
        anonymizedResult.fold(
          (failure) => throw failure,
          (anonymized) => export['analytics'] = anonymized,
        );
      }
      
      if (includePurchaseHistory) {
        // Sanitize purchase history
        final purchases = userData['purchases'] ?? [];
        export['purchases'] = _sanitizePurchaseHistory(purchases);
      }
      
      return Right(export);
    } catch (e) {
      return Left(SecurityFailure('Failed to create privacy-compliant export: $e'));
    }
  }
  
  /// Sanitize purchase history
  List<Map<String, dynamic>> _sanitizePurchaseHistory(List<dynamic> purchases) {
    return purchases.map((purchase) {
      if (purchase is Map<String, dynamic>) {
        final sanitized = Map<String, dynamic>.from(purchase);
        
        // Remove sensitive payment information
        sanitized.remove('creditCard');
        sanitized.remove('cardNumber');
        sanitized.remove('cvv');
        sanitized.remove('billingAddress');
        
        // Mask order ID
        if (sanitized['orderId'] != null) {
          final orderId = sanitized['orderId'].toString();
          sanitized['orderId'] = orderId.length > 8
              ? '${orderId.substring(0, 4)}****'
              : '****';
        }
        
        return sanitized;
      }
      return <String, dynamic>{};
    }).toList();
  }
}

/// Sanitization levels
enum SanitizationLevel {
  /// Standard sanitization - masks sensitive data
  standard,
  
  /// Strict sanitization - removes sensitive data entirely
  strict,
}