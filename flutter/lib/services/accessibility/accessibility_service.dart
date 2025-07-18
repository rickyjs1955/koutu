import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Service for managing accessibility features
class AccessibilityService {
  final SharedPreferences _preferences;
  
  // Accessibility settings keys
  static const String _screenReaderEnabledKey = 'screen_reader_enabled';
  static const String _highContrastEnabledKey = 'high_contrast_enabled';
  static const String _colorBlindModeKey = 'color_blind_mode';
  static const String _textScaleFactorKey = 'text_scale_factor';
  static const String _fontFamilyKey = 'font_family';
  static const String _voiceCommandsEnabledKey = 'voice_commands_enabled';
  static const String _gestureNavigationEnabledKey = 'gesture_navigation_enabled';
  static const String _reduceMotionKey = 'reduce_motion';
  static const String _reduceSoundKey = 'reduce_sound';
  static const String _accessibilityAnnouncementsKey = 'accessibility_announcements';
  
  AccessibilityService({
    required SharedPreferences preferences,
  }) : _preferences = preferences;
  
  /// Get current accessibility settings
  AccessibilitySettings getAccessibilitySettings() {
    return AccessibilitySettings(
      screenReaderEnabled: _preferences.getBool(_screenReaderEnabledKey) ?? false,
      highContrastEnabled: _preferences.getBool(_highContrastEnabledKey) ?? false,
      colorBlindMode: ColorBlindMode.values.firstWhere(
        (mode) => mode.name == _preferences.getString(_colorBlindModeKey),
        orElse: () => ColorBlindMode.none,
      ),
      textScaleFactor: _preferences.getDouble(_textScaleFactorKey) ?? 1.0,
      fontFamily: AccessibilityFont.values.firstWhere(
        (font) => font.name == _preferences.getString(_fontFamilyKey),
        orElse: () => AccessibilityFont.system,
      ),
      voiceCommandsEnabled: _preferences.getBool(_voiceCommandsEnabledKey) ?? false,
      gestureNavigationEnabled: _preferences.getBool(_gestureNavigationEnabledKey) ?? false,
      reduceMotion: _preferences.getBool(_reduceMotionKey) ?? false,
      reduceSound: _preferences.getBool(_reduceSoundKey) ?? false,
      accessibilityAnnouncements: _preferences.getBool(_accessibilityAnnouncementsKey) ?? true,
    );
  }
  
  /// Update accessibility settings
  Future<Either<Failure, void>> updateAccessibilitySettings(
    AccessibilitySettings settings,
  ) async {
    try {
      await _preferences.setBool(_screenReaderEnabledKey, settings.screenReaderEnabled);
      await _preferences.setBool(_highContrastEnabledKey, settings.highContrastEnabled);
      await _preferences.setString(_colorBlindModeKey, settings.colorBlindMode.name);
      await _preferences.setDouble(_textScaleFactorKey, settings.textScaleFactor);
      await _preferences.setString(_fontFamilyKey, settings.fontFamily.name);
      await _preferences.setBool(_voiceCommandsEnabledKey, settings.voiceCommandsEnabled);
      await _preferences.setBool(_gestureNavigationEnabledKey, settings.gestureNavigationEnabled);
      await _preferences.setBool(_reduceMotionKey, settings.reduceMotion);
      await _preferences.setBool(_reduceSoundKey, settings.reduceSound);
      await _preferences.setBool(_accessibilityAnnouncementsKey, settings.accessibilityAnnouncements);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update accessibility settings: $e'));
    }
  }
  
  /// Announce message to screen reader
  Future<Either<Failure, void>> announceToScreenReader(
    String message, {
    AccessibilityAnnouncementPriority priority = AccessibilityAnnouncementPriority.polite,
  }) async {
    try {
      final settings = getAccessibilitySettings();
      
      if (!settings.screenReaderEnabled || !settings.accessibilityAnnouncements) {
        return const Right(null);
      }
      
      await SystemChannels.accessibility.invokeMethod('announce', {
        'message': message,
        'priority': priority.name,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to announce to screen reader: $e'));
    }
  }
  
  /// Get semantic label for UI element
  String getSemanticLabel(String baseLabel, {
    String? hint,
    String? value,
    bool? isEnabled,
    bool? isSelected,
  }) {
    final parts = <String>[baseLabel];
    
    if (value != null && value.isNotEmpty) {
      parts.add(value);
    }
    
    if (isSelected == true) {
      parts.add('selected');
    }
    
    if (isEnabled == false) {
      parts.add('disabled');
    }
    
    if (hint != null && hint.isNotEmpty) {
      parts.add(hint);
    }
    
    return parts.join(', ');
  }
  
  /// Get appropriate color for accessibility mode
  Color getAccessibilityColor(Color originalColor, {
    required bool isHighContrast,
    required ColorBlindMode colorBlindMode,
  }) {
    Color color = originalColor;
    
    // Apply color blind adjustments
    if (colorBlindMode != ColorBlindMode.none) {
      color = _adjustColorForColorBlindness(color, colorBlindMode);
    }
    
    // Apply high contrast adjustments
    if (isHighContrast) {
      color = _adjustColorForHighContrast(color);
    }
    
    return color;
  }
  
  /// Get accessible text style
  TextStyle getAccessibilityTextStyle(
    TextStyle baseStyle, {
    required double textScaleFactor,
    required AccessibilityFont fontFamily,
  }) {
    return baseStyle.copyWith(
      fontSize: (baseStyle.fontSize ?? 14) * textScaleFactor,
      fontFamily: _getFontFamily(fontFamily),
    );
  }
  
  /// Check if device accessibility features are enabled
  Future<Either<Failure, DeviceAccessibilityStatus>> checkDeviceAccessibility() async {
    try {
      final isScreenReaderEnabled = await _isScreenReaderEnabled();
      final isHighContrastEnabled = await _isHighContrastEnabled();
      final isLargeTextEnabled = await _isLargeTextEnabled();
      final isReduceMotionEnabled = await _isReduceMotionEnabled();
      
      return Right(DeviceAccessibilityStatus(
        screenReaderEnabled: isScreenReaderEnabled,
        highContrastEnabled: isHighContrastEnabled,
        largeTextEnabled: isLargeTextEnabled,
        reduceMotionEnabled: isReduceMotionEnabled,
      ));
    } catch (e) {
      return Left(ServiceFailure('Failed to check device accessibility: $e'));
    }
  }
  
  /// Provide haptic feedback for accessibility
  Future<Either<Failure, void>> provideHapticFeedback(
    AccessibilityHapticType type,
  ) async {
    try {
      final settings = getAccessibilitySettings();
      
      if (settings.reduceMotion) {
        // Skip haptic feedback if reduce motion is enabled
        return const Right(null);
      }
      
      switch (type) {
        case AccessibilityHapticType.light:
          await HapticFeedback.lightImpact();
          break;
        case AccessibilityHapticType.medium:
          await HapticFeedback.mediumImpact();
          break;
        case AccessibilityHapticType.heavy:
          await HapticFeedback.heavyImpact();
          break;
        case AccessibilityHapticType.selection:
          await HapticFeedback.selectionClick();
          break;
        case AccessibilityHapticType.vibrate:
          await HapticFeedback.vibrate();
          break;
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to provide haptic feedback: $e'));
    }
  }
  
  /// Generate accessibility report
  Future<Either<Failure, AccessibilityReport>> generateAccessibilityReport() async {
    try {
      final settings = getAccessibilitySettings();
      final deviceStatus = await checkDeviceAccessibility();
      
      return deviceStatus.fold(
        (failure) => Left(failure),
        (status) => Right(AccessibilityReport(
          settings: settings,
          deviceStatus: status,
          recommendations: _generateAccessibilityRecommendations(settings, status),
          complianceScore: _calculateComplianceScore(settings, status),
          generatedAt: DateTime.now(),
        )),
      );
    } catch (e) {
      return Left(ServiceFailure('Failed to generate accessibility report: $e'));
    }
  }
  
  // Private methods
  
  Future<bool> _isScreenReaderEnabled() async {
    try {
      final result = await SystemChannels.accessibility.invokeMethod('isScreenReaderEnabled');
      return result as bool? ?? false;
    } catch (e) {
      return false;
    }
  }
  
  Future<bool> _isHighContrastEnabled() async {
    try {
      final result = await SystemChannels.accessibility.invokeMethod('isHighContrastEnabled');
      return result as bool? ?? false;
    } catch (e) {
      return false;
    }
  }
  
  Future<bool> _isLargeTextEnabled() async {
    try {
      final result = await SystemChannels.accessibility.invokeMethod('isLargeTextEnabled');
      return result as bool? ?? false;
    } catch (e) {
      return false;
    }
  }
  
  Future<bool> _isReduceMotionEnabled() async {
    try {
      final result = await SystemChannels.accessibility.invokeMethod('isReduceMotionEnabled');
      return result as bool? ?? false;
    } catch (e) {
      return false;
    }
  }
  
  Color _adjustColorForColorBlindness(Color color, ColorBlindMode mode) {
    switch (mode) {
      case ColorBlindMode.protanopia:
        // Red-blind: Remove red component
        return Color.fromARGB(
          color.alpha,
          0,
          color.green,
          color.blue,
        );
      case ColorBlindMode.deuteranopia:
        // Green-blind: Remove green component
        return Color.fromARGB(
          color.alpha,
          color.red,
          0,
          color.blue,
        );
      case ColorBlindMode.tritanopia:
        // Blue-blind: Remove blue component
        return Color.fromARGB(
          color.alpha,
          color.red,
          color.green,
          0,
        );
      case ColorBlindMode.monochromacy:
        // Convert to grayscale
        final gray = (0.299 * color.red + 0.587 * color.green + 0.114 * color.blue).round();
        return Color.fromARGB(color.alpha, gray, gray, gray);
      case ColorBlindMode.none:
        return color;
    }
  }
  
  Color _adjustColorForHighContrast(Color color) {
    // Increase contrast by making colors more extreme
    final luminance = color.computeLuminance();
    
    if (luminance > 0.5) {
      // Light colors become white
      return Colors.white;
    } else {
      // Dark colors become black
      return Colors.black;
    }
  }
  
  String? _getFontFamily(AccessibilityFont font) {
    switch (font) {
      case AccessibilityFont.system:
        return null;
      case AccessibilityFont.dyslexic:
        return 'OpenDyslexic';
      case AccessibilityFont.monospace:
        return 'Courier';
      case AccessibilityFont.sansSerif:
        return 'Arial';
      case AccessibilityFont.serif:
        return 'Times';
    }
  }
  
  List<String> _generateAccessibilityRecommendations(
    AccessibilitySettings settings,
    DeviceAccessibilityStatus status,
  ) {
    final recommendations = <String>[];
    
    if (status.screenReaderEnabled && !settings.screenReaderEnabled) {
      recommendations.add('Enable screen reader support in app settings');
    }
    
    if (status.highContrastEnabled && !settings.highContrastEnabled) {
      recommendations.add('Enable high contrast mode for better visibility');
    }
    
    if (status.largeTextEnabled && settings.textScaleFactor == 1.0) {
      recommendations.add('Increase text scale factor to match system preferences');
    }
    
    if (status.reduceMotionEnabled && !settings.reduceMotion) {
      recommendations.add('Enable reduce motion to match system preferences');
    }
    
    if (settings.colorBlindMode == ColorBlindMode.none) {
      recommendations.add('Consider enabling color blind mode if needed');
    }
    
    return recommendations;
  }
  
  double _calculateComplianceScore(
    AccessibilitySettings settings,
    DeviceAccessibilityStatus status,
  ) {
    double score = 0.0;
    int totalChecks = 0;
    
    // Screen reader support
    totalChecks++;
    if (settings.screenReaderEnabled || !status.screenReaderEnabled) {
      score += 1.0;
    }
    
    // High contrast support
    totalChecks++;
    if (settings.highContrastEnabled || !status.highContrastEnabled) {
      score += 1.0;
    }
    
    // Text scaling
    totalChecks++;
    if (settings.textScaleFactor >= 1.0) {
      score += 1.0;
    }
    
    // Reduce motion
    totalChecks++;
    if (settings.reduceMotion || !status.reduceMotionEnabled) {
      score += 1.0;
    }
    
    // Accessibility announcements
    totalChecks++;
    if (settings.accessibilityAnnouncements) {
      score += 1.0;
    }
    
    return (score / totalChecks) * 100.0;
  }
}

// Data classes

class AccessibilitySettings {
  final bool screenReaderEnabled;
  final bool highContrastEnabled;
  final ColorBlindMode colorBlindMode;
  final double textScaleFactor;
  final AccessibilityFont fontFamily;
  final bool voiceCommandsEnabled;
  final bool gestureNavigationEnabled;
  final bool reduceMotion;
  final bool reduceSound;
  final bool accessibilityAnnouncements;
  
  const AccessibilitySettings({
    required this.screenReaderEnabled,
    required this.highContrastEnabled,
    required this.colorBlindMode,
    required this.textScaleFactor,
    required this.fontFamily,
    required this.voiceCommandsEnabled,
    required this.gestureNavigationEnabled,
    required this.reduceMotion,
    required this.reduceSound,
    required this.accessibilityAnnouncements,
  });
}

class DeviceAccessibilityStatus {
  final bool screenReaderEnabled;
  final bool highContrastEnabled;
  final bool largeTextEnabled;
  final bool reduceMotionEnabled;
  
  const DeviceAccessibilityStatus({
    required this.screenReaderEnabled,
    required this.highContrastEnabled,
    required this.largeTextEnabled,
    required this.reduceMotionEnabled,
  });
}

class AccessibilityReport {
  final AccessibilitySettings settings;
  final DeviceAccessibilityStatus deviceStatus;
  final List<String> recommendations;
  final double complianceScore;
  final DateTime generatedAt;
  
  const AccessibilityReport({
    required this.settings,
    required this.deviceStatus,
    required this.recommendations,
    required this.complianceScore,
    required this.generatedAt,
  });
}

// Enums

enum ColorBlindMode {
  none,
  protanopia,
  deuteranopia,
  tritanopia,
  monochromacy,
}

enum AccessibilityFont {
  system,
  dyslexic,
  monospace,
  sansSerif,
  serif,
}

enum AccessibilityAnnouncementPriority {
  polite,
  assertive,
}

enum AccessibilityHapticType {
  light,
  medium,
  heavy,
  selection,
  vibrate,
}