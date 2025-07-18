import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Service for gesture-based navigation
class GestureNavigationService {
  final SharedPreferences _preferences;
  
  // Gesture settings keys
  static const String _gestureNavigationEnabledKey = 'gesture_navigation_enabled';
  static const String _swipeGesturesEnabledKey = 'swipe_gestures_enabled';
  static const String _tapGesturesEnabledKey = 'tap_gestures_enabled';
  static const String _longPressGesturesEnabledKey = 'long_press_gestures_enabled';
  static const String _swipeSensitivityKey = 'swipe_sensitivity';
  static const String _tapSensitivityKey = 'tap_sensitivity';
  static const String _longPressDurationKey = 'long_press_duration';
  static const String _customGesturesKey = 'custom_gestures';
  
  GestureNavigationService({
    required SharedPreferences preferences,
  }) : _preferences = preferences;
  
  /// Get gesture navigation settings
  GestureNavigationSettings getGestureSettings() {
    return GestureNavigationSettings(
      enabled: _preferences.getBool(_gestureNavigationEnabledKey) ?? false,
      swipeGesturesEnabled: _preferences.getBool(_swipeGesturesEnabledKey) ?? true,
      tapGesturesEnabled: _preferences.getBool(_tapGesturesEnabledKey) ?? true,
      longPressGesturesEnabled: _preferences.getBool(_longPressGesturesEnabledKey) ?? true,
      swipeSensitivity: _preferences.getDouble(_swipeSensitivityKey) ?? 1.0,
      tapSensitivity: _preferences.getDouble(_tapSensitivityKey) ?? 1.0,
      longPressDuration: Duration(milliseconds: _preferences.getInt(_longPressDurationKey) ?? 500),
      customGestures: _loadCustomGestures(),
    );
  }
  
  /// Update gesture navigation settings
  Future<Either<Failure, void>> updateGestureSettings(
    GestureNavigationSettings settings,
  ) async {
    try {
      await _preferences.setBool(_gestureNavigationEnabledKey, settings.enabled);
      await _preferences.setBool(_swipeGesturesEnabledKey, settings.swipeGesturesEnabled);
      await _preferences.setBool(_tapGesturesEnabledKey, settings.tapGesturesEnabled);
      await _preferences.setBool(_longPressGesturesEnabledKey, settings.longPressGesturesEnabled);
      await _preferences.setDouble(_swipeSensitivityKey, settings.swipeSensitivity);
      await _preferences.setDouble(_tapSensitivityKey, settings.tapSensitivity);
      await _preferences.setInt(_longPressDurationKey, settings.longPressDuration.inMilliseconds);
      await _saveCustomGestures(settings.customGestures);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update gesture settings: $e'));
    }
  }
  
  /// Process gesture input
  Either<Failure, GestureAction> processGesture(
    GestureType gestureType,
    GestureDetails details,
  ) {
    try {
      final settings = getGestureSettings();
      
      if (!settings.enabled) {
        return Left(ServiceFailure('Gesture navigation is disabled'));
      }
      
      switch (gestureType) {
        case GestureType.swipeLeft:
          if (!settings.swipeGesturesEnabled) {
            return Left(ServiceFailure('Swipe gestures are disabled'));
          }
          return _processSwipeLeft(details, settings);
          
        case GestureType.swipeRight:
          if (!settings.swipeGesturesEnabled) {
            return Left(ServiceFailure('Swipe gestures are disabled'));
          }
          return _processSwipeRight(details, settings);
          
        case GestureType.swipeUp:
          if (!settings.swipeGesturesEnabled) {
            return Left(ServiceFailure('Swipe gestures are disabled'));
          }
          return _processSwipeUp(details, settings);
          
        case GestureType.swipeDown:
          if (!settings.swipeGesturesEnabled) {
            return Left(ServiceFailure('Swipe gestures are disabled'));
          }
          return _processSwipeDown(details, settings);
          
        case GestureType.tap:
          if (!settings.tapGesturesEnabled) {
            return Left(ServiceFailure('Tap gestures are disabled'));
          }
          return _processTap(details, settings);
          
        case GestureType.doubleTap:
          if (!settings.tapGesturesEnabled) {
            return Left(ServiceFailure('Tap gestures are disabled'));
          }
          return _processDoubleTap(details, settings);
          
        case GestureType.longPress:
          if (!settings.longPressGesturesEnabled) {
            return Left(ServiceFailure('Long press gestures are disabled'));
          }
          return _processLongPress(details, settings);
          
        case GestureType.pinch:
          return _processPinch(details, settings);
          
        case GestureType.rotate:
          return _processRotate(details, settings);
          
        case GestureType.twoFingerTap:
          return _processTwoFingerTap(details, settings);
          
        case GestureType.threeFingerTap:
          return _processThreeFingerTap(details, settings);
      }
    } catch (e) {
      return Left(ServiceFailure('Failed to process gesture: $e'));
    }
  }
  
  /// Get available gestures
  List<GestureMapping> getAvailableGestures() {
    return [
      // Navigation gestures
      GestureMapping(
        gesture: GestureType.swipeLeft,
        action: GestureAction.navigateBack,
        description: 'Navigate back to previous screen',
        zone: GestureZone.edge,
      ),
      GestureMapping(
        gesture: GestureType.swipeRight,
        action: GestureAction.navigateForward,
        description: 'Navigate forward if available',
        zone: GestureZone.edge,
      ),
      GestureMapping(
        gesture: GestureType.swipeUp,
        action: GestureAction.scrollUp,
        description: 'Scroll up in current view',
        zone: GestureZone.content,
      ),
      GestureMapping(
        gesture: GestureType.swipeDown,
        action: GestureAction.scrollDown,
        description: 'Scroll down in current view',
        zone: GestureZone.content,
      ),
      
      // Tap gestures
      GestureMapping(
        gesture: GestureType.tap,
        action: GestureAction.select,
        description: 'Select item or activate button',
        zone: GestureZone.any,
      ),
      GestureMapping(
        gesture: GestureType.doubleTap,
        action: GestureAction.activate,
        description: 'Activate or open item',
        zone: GestureZone.any,
      ),
      GestureMapping(
        gesture: GestureType.longPress,
        action: GestureAction.showContextMenu,
        description: 'Show context menu or options',
        zone: GestureZone.any,
      ),
      
      // Zoom gestures
      GestureMapping(
        gesture: GestureType.pinch,
        action: GestureAction.zoom,
        description: 'Zoom in or out',
        zone: GestureZone.content,
      ),
      
      // Accessibility gestures
      GestureMapping(
        gesture: GestureType.twoFingerTap,
        action: GestureAction.readScreen,
        description: 'Read screen content aloud',
        zone: GestureZone.any,
      ),
      GestureMapping(
        gesture: GestureType.threeFingerTap,
        action: GestureAction.toggleAccessibility,
        description: 'Toggle accessibility features',
        zone: GestureZone.any,
      ),
      
      // Custom gestures
      GestureMapping(
        gesture: GestureType.swipeUp,
        action: GestureAction.openQuickActions,
        description: 'Open quick actions menu',
        zone: GestureZone.bottom,
      ),
      GestureMapping(
        gesture: GestureType.swipeDown,
        action: GestureAction.openNotifications,
        description: 'Open notifications panel',
        zone: GestureZone.top,
      ),
    ];
  }
  
  /// Create custom gesture
  Future<Either<Failure, void>> createCustomGesture(
    CustomGesture gesture,
  ) async {
    try {
      final settings = getGestureSettings();
      final updatedGestures = [...settings.customGestures, gesture];
      
      await _saveCustomGestures(updatedGestures);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create custom gesture: $e'));
    }
  }
  
  /// Remove custom gesture
  Future<Either<Failure, void>> removeCustomGesture(String gestureId) async {
    try {
      final settings = getGestureSettings();
      final updatedGestures = settings.customGestures
          .where((g) => g.id != gestureId)
          .toList();
      
      await _saveCustomGestures(updatedGestures);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to remove custom gesture: $e'));
    }
  }
  
  /// Test gesture recognition
  Future<Either<Failure, GestureTestResult>> testGestureRecognition(
    GestureType gestureType,
    GestureDetails details,
  ) async {
    try {
      final result = processGesture(gestureType, details);
      
      return Right(GestureTestResult(
        gestureType: gestureType,
        recognized: result.isRight(),
        action: result.fold(
          (failure) => null,
          (action) => action,
        ),
        confidence: result.isRight() ? 1.0 : 0.0,
        timestamp: DateTime.now(),
      ));
    } catch (e) {
      return Left(ServiceFailure('Failed to test gesture recognition: $e'));
    }
  }
  
  /// Get gesture help
  List<GestureHelp> getGestureHelp() {
    return [
      GestureHelp(
        title: 'Basic Navigation',
        gestures: [
          'Swipe left from edge: Go back',
          'Swipe right from edge: Go forward',
          'Swipe up: Scroll up',
          'Swipe down: Scroll down',
        ],
      ),
      GestureHelp(
        title: 'Selection and Activation',
        gestures: [
          'Single tap: Select item',
          'Double tap: Activate or open',
          'Long press: Show options menu',
        ],
      ),
      GestureHelp(
        title: 'Accessibility Features',
        gestures: [
          'Two finger tap: Read screen aloud',
          'Three finger tap: Toggle accessibility',
          'Pinch: Zoom in/out',
        ],
      ),
      GestureHelp(
        title: 'Quick Actions',
        gestures: [
          'Swipe up from bottom: Quick actions',
          'Swipe down from top: Notifications',
          'Rotate: Rotate images',
        ],
      ),
    ];
  }
  
  // Private methods
  
  Either<Failure, GestureAction> _processSwipeLeft(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    if (details.velocity.pixelsPerSecond.dx < -100 * settings.swipeSensitivity) {
      return const Right(GestureAction.navigateBack);
    }
    return Left(ServiceFailure('Swipe not strong enough'));
  }
  
  Either<Failure, GestureAction> _processSwipeRight(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    if (details.velocity.pixelsPerSecond.dx > 100 * settings.swipeSensitivity) {
      return const Right(GestureAction.navigateForward);
    }
    return Left(ServiceFailure('Swipe not strong enough'));
  }
  
  Either<Failure, GestureAction> _processSwipeUp(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    if (details.velocity.pixelsPerSecond.dy < -100 * settings.swipeSensitivity) {
      if (details.globalPosition.dy > 600) {
        return const Right(GestureAction.openQuickActions);
      }
      return const Right(GestureAction.scrollUp);
    }
    return Left(ServiceFailure('Swipe not strong enough'));
  }
  
  Either<Failure, GestureAction> _processSwipeDown(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    if (details.velocity.pixelsPerSecond.dy > 100 * settings.swipeSensitivity) {
      if (details.globalPosition.dy < 100) {
        return const Right(GestureAction.openNotifications);
      }
      return const Right(GestureAction.scrollDown);
    }
    return Left(ServiceFailure('Swipe not strong enough'));
  }
  
  Either<Failure, GestureAction> _processTap(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.select);
  }
  
  Either<Failure, GestureAction> _processDoubleTap(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.activate);
  }
  
  Either<Failure, GestureAction> _processLongPress(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.showContextMenu);
  }
  
  Either<Failure, GestureAction> _processPinch(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.zoom);
  }
  
  Either<Failure, GestureAction> _processRotate(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.rotate);
  }
  
  Either<Failure, GestureAction> _processTwoFingerTap(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.readScreen);
  }
  
  Either<Failure, GestureAction> _processThreeFingerTap(
    GestureDetails details,
    GestureNavigationSettings settings,
  ) {
    return const Right(GestureAction.toggleAccessibility);
  }
  
  List<CustomGesture> _loadCustomGestures() {
    // This would load custom gestures from preferences
    // For now, return empty list
    return [];
  }
  
  Future<void> _saveCustomGestures(List<CustomGesture> gestures) async {
    // This would save custom gestures to preferences
    // Implementation depends on JSON serialization
  }
}

// Data classes

class GestureNavigationSettings {
  final bool enabled;
  final bool swipeGesturesEnabled;
  final bool tapGesturesEnabled;
  final bool longPressGesturesEnabled;
  final double swipeSensitivity;
  final double tapSensitivity;
  final Duration longPressDuration;
  final List<CustomGesture> customGestures;
  
  const GestureNavigationSettings({
    required this.enabled,
    required this.swipeGesturesEnabled,
    required this.tapGesturesEnabled,
    required this.longPressGesturesEnabled,
    required this.swipeSensitivity,
    required this.tapSensitivity,
    required this.longPressDuration,
    required this.customGestures,
  });
}

class GestureDetails {
  final Offset globalPosition;
  final Offset localPosition;
  final Velocity velocity;
  final Duration duration;
  final int pointerCount;
  
  const GestureDetails({
    required this.globalPosition,
    required this.localPosition,
    required this.velocity,
    required this.duration,
    this.pointerCount = 1,
  });
}

class GestureMapping {
  final GestureType gesture;
  final GestureAction action;
  final String description;
  final GestureZone zone;
  
  const GestureMapping({
    required this.gesture,
    required this.action,
    required this.description,
    required this.zone,
  });
}

class CustomGesture {
  final String id;
  final String name;
  final GestureType gestureType;
  final GestureAction action;
  final String description;
  final GestureZone zone;
  final Map<String, dynamic> parameters;
  
  const CustomGesture({
    required this.id,
    required this.name,
    required this.gestureType,
    required this.action,
    required this.description,
    required this.zone,
    required this.parameters,
  });
}

class GestureTestResult {
  final GestureType gestureType;
  final bool recognized;
  final GestureAction? action;
  final double confidence;
  final DateTime timestamp;
  
  const GestureTestResult({
    required this.gestureType,
    required this.recognized,
    this.action,
    required this.confidence,
    required this.timestamp,
  });
}

class GestureHelp {
  final String title;
  final List<String> gestures;
  
  const GestureHelp({
    required this.title,
    required this.gestures,
  });
}

// Enums

enum GestureType {
  swipeLeft,
  swipeRight,
  swipeUp,
  swipeDown,
  tap,
  doubleTap,
  longPress,
  pinch,
  rotate,
  twoFingerTap,
  threeFingerTap,
}

enum GestureAction {
  navigateBack,
  navigateForward,
  scrollUp,
  scrollDown,
  select,
  activate,
  showContextMenu,
  zoom,
  rotate,
  readScreen,
  toggleAccessibility,
  openQuickActions,
  openNotifications,
}

enum GestureZone {
  any,
  edge,
  top,
  bottom,
  left,
  right,
  center,
  content,
}