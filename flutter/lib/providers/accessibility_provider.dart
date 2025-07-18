import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/accessibility/accessibility_service.dart';
import 'package:koutu/services/accessibility/voice_command_service.dart';
import 'package:koutu/services/accessibility/gesture_navigation_service.dart';
import 'package:koutu/services/accessibility/multi_language_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:speech_to_text/speech_to_text.dart';
import 'package:flutter_tts/flutter_tts.dart';

/// Provider for accessibility service
final accessibilityServiceProvider = FutureProvider<AccessibilityService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return AccessibilityService(
    preferences: preferences,
  );
});

/// Provider for voice command service
final voiceCommandServiceProvider = FutureProvider<VoiceCommandService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  final speechToText = SpeechToText();
  final flutterTts = FlutterTts();
  
  return VoiceCommandService(
    preferences: preferences,
    speechToText: speechToText,
    flutterTts: flutterTts,
  );
});

/// Provider for gesture navigation service
final gestureNavigationServiceProvider = FutureProvider<GestureNavigationService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return GestureNavigationService(
    preferences: preferences,
  );
});

/// Provider for multi-language service
final multiLanguageServiceProvider = FutureProvider<MultiLanguageService>((ref) async {
  final preferences = await SharedPreferences.getInstance();
  
  return MultiLanguageService(
    preferences: preferences,
  );
});

/// Provider for accessibility settings
final accessibilitySettingsProvider = FutureProvider<AccessibilitySettings>((ref) async {
  final service = await ref.watch(accessibilityServiceProvider.future);
  return service.getAccessibilitySettings();
});

/// Provider for voice command settings
final voiceCommandSettingsProvider = FutureProvider<VoiceCommandSettings>((ref) async {
  final service = await ref.watch(voiceCommandServiceProvider.future);
  return service.getVoiceSettings();
});

/// Provider for gesture navigation settings
final gestureNavigationSettingsProvider = FutureProvider<GestureNavigationSettings>((ref) async {
  final service = await ref.watch(gestureNavigationServiceProvider.future);
  return service.getGestureSettings();
});

/// Provider for language settings
final languageSettingsProvider = FutureProvider<LanguageSettings>((ref) async {
  final service = await ref.watch(multiLanguageServiceProvider.future);
  return service.getLanguageSettings();
});

/// Provider for device accessibility status
final deviceAccessibilityStatusProvider = FutureProvider<DeviceAccessibilityStatus>((ref) async {
  final service = await ref.watch(accessibilityServiceProvider.future);
  final result = await service.checkDeviceAccessibility();
  
  return result.fold(
    (failure) => const DeviceAccessibilityStatus(
      screenReaderEnabled: false,
      highContrastEnabled: false,
      largeTextEnabled: false,
      reduceMotionEnabled: false,
    ),
    (status) => status,
  );
});

/// Provider for supported languages
final supportedLanguagesProvider = FutureProvider<List<LanguageInfo>>((ref) async {
  final service = await ref.watch(multiLanguageServiceProvider.future);
  return service.getSupportedLanguages();
});

/// Provider for RTL languages
final rtlLanguagesProvider = FutureProvider<List<LanguageInfo>>((ref) async {
  final service = await ref.watch(multiLanguageServiceProvider.future);
  return service.getRtlLanguages();
});

/// Provider for text direction
final textDirectionProvider = FutureProvider<TextDirection>((ref) async {
  final service = await ref.watch(multiLanguageServiceProvider.future);
  return service.getTextDirection();
});

/// Provider for available voice commands
final availableVoiceCommandsProvider = FutureProvider<List<VoiceCommand>>((ref) async {
  final service = await ref.watch(voiceCommandServiceProvider.future);
  return service.getAvailableCommands();
});

/// Provider for available gestures
final availableGesturesProvider = FutureProvider<List<GestureMapping>>((ref) async {
  final service = await ref.watch(gestureNavigationServiceProvider.future);
  return service.getAvailableGestures();
});

/// Provider for accessibility report
final accessibilityReportProvider = FutureProvider<AccessibilityReport>((ref) async {
  final service = await ref.watch(accessibilityServiceProvider.future);
  final result = await service.generateAccessibilityReport();
  
  return result.fold(
    (failure) => AccessibilityReport(
      settings: const AccessibilitySettings(
        screenReaderEnabled: false,
        highContrastEnabled: false,
        colorBlindMode: ColorBlindMode.none,
        textScaleFactor: 1.0,
        fontFamily: AccessibilityFont.system,
        voiceCommandsEnabled: false,
        gestureNavigationEnabled: false,
        reduceMotion: false,
        reduceSound: false,
        accessibilityAnnouncements: true,
      ),
      deviceStatus: const DeviceAccessibilityStatus(
        screenReaderEnabled: false,
        highContrastEnabled: false,
        largeTextEnabled: false,
        reduceMotionEnabled: false,
      ),
      recommendations: [],
      complianceScore: 0.0,
      generatedAt: DateTime.now(),
    ),
    (report) => report,
  );
});

/// Provider for language report
final languageReportProvider = FutureProvider<LanguageReport>((ref) async {
  final service = await ref.watch(multiLanguageServiceProvider.future);
  final result = await service.generateLanguageReport();
  
  return result.fold(
    (failure) => LanguageReport(
      currentLanguage: const LanguageInfo(
        code: 'en',
        name: 'English',
        nativeName: 'English',
        isRtl: false,
        countryCode: 'US',
      ),
      supportedLanguages: [],
      rtlLanguages: [],
      translationCoverage: 0.0,
      isRtlEnabled: false,
      dateFormat: 'yyyy-MM-dd',
      numberFormat: 'en_US',
      currencyCode: 'USD',
      generatedAt: DateTime.now(),
    ),
    (report) => report,
  );
});

/// Provider for voice command test result
final voiceCommandTestProvider = FutureProvider<VoiceCommandTestResult>((ref) async {
  final service = await ref.watch(voiceCommandServiceProvider.future);
  final result = await service.testVoiceCommandSetup();
  
  return result.fold(
    (failure) => const VoiceCommandTestResult(
      speechToTextAvailable: false,
      textToSpeechAvailable: false,
      microphone: false,
      overallStatus: false,
    ),
    (testResult) => testResult,
  );
});

/// State notifier for accessibility theme
class AccessibilityThemeNotifier extends StateNotifier<AccessibilityTheme> {
  AccessibilityThemeNotifier() : super(AccessibilityTheme.system);
  
  void setHighContrast(bool enabled) {
    state = state.copyWith(highContrastEnabled: enabled);
  }
  
  void setColorBlindMode(ColorBlindMode mode) {
    state = state.copyWith(colorBlindMode: mode);
  }
  
  void setTextScaleFactor(double factor) {
    state = state.copyWith(textScaleFactor: factor);
  }
  
  void setFontFamily(AccessibilityFont font) {
    state = state.copyWith(fontFamily: font);
  }
  
  void setReduceMotion(bool enabled) {
    state = state.copyWith(reduceMotion: enabled);
  }
}

/// Provider for accessibility theme
final accessibilityThemeProvider = StateNotifierProvider<AccessibilityThemeNotifier, AccessibilityTheme>((ref) {
  return AccessibilityThemeNotifier();
});

/// State notifier for voice command state
class VoiceCommandStateNotifier extends StateNotifier<VoiceCommandState> {
  VoiceCommandStateNotifier() : super(VoiceCommandState.idle);
  
  void startListening() {
    state = VoiceCommandState.listening;
  }
  
  void stopListening() {
    state = VoiceCommandState.idle;
  }
  
  void processing() {
    state = VoiceCommandState.processing;
  }
  
  void error() {
    state = VoiceCommandState.error;
  }
}

/// Provider for voice command state
final voiceCommandStateProvider = StateNotifierProvider<VoiceCommandStateNotifier, VoiceCommandState>((ref) {
  return VoiceCommandStateNotifier();
});

// Data classes

class AccessibilityTheme {
  final bool highContrastEnabled;
  final ColorBlindMode colorBlindMode;
  final double textScaleFactor;
  final AccessibilityFont fontFamily;
  final bool reduceMotion;
  
  const AccessibilityTheme({
    required this.highContrastEnabled,
    required this.colorBlindMode,
    required this.textScaleFactor,
    required this.fontFamily,
    required this.reduceMotion,
  });
  
  static const system = AccessibilityTheme(
    highContrastEnabled: false,
    colorBlindMode: ColorBlindMode.none,
    textScaleFactor: 1.0,
    fontFamily: AccessibilityFont.system,
    reduceMotion: false,
  );
  
  AccessibilityTheme copyWith({
    bool? highContrastEnabled,
    ColorBlindMode? colorBlindMode,
    double? textScaleFactor,
    AccessibilityFont? fontFamily,
    bool? reduceMotion,
  }) {
    return AccessibilityTheme(
      highContrastEnabled: highContrastEnabled ?? this.highContrastEnabled,
      colorBlindMode: colorBlindMode ?? this.colorBlindMode,
      textScaleFactor: textScaleFactor ?? this.textScaleFactor,
      fontFamily: fontFamily ?? this.fontFamily,
      reduceMotion: reduceMotion ?? this.reduceMotion,
    );
  }
}

// Enums

enum VoiceCommandState {
  idle,
  listening,
  processing,
  error,
}

enum TextDirection {
  ltr,
  rtl,
}