import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/accessibility/accessibility_service.dart';
import 'package:koutu/services/accessibility/voice_command_service.dart';
import 'package:koutu/services/accessibility/gesture_navigation_service.dart';
import 'package:koutu/services/accessibility/multi_language_service.dart';
import 'package:koutu/providers/accessibility_provider.dart';
import 'package:intl/intl.dart';

class AccessibilitySettingsScreen extends ConsumerStatefulWidget {
  const AccessibilitySettingsScreen({super.key});

  @override
  ConsumerState<AccessibilitySettingsScreen> createState() => _AccessibilitySettingsScreenState();
}

class _AccessibilitySettingsScreenState extends ConsumerState<AccessibilitySettingsScreen> {
  final _dateFormat = DateFormat('MMM d, yyyy h:mm a');
  bool _isLoading = false;
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Accessibility & Inclusive Design'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: () => _showAccessibilityInfoDialog(),
          ),
        ],
      ),
      body: ListView(
        children: [
          _buildScreenReaderSection(),
          _buildVisualAccessibilitySection(),
          _buildTextAndFontSection(),
          _buildVoiceCommandSection(),
          _buildGestureNavigationSection(),
          _buildLanguageSection(),
          _buildMotionAndSoundSection(),
          _buildAccessibilityReportSection(),
          _buildTestingSection(),
        ],
      ),
    );
  }
  
  Widget _buildScreenReaderSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(accessibilitySettingsProvider);
        final deviceStatusAsync = ref.watch(deviceAccessibilityStatusProvider);
        
        return settingsAsync.when(
          data: (settings) => deviceStatusAsync.when(
            data: (deviceStatus) => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: Text(
                    'SCREEN READER SUPPORT',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ),
                SwitchListTile(
                  secondary: Icon(
                    Icons.visibility,
                    color: deviceStatus.screenReaderEnabled ? Colors.green : Colors.grey,
                  ),
                  title: const Text('Screen Reader Support'),
                  subtitle: Text(
                    deviceStatus.screenReaderEnabled
                        ? 'Device screen reader detected'
                        : 'Enable for better accessibility',
                  ),
                  value: settings.screenReaderEnabled,
                  onChanged: _isLoading ? null : (value) => _updateScreenReaderSettings(value),
                ),
                SwitchListTile(
                  secondary: const Icon(Icons.campaign),
                  title: const Text('Accessibility Announcements'),
                  subtitle: const Text('Announce important changes and updates'),
                  value: settings.accessibilityAnnouncements,
                  onChanged: _isLoading ? null : (value) => _updateAnnouncementSettings(value),
                ),
              ],
            ),
            loading: () => const CircularProgressIndicator(),
            error: (error, _) => Text('Error: $error'),
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildVisualAccessibilitySection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(accessibilitySettingsProvider);
        
        return settingsAsync.when(
          data: (settings) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                child: Text(
                  'VISUAL ACCESSIBILITY',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              SwitchListTile(
                secondary: const Icon(Icons.contrast),
                title: const Text('High Contrast Mode'),
                subtitle: const Text('Improve visibility with high contrast colors'),
                value: settings.highContrastEnabled,
                onChanged: _isLoading ? null : (value) => _updateHighContrastSettings(value),
              ),
              ListTile(
                leading: const Icon(Icons.color_lens),
                title: const Text('Color Blind Mode'),
                subtitle: Text(_formatColorBlindMode(settings.colorBlindMode)),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _showColorBlindModeDialog(settings.colorBlindMode),
              ),
            ],
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildTextAndFontSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(accessibilitySettingsProvider);
        
        return settingsAsync.when(
          data: (settings) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                child: Text(
                  'TEXT & FONT SETTINGS',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.format_size),
                title: const Text('Text Scale Factor'),
                subtitle: Text('${(settings.textScaleFactor * 100).toInt()}%'),
                trailing: SizedBox(
                  width: 150,
                  child: Slider(
                    value: settings.textScaleFactor,
                    min: 0.5,
                    max: 2.0,
                    divisions: 15,
                    label: '${(settings.textScaleFactor * 100).toInt()}%',
                    onChanged: _isLoading ? null : (value) => _updateTextScaleSettings(value),
                  ),
                ),
              ),
              ListTile(
                leading: const Icon(Icons.font_download),
                title: const Text('Font Family'),
                subtitle: Text(_formatFontFamily(settings.fontFamily)),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _showFontFamilyDialog(settings.fontFamily),
              ),
            ],
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildVoiceCommandSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(voiceCommandSettingsProvider);
        final testResultAsync = ref.watch(voiceCommandTestProvider);
        final stateAsync = ref.watch(voiceCommandStateProvider);
        
        return settingsAsync.when(
          data: (settings) => testResultAsync.when(
            data: (testResult) => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: Text(
                    'VOICE COMMANDS',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ),
                SwitchListTile(
                  secondary: Icon(
                    Icons.mic,
                    color: testResult.overallStatus ? Colors.green : Colors.red,
                  ),
                  title: const Text('Voice Commands'),
                  subtitle: Text(
                    testResult.overallStatus
                        ? 'Voice commands are available'
                        : 'Voice commands not available',
                  ),
                  value: settings.enabled && testResult.overallStatus,
                  onChanged: _isLoading || !testResult.overallStatus 
                      ? null 
                      : (value) => _updateVoiceCommandSettings(value),
                ),
                if (settings.enabled) ...[
                  ListTile(
                    leading: const Icon(Icons.language),
                    title: const Text('Voice Language'),
                    subtitle: Text(settings.language),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _showVoiceLanguageDialog(settings.language),
                  ),
                  ListTile(
                    leading: const Icon(Icons.volume_up),
                    title: const Text('Wake Word'),
                    subtitle: Text('"${settings.wakeWord}"'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _showWakeWordDialog(settings.wakeWord),
                  ),
                  ListTile(
                    leading: const Icon(Icons.help),
                    title: const Text('Voice Commands Help'),
                    subtitle: const Text('Learn available voice commands'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _showVoiceCommandsHelpDialog(),
                  ),
                ],
              ],
            ),
            loading: () => const CircularProgressIndicator(),
            error: (error, _) => Text('Error: $error'),
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildGestureNavigationSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(gestureNavigationSettingsProvider);
        
        return settingsAsync.when(
          data: (settings) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                child: Text(
                  'GESTURE NAVIGATION',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              SwitchListTile(
                secondary: const Icon(Icons.gesture),
                title: const Text('Gesture Navigation'),
                subtitle: const Text('Navigate using gestures and swipes'),
                value: settings.enabled,
                onChanged: _isLoading ? null : (value) => _updateGestureNavigationSettings(value),
              ),
              if (settings.enabled) ...[
                SwitchListTile(
                  secondary: const Icon(Icons.swipe),
                  title: const Text('Swipe Gestures'),
                  subtitle: const Text('Navigate with swipe gestures'),
                  value: settings.swipeGesturesEnabled,
                  onChanged: _isLoading ? null : (value) => _updateSwipeGestureSettings(value),
                ),
                ListTile(
                  leading: const Icon(Icons.help),
                  title: const Text('Gesture Help'),
                  subtitle: const Text('Learn available gestures'),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => _showGestureHelpDialog(),
                ),
              ],
            ],
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildLanguageSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(languageSettingsProvider);
        final textDirectionAsync = ref.watch(textDirectionProvider);
        
        return settingsAsync.when(
          data: (settings) => textDirectionAsync.when(
            data: (textDirection) => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: Text(
                    'LANGUAGE & LOCALIZATION',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ),
                ListTile(
                  leading: const Icon(Icons.language),
                  title: const Text('Language'),
                  subtitle: Text('${settings.currentLanguage.nativeName} (${settings.currentLanguage.name})'),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (settings.currentLanguage.isRtl)
                        const Icon(Icons.format_textdirection_r_to_l, size: 16),
                      const Icon(Icons.chevron_right),
                    ],
                  ),
                  onTap: () => _showLanguageSelectionDialog(),
                ),
                ListTile(
                  leading: const Icon(Icons.date_range),
                  title: const Text('Date Format'),
                  subtitle: Text(settings.dateFormat),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => _showDateFormatDialog(settings.dateFormat),
                ),
                ListTile(
                  leading: const Icon(Icons.attach_money),
                  title: const Text('Currency'),
                  subtitle: Text(settings.currencyCode),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => _showCurrencyDialog(settings.currencyCode),
                ),
              ],
            ),
            loading: () => const CircularProgressIndicator(),
            error: (error, _) => Text('Error: $error'),
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildMotionAndSoundSection() {
    return Consumer(
      builder: (context, ref, child) {
        final settingsAsync = ref.watch(accessibilitySettingsProvider);
        
        return settingsAsync.when(
          data: (settings) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                child: Text(
                  'MOTION & SOUND',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              SwitchListTile(
                secondary: const Icon(Icons.motion_photos_off),
                title: const Text('Reduce Motion'),
                subtitle: const Text('Minimize animations and transitions'),
                value: settings.reduceMotion,
                onChanged: _isLoading ? null : (value) => _updateReduceMotionSettings(value),
              ),
              SwitchListTile(
                secondary: const Icon(Icons.volume_off),
                title: const Text('Reduce Sound'),
                subtitle: const Text('Minimize sound effects and audio'),
                value: settings.reduceSound,
                onChanged: _isLoading ? null : (value) => _updateReduceSoundSettings(value),
              ),
            ],
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildAccessibilityReportSection() {
    return Consumer(
      builder: (context, ref, child) {
        final reportAsync = ref.watch(accessibilityReportProvider);
        
        return reportAsync.when(
          data: (report) => Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
                child: Text(
                  'ACCESSIBILITY REPORT',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
              ListTile(
                leading: Icon(
                  Icons.assessment,
                  color: _getComplianceColor(report.complianceScore),
                ),
                title: const Text('Accessibility Compliance'),
                subtitle: Text('Score: ${report.complianceScore.toStringAsFixed(1)}%'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _showAccessibilityReportDialog(report),
              ),
              if (report.recommendations.isNotEmpty)
                ListTile(
                  leading: const Icon(Icons.lightbulb, color: Colors.orange),
                  title: const Text('Recommendations'),
                  subtitle: Text('${report.recommendations.length} suggestions available'),
                  trailing: const Icon(Icons.chevron_right),
                  onTap: () => _showRecommendationsDialog(report.recommendations),
                ),
            ],
          ),
          loading: () => const CircularProgressIndicator(),
          error: (error, _) => Text('Error: $error'),
        );
      },
    );
  }
  
  Widget _buildTestingSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'TESTING & VALIDATION',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.mic_none),
          title: const Text('Test Voice Commands'),
          subtitle: const Text('Test voice recognition and commands'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _testVoiceCommands(),
        ),
        ListTile(
          leading: const Icon(Icons.gesture),
          title: const Text('Test Gesture Navigation'),
          subtitle: const Text('Test gesture recognition'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _testGestureNavigation(),
        ),
        ListTile(
          leading: const Icon(Icons.speaker),
          title: const Text('Test Screen Reader'),
          subtitle: const Text('Test screen reader announcements'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _testScreenReader(),
        ),
        const SizedBox(height: 32),
      ],
    );
  }
  
  // Update methods
  
  Future<void> _updateScreenReaderSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: enabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Screen reader settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateAnnouncementSettings(bool enabled) async {
    // Similar implementation for announcement settings
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: enabled,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Announcement settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateHighContrastSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: enabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('High contrast settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateTextScaleSettings(double factor) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: factor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateVoiceCommandSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(voiceCommandServiceProvider.future);
      final currentSettings = service.getVoiceSettings();
      
      final updatedSettings = VoiceCommandSettings(
        enabled: enabled,
        language: currentSettings.language,
        speechRate: currentSettings.speechRate,
        speechPitch: currentSettings.speechPitch,
        speechVolume: currentSettings.speechVolume,
        wakeWord: currentSettings.wakeWord,
        confidenceThreshold: currentSettings.confidenceThreshold,
      );
      
      final result = await service.updateVoiceSettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(voiceCommandSettingsProvider);
          _showSuccess('Voice command settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateGestureNavigationSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(gestureNavigationServiceProvider.future);
      final currentSettings = service.getGestureSettings();
      
      final updatedSettings = GestureNavigationSettings(
        enabled: enabled,
        swipeGesturesEnabled: currentSettings.swipeGesturesEnabled,
        tapGesturesEnabled: currentSettings.tapGesturesEnabled,
        longPressGesturesEnabled: currentSettings.longPressGesturesEnabled,
        swipeSensitivity: currentSettings.swipeSensitivity,
        tapSensitivity: currentSettings.tapSensitivity,
        longPressDuration: currentSettings.longPressDuration,
        customGestures: currentSettings.customGestures,
      );
      
      final result = await service.updateGestureSettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(gestureNavigationSettingsProvider);
          _showSuccess('Gesture navigation settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateSwipeGestureSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(gestureNavigationServiceProvider.future);
      final currentSettings = service.getGestureSettings();
      
      final updatedSettings = GestureNavigationSettings(
        enabled: currentSettings.enabled,
        swipeGesturesEnabled: enabled,
        tapGesturesEnabled: currentSettings.tapGesturesEnabled,
        longPressGesturesEnabled: currentSettings.longPressGesturesEnabled,
        swipeSensitivity: currentSettings.swipeSensitivity,
        tapSensitivity: currentSettings.tapSensitivity,
        longPressDuration: currentSettings.longPressDuration,
        customGestures: currentSettings.customGestures,
      );
      
      final result = await service.updateGestureSettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(gestureNavigationSettingsProvider);
          _showSuccess('Swipe gesture settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateReduceMotionSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: enabled,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Reduce motion settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateReduceSoundSettings(bool enabled) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: enabled,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Reduce sound settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  // Dialog methods
  
  void _showColorBlindModeDialog(ColorBlindMode currentMode) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Color Blind Mode'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: ColorBlindMode.values.map((mode) {
            return RadioListTile<ColorBlindMode>(
              title: Text(_formatColorBlindMode(mode)),
              value: mode,
              groupValue: currentMode,
              onChanged: (value) async {
                Navigator.pop(context);
                if (value != null) {
                  await _updateColorBlindMode(value);
                }
              },
            );
          }).toList(),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
  
  void _showFontFamilyDialog(AccessibilityFont currentFont) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Font Family'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: AccessibilityFont.values.map((font) {
            return RadioListTile<AccessibilityFont>(
              title: Text(_formatFontFamily(font)),
              value: font,
              groupValue: currentFont,
              onChanged: (value) async {
                Navigator.pop(context);
                if (value != null) {
                  await _updateFontFamily(value);
                }
              },
            );
          }).toList(),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
  
  void _showLanguageSelectionDialog() {
    showDialog(
      context: context,
      builder: (context) => Consumer(
        builder: (context, ref, child) {
          final languagesAsync = ref.watch(supportedLanguagesProvider);
          
          return languagesAsync.when(
            data: (languages) => AlertDialog(
              title: const Text('Select Language'),
              content: SizedBox(
                width: double.maxFinite,
                child: ListView.builder(
                  shrinkWrap: true,
                  itemCount: languages.length,
                  itemBuilder: (context, index) {
                    final language = languages[index];
                    return ListTile(
                      title: Text(language.nativeName),
                      subtitle: Text(language.name),
                      trailing: language.isRtl 
                          ? const Icon(Icons.format_textdirection_r_to_l, size: 16)
                          : null,
                      onTap: () async {
                        Navigator.pop(context);
                        await _updateLanguage(language.code);
                      },
                    );
                  },
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel'),
                ),
              ],
            ),
            loading: () => const AlertDialog(
              content: CircularProgressIndicator(),
            ),
            error: (error, _) => AlertDialog(
              title: const Text('Error'),
              content: Text('Failed to load languages: $error'),
            ),
          );
        },
      ),
    );
  }
  
  void _showAccessibilityReportDialog(AccessibilityReport report) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Accessibility Report'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Compliance Score: ${report.complianceScore.toStringAsFixed(1)}%'),
              Text('Generated: ${_dateFormat.format(report.generatedAt)}'),
              const SizedBox(height: 16),
              const Text('Device Status:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Screen Reader: ${report.deviceStatus.screenReaderEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• High Contrast: ${report.deviceStatus.highContrastEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• Large Text: ${report.deviceStatus.largeTextEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• Reduce Motion: ${report.deviceStatus.reduceMotionEnabled ? 'Enabled' : 'Disabled'}'),
              const SizedBox(height: 16),
              const Text('App Settings:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text('• Screen Reader: ${report.settings.screenReaderEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• High Contrast: ${report.settings.highContrastEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• Color Blind Mode: ${_formatColorBlindMode(report.settings.colorBlindMode)}'),
              Text('• Text Scale: ${(report.settings.textScaleFactor * 100).toInt()}%'),
              Text('• Voice Commands: ${report.settings.voiceCommandsEnabled ? 'Enabled' : 'Disabled'}'),
              Text('• Gesture Navigation: ${report.settings.gestureNavigationEnabled ? 'Enabled' : 'Disabled'}'),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
  
  void _showRecommendationsDialog(List<String> recommendations) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Accessibility Recommendations'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: recommendations.map((rec) => 
              Padding(
                padding: const EdgeInsets.only(bottom: 8.0),
                child: Text('• $rec'),
              ),
            ).toList(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
  
  void _showVoiceCommandsHelpDialog() {
    showDialog(
      context: context,
      builder: (context) => Consumer(
        builder: (context, ref, child) {
          final commandsAsync = ref.watch(availableVoiceCommandsProvider);
          
          return commandsAsync.when(
            data: (commands) => AlertDialog(
              title: const Text('Voice Commands Help'),
              content: SizedBox(
                width: double.maxFinite,
                child: ListView.builder(
                  shrinkWrap: true,
                  itemCount: commands.length,
                  itemBuilder: (context, index) {
                    final command = commands[index];
                    return ListTile(
                      title: Text(command.phrases.first),
                      subtitle: Text(command.description),
                      dense: true,
                    );
                  },
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Close'),
                ),
              ],
            ),
            loading: () => const AlertDialog(
              content: CircularProgressIndicator(),
            ),
            error: (error, _) => AlertDialog(
              title: const Text('Error'),
              content: Text('Failed to load commands: $error'),
            ),
          );
        },
      ),
    );
  }
  
  void _showGestureHelpDialog() {
    showDialog(
      context: context,
      builder: (context) => Consumer(
        builder: (context, ref, child) {
          final gesturesAsync = ref.watch(availableGesturesProvider);
          
          return gesturesAsync.when(
            data: (gestures) => AlertDialog(
              title: const Text('Gesture Navigation Help'),
              content: SizedBox(
                width: double.maxFinite,
                child: ListView.builder(
                  shrinkWrap: true,
                  itemCount: gestures.length,
                  itemBuilder: (context, index) {
                    final gesture = gestures[index];
                    return ListTile(
                      title: Text(_formatGestureType(gesture.gesture)),
                      subtitle: Text(gesture.description),
                      dense: true,
                    );
                  },
                ),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Close'),
                ),
              ],
            ),
            loading: () => const AlertDialog(
              content: CircularProgressIndicator(),
            ),
            error: (error, _) => AlertDialog(
              title: const Text('Error'),
              content: Text('Failed to load gestures: $error'),
            ),
          );
        },
      ),
    );
  }
  
  void _showAccessibilityInfoDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Accessibility & Inclusive Design'),
        content: const SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'This app is designed to be accessible to all users. Features include:',
              ),
              SizedBox(height: 16),
              Text(
                '• Comprehensive screen reader support\n'
                '• High contrast and color blind modes\n'
                '• Voice command integration\n'
                '• Gesture-based navigation\n'
                '• Text scaling and font options\n'
                '• Multi-language support with RTL\n'
                '• Reduced motion and sound options\n'
                '• Accessibility compliance reporting',
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Got it'),
          ),
        ],
      ),
    );
  }
  
  // Test methods
  
  Future<void> _testVoiceCommands() async {
    try {
      final service = await ref.read(voiceCommandServiceProvider.future);
      
      // Test voice command setup
      final testResult = await service.testVoiceCommandSetup();
      
      testResult.fold(
        (failure) => _showError(failure.message),
        (result) {
          showDialog(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('Voice Command Test'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Speech-to-Text: ${result.speechToTextAvailable ? 'Available' : 'Not Available'}'),
                  Text('Text-to-Speech: ${result.textToSpeechAvailable ? 'Available' : 'Not Available'}'),
                  Text('Microphone: ${result.microphone ? 'Available' : 'Not Available'}'),
                  Text('Overall Status: ${result.overallStatus ? 'Working' : 'Not Working'}'),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Close'),
                ),
                if (result.overallStatus)
                  ElevatedButton(
                    onPressed: () async {
                      Navigator.pop(context);
                      await service.speak('Voice commands are working correctly!');
                    },
                    child: const Text('Test Speech'),
                  ),
              ],
            ),
          );
        },
      );
    } catch (e) {
      _showError('Failed to test voice commands: $e');
    }
  }
  
  Future<void> _testGestureNavigation() async {
    _showSuccess('Gesture navigation test: Try swiping left to go back');
  }
  
  Future<void> _testScreenReader() async {
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      
      final result = await service.announceToScreenReader(
        'Screen reader test: This is a test announcement from the accessibility settings.',
      );
      
      result.fold(
        (failure) => _showError(failure.message),
        (_) => _showSuccess('Screen reader test announcement sent'),
      );
    } catch (e) {
      _showError('Failed to test screen reader: $e');
    }
  }
  
  // Helper methods
  
  Future<void> _updateColorBlindMode(ColorBlindMode mode) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: mode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: currentSettings.fontFamily,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Color blind mode updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateFontFamily(AccessibilityFont font) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(accessibilityServiceProvider.future);
      final currentSettings = service.getAccessibilitySettings();
      
      final updatedSettings = AccessibilitySettings(
        screenReaderEnabled: currentSettings.screenReaderEnabled,
        highContrastEnabled: currentSettings.highContrastEnabled,
        colorBlindMode: currentSettings.colorBlindMode,
        textScaleFactor: currentSettings.textScaleFactor,
        fontFamily: font,
        voiceCommandsEnabled: currentSettings.voiceCommandsEnabled,
        gestureNavigationEnabled: currentSettings.gestureNavigationEnabled,
        reduceMotion: currentSettings.reduceMotion,
        reduceSound: currentSettings.reduceSound,
        accessibilityAnnouncements: currentSettings.accessibilityAnnouncements,
      );
      
      final result = await service.updateAccessibilitySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(accessibilitySettingsProvider);
          _showSuccess('Font family updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  Future<void> _updateLanguage(String languageCode) async {
    setState(() => _isLoading = true);
    
    try {
      final service = await ref.read(multiLanguageServiceProvider.future);
      
      final result = await service.setCurrentLanguage(languageCode);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          ref.invalidate(languageSettingsProvider);
          ref.invalidate(textDirectionProvider);
          _showSuccess('Language updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  String _formatColorBlindMode(ColorBlindMode mode) {
    switch (mode) {
      case ColorBlindMode.none:
        return 'None';
      case ColorBlindMode.protanopia:
        return 'Protanopia (Red-blind)';
      case ColorBlindMode.deuteranopia:
        return 'Deuteranopia (Green-blind)';
      case ColorBlindMode.tritanopia:
        return 'Tritanopia (Blue-blind)';
      case ColorBlindMode.monochromacy:
        return 'Monochromacy (Grayscale)';
    }
  }
  
  String _formatFontFamily(AccessibilityFont font) {
    switch (font) {
      case AccessibilityFont.system:
        return 'System Default';
      case AccessibilityFont.dyslexic:
        return 'Dyslexic-friendly';
      case AccessibilityFont.monospace:
        return 'Monospace';
      case AccessibilityFont.sansSerif:
        return 'Sans Serif';
      case AccessibilityFont.serif:
        return 'Serif';
    }
  }
  
  String _formatGestureType(GestureType type) {
    switch (type) {
      case GestureType.swipeLeft:
        return 'Swipe Left';
      case GestureType.swipeRight:
        return 'Swipe Right';
      case GestureType.swipeUp:
        return 'Swipe Up';
      case GestureType.swipeDown:
        return 'Swipe Down';
      case GestureType.tap:
        return 'Tap';
      case GestureType.doubleTap:
        return 'Double Tap';
      case GestureType.longPress:
        return 'Long Press';
      case GestureType.pinch:
        return 'Pinch';
      case GestureType.rotate:
        return 'Rotate';
      case GestureType.twoFingerTap:
        return 'Two Finger Tap';
      case GestureType.threeFingerTap:
        return 'Three Finger Tap';
    }
  }
  
  Color _getComplianceColor(double score) {
    if (score >= 90) return Colors.green;
    if (score >= 70) return Colors.orange;
    return Colors.red;
  }
  
  void _showVoiceLanguageDialog(String currentLanguage) {
    // Implementation for voice language selection
  }
  
  void _showWakeWordDialog(String currentWakeWord) {
    // Implementation for wake word customization
  }
  
  void _showDateFormatDialog(String currentFormat) {
    // Implementation for date format selection
  }
  
  void _showCurrencyDialog(String currentCurrency) {
    // Implementation for currency selection
  }
  
  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.red,
      ),
    );
  }
  
  void _showSuccess(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.green,
      ),
    );
  }
}