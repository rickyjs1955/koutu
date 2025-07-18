import 'package:flutter/services.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';

/// Service for voice assistant integration (Siri & Google Assistant)
class VoiceAssistantService {
  final SharedPreferences _preferences;
  final MethodChannel _channel;
  
  // Voice assistant settings keys
  static const String _voiceAssistantEnabledKey = 'voice_assistant_enabled';
  static const String _siriEnabledKey = 'siri_enabled';
  static const String _googleAssistantEnabledKey = 'google_assistant_enabled';
  static const String _voiceAssistantConfigKey = 'voice_assistant_config';
  static const String _shortcutsKey = 'voice_shortcuts';
  static const String _intentHistoryKey = 'intent_history';
  
  VoiceAssistantService({
    required SharedPreferences preferences,
    MethodChannel? channel,
  }) : _preferences = preferences,
       _channel = channel ?? const MethodChannel('koutu/voice_assistant');
  
  /// Initialize voice assistant service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Check voice assistant availability
      final availability = await _channel.invokeMethod<Map<dynamic, dynamic>>('checkVoiceAssistantAvailability');
      
      if (availability == null) {
        return Left(ServiceFailure('Failed to check voice assistant availability'));
      }
      
      final siriAvailable = availability['siri'] ?? false;
      final googleAssistantAvailable = availability['googleAssistant'] ?? false;
      
      if (!siriAvailable && !googleAssistantAvailable) {
        return Left(ServiceFailure('No voice assistants available'));
      }
      
      // Set up voice assistant message handler
      _channel.setMethodCallHandler(_handleVoiceAssistantMessage);
      
      // Register voice shortcuts
      await _registerVoiceShortcuts();
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize voice assistant: $e'));
    }
  }
  
  /// Get voice assistant settings
  VoiceAssistantSettings getVoiceAssistantSettings() {
    final config = _getVoiceAssistantConfig();
    
    return VoiceAssistantSettings(
      enabled: _preferences.getBool(_voiceAssistantEnabledKey) ?? false,
      siriEnabled: _preferences.getBool(_siriEnabledKey) ?? false,
      googleAssistantEnabled: _preferences.getBool(_googleAssistantEnabledKey) ?? false,
      customShortcutsEnabled: config['customShortcuts'] ?? true,
      contextualSuggestionsEnabled: config['contextualSuggestions'] ?? true,
      personalizedResponsesEnabled: config['personalizedResponses'] ?? true,
      quickActionsEnabled: config['quickActions'] ?? true,
      outfitSuggestionsEnabled: config['outfitSuggestions'] ?? true,
      weatherIntegrationEnabled: config['weatherIntegration'] ?? true,
      smartRemindersEnabled: config['smartReminders'] ?? true,
      voiceResponseEnabled: config['voiceResponse'] ?? true,
      hapticFeedbackEnabled: config['hapticFeedback'] ?? true,
    );
  }
  
  /// Update voice assistant settings
  Future<Either<Failure, void>> updateVoiceAssistantSettings(
    VoiceAssistantSettings settings,
  ) async {
    try {
      await _preferences.setBool(_voiceAssistantEnabledKey, settings.enabled);
      await _preferences.setBool(_siriEnabledKey, settings.siriEnabled);
      await _preferences.setBool(_googleAssistantEnabledKey, settings.googleAssistantEnabled);
      
      final config = {
        'customShortcuts': settings.customShortcutsEnabled,
        'contextualSuggestions': settings.contextualSuggestionsEnabled,
        'personalizedResponses': settings.personalizedResponsesEnabled,
        'quickActions': settings.quickActionsEnabled,
        'outfitSuggestions': settings.outfitSuggestionsEnabled,
        'weatherIntegration': settings.weatherIntegrationEnabled,
        'smartReminders': settings.smartRemindersEnabled,
        'voiceResponse': settings.voiceResponseEnabled,
        'hapticFeedback': settings.hapticFeedbackEnabled,
      };
      
      await _preferences.setString(_voiceAssistantConfigKey, json.encode(config));
      
      // Update voice shortcuts
      if (settings.enabled) {
        await _registerVoiceShortcuts();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update voice assistant settings: $e'));
    }
  }
  
  /// Register Siri shortcuts
  Future<Either<Failure, void>> registerSiriShortcuts(
    List<SiriShortcut> shortcuts,
  ) async {
    try {
      final settings = getVoiceAssistantSettings();
      
      if (!settings.enabled || !settings.siriEnabled) {
        return Left(ServiceFailure('Siri integration is disabled'));
      }
      
      final shortcutData = shortcuts.map((shortcut) => shortcut.toJson()).toList();
      
      await _channel.invokeMethod('registerSiriShortcuts', {
        'shortcuts': shortcutData,
      });
      
      await _storeShortcuts('siri', shortcutData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to register Siri shortcuts: $e'));
    }
  }
  
  /// Register Google Assistant actions
  Future<Either<Failure, void>> registerGoogleAssistantActions(
    List<GoogleAssistantAction> actions,
  ) async {
    try {
      final settings = getVoiceAssistantSettings();
      
      if (!settings.enabled || !settings.googleAssistantEnabled) {
        return Left(ServiceFailure('Google Assistant integration is disabled'));
      }
      
      final actionData = actions.map((action) => action.toJson()).toList();
      
      await _channel.invokeMethod('registerGoogleAssistantActions', {
        'actions': actionData,
      });
      
      await _storeShortcuts('googleAssistant', actionData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to register Google Assistant actions: $e'));
    }
  }
  
  /// Handle voice intent
  Future<Either<Failure, VoiceIntentResponse>> handleVoiceIntent(
    VoiceIntent intent,
  ) async {
    try {
      final settings = getVoiceAssistantSettings();
      
      if (!settings.enabled) {
        return Left(ServiceFailure('Voice assistant is disabled'));
      }
      
      final response = await _processVoiceIntent(intent);
      
      // Log intent for analytics
      await _logIntentUsage(intent);
      
      return Right(response);
    } catch (e) {
      return Left(ServiceFailure('Failed to handle voice intent: $e'));
    }
  }
  
  /// Create custom voice shortcut
  Future<Either<Failure, void>> createCustomVoiceShortcut(
    CustomVoiceShortcut shortcut,
  ) async {
    try {
      final settings = getVoiceAssistantSettings();
      
      if (!settings.enabled || !settings.customShortcutsEnabled) {
        return Left(ServiceFailure('Custom shortcuts are disabled'));
      }
      
      await _channel.invokeMethod('createCustomVoiceShortcut', {
        'shortcut': shortcut.toJson(),
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create custom voice shortcut: $e'));
    }
  }
  
  /// Get voice assistant capabilities
  Future<Either<Failure, VoiceAssistantCapabilities>> getVoiceAssistantCapabilities() async {
    try {
      final capabilities = await _channel.invokeMethod<Map<dynamic, dynamic>>('getVoiceAssistantCapabilities');
      
      if (capabilities == null) {
        return Left(ServiceFailure('Failed to get voice assistant capabilities'));
      }
      
      return Right(VoiceAssistantCapabilities.fromJson(capabilities));
    } catch (e) {
      return Left(ServiceFailure('Failed to get voice assistant capabilities: $e'));
    }
  }
  
  /// Get available voice shortcuts
  Future<Either<Failure, List<VoiceShortcut>>> getAvailableVoiceShortcuts() async {
    try {
      final shortcuts = await _channel.invokeMethod<List<dynamic>>('getAvailableVoiceShortcuts');
      
      if (shortcuts == null) {
        return const Right([]);
      }
      
      final voiceShortcuts = shortcuts.map((shortcut) => VoiceShortcut.fromJson(shortcut)).toList();
      return Right(voiceShortcuts);
    } catch (e) {
      return Left(ServiceFailure('Failed to get available voice shortcuts: $e'));
    }
  }
  
  /// Donate intent to voice assistant
  Future<Either<Failure, void>> donateIntentToVoiceAssistant(
    VoiceIntent intent,
  ) async {
    try {
      await _channel.invokeMethod('donateIntent', {
        'intent': intent.toJson(),
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to donate intent: $e'));
    }
  }
  
  /// Delete voice shortcut
  Future<Either<Failure, void>> deleteVoiceShortcut(
    String shortcutId,
  ) async {
    try {
      await _channel.invokeMethod('deleteVoiceShortcut', {
        'shortcutId': shortcutId,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to delete voice shortcut: $e'));
    }
  }
  
  /// Get voice intent history
  Future<Either<Failure, List<VoiceIntentHistoryEntry>>> getVoiceIntentHistory() async {
    try {
      final historyData = _getIntentHistory();
      
      final history = historyData.map((entry) => VoiceIntentHistoryEntry.fromJson(entry)).toList();
      return Right(history);
    } catch (e) {
      return Left(ServiceFailure('Failed to get voice intent history: $e'));
    }
  }
  
  /// Generate contextual suggestions
  Future<Either<Failure, List<VoiceContextualSuggestion>>> generateContextualSuggestions(
    String context,
  ) async {
    try {
      final settings = getVoiceAssistantSettings();
      
      if (!settings.enabled || !settings.contextualSuggestionsEnabled) {
        return Left(ServiceFailure('Contextual suggestions are disabled'));
      }
      
      final suggestions = await _generateContextualSuggestions(context);
      return Right(suggestions);
    } catch (e) {
      return Left(ServiceFailure('Failed to generate contextual suggestions: $e'));
    }
  }
  
  /// Test voice assistant integration
  Future<Either<Failure, VoiceAssistantTestResult>> testVoiceAssistantIntegration() async {
    try {
      final testResult = await _channel.invokeMethod<Map<dynamic, dynamic>>('testVoiceAssistantIntegration');
      
      if (testResult == null) {
        return Left(ServiceFailure('Failed to test voice assistant integration'));
      }
      
      return Right(VoiceAssistantTestResult.fromJson(testResult));
    } catch (e) {
      return Left(ServiceFailure('Failed to test voice assistant integration: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _handleVoiceAssistantMessage(MethodCall call) async {
    switch (call.method) {
      case 'voiceIntentReceived':
        final intentData = call.arguments['intent'] as Map<String, dynamic>;
        final intent = VoiceIntent.fromJson(intentData);
        await handleVoiceIntent(intent);
        break;
        
      case 'siriShortcutTapped':
        final shortcutId = call.arguments['shortcutId'] as String;
        await _handleSiriShortcutTapped(shortcutId);
        break;
        
      case 'googleAssistantActionTriggered':
        final actionId = call.arguments['actionId'] as String;
        await _handleGoogleAssistantActionTriggered(actionId);
        break;
        
      case 'voiceAssistantConnected':
        final assistant = call.arguments['assistant'] as String;
        await _handleVoiceAssistantConnected(assistant);
        break;
        
      case 'voiceAssistantDisconnected':
        final assistant = call.arguments['assistant'] as String;
        await _handleVoiceAssistantDisconnected(assistant);
        break;
    }
  }
  
  Future<void> _handleSiriShortcutTapped(String shortcutId) async {
    // Handle Siri shortcut tap
    final response = await _executeShortcut(shortcutId);
    
    await _channel.invokeMethod('sendSiriResponse', {
      'response': response.toJson(),
    });
  }
  
  Future<void> _handleGoogleAssistantActionTriggered(String actionId) async {
    // Handle Google Assistant action
    final response = await _executeAction(actionId);
    
    await _channel.invokeMethod('sendGoogleAssistantResponse', {
      'response': response.toJson(),
    });
  }
  
  Future<void> _handleVoiceAssistantConnected(String assistant) async {
    // Handle voice assistant connection
  }
  
  Future<void> _handleVoiceAssistantDisconnected(String assistant) async {
    // Handle voice assistant disconnection
  }
  
  Future<void> _registerVoiceShortcuts() async {
    final settings = getVoiceAssistantSettings();
    
    if (!settings.enabled) {
      return;
    }
    
    // Register Siri shortcuts
    if (settings.siriEnabled) {
      await _registerSiriShortcuts();
    }
    
    // Register Google Assistant actions
    if (settings.googleAssistantEnabled) {
      await _registerGoogleAssistantActions();
    }
  }
  
  Future<void> _registerSiriShortcuts() async {
    final siriShortcuts = [
      SiriShortcut(
        identifier: 'quick_photo',
        phrase: 'Take a quick photo',
        title: 'Quick Photo',
        subtitle: 'Take a photo with Koutu',
        systemImageName: 'camera',
        intentClass: 'QuickPhotoIntent',
      ),
      SiriShortcut(
        identifier: 'view_outfits',
        phrase: 'Show my outfits',
        title: 'View Outfits',
        subtitle: 'View today\'s outfit suggestions',
        systemImageName: 'tshirt',
        intentClass: 'ViewOutfitsIntent',
      ),
      SiriShortcut(
        identifier: 'check_weather',
        phrase: 'Check weather for outfit',
        title: 'Weather Check',
        subtitle: 'Check weather for outfit planning',
        systemImageName: 'cloud.sun',
        intentClass: 'CheckWeatherIntent',
      ),
      SiriShortcut(
        identifier: 'open_wardrobe',
        phrase: 'Open my wardrobe',
        title: 'Open Wardrobe',
        subtitle: 'View my wardrobe collection',
        systemImageName: 'archivebox',
        intentClass: 'OpenWardrobeIntent',
      ),
    ];
    
    await registerSiriShortcuts(siriShortcuts);
  }
  
  Future<void> _registerGoogleAssistantActions() async {
    final googleActions = [
      GoogleAssistantAction(
        identifier: 'quick_photo',
        displayName: 'Quick Photo',
        description: 'Take a quick photo with Koutu',
        queryPatterns: ['take a photo', 'quick photo', 'capture image'],
        action: 'QUICK_PHOTO',
      ),
      GoogleAssistantAction(
        identifier: 'view_outfits',
        displayName: 'View Outfits',
        description: 'View outfit suggestions',
        queryPatterns: ['show outfits', 'view outfits', 'outfit suggestions'],
        action: 'VIEW_OUTFITS',
      ),
      GoogleAssistantAction(
        identifier: 'check_weather',
        displayName: 'Weather Check',
        description: 'Check weather for outfit planning',
        queryPatterns: ['check weather', 'weather outfit', 'what to wear'],
        action: 'CHECK_WEATHER',
      ),
      GoogleAssistantAction(
        identifier: 'open_wardrobe',
        displayName: 'Open Wardrobe',
        description: 'Open wardrobe collection',
        queryPatterns: ['open wardrobe', 'my wardrobe', 'show clothes'],
        action: 'OPEN_WARDROBE',
      ),
    ];
    
    await registerGoogleAssistantActions(googleActions);
  }
  
  Future<VoiceIntentResponse> _processVoiceIntent(VoiceIntent intent) async {
    switch (intent.action) {
      case 'QUICK_PHOTO':
        return VoiceIntentResponse(
          success: true,
          action: 'openScreen',
          parameters: {'screen': 'camera'},
          message: 'Opening camera for quick photo',
          voiceResponse: 'Taking you to the camera',
        );
        
      case 'VIEW_OUTFITS':
        return VoiceIntentResponse(
          success: true,
          action: 'openScreen',
          parameters: {'screen': 'outfits'},
          message: 'Opening outfit suggestions',
          voiceResponse: 'Here are your outfit suggestions',
        );
        
      case 'CHECK_WEATHER':
        return VoiceIntentResponse(
          success: true,
          action: 'openScreen',
          parameters: {'screen': 'weather'},
          message: 'Checking weather for outfit planning',
          voiceResponse: 'It\'s sunny and 22 degrees, perfect for light clothing',
        );
        
      case 'OPEN_WARDROBE':
        return VoiceIntentResponse(
          success: true,
          action: 'openScreen',
          parameters: {'screen': 'wardrobe'},
          message: 'Opening wardrobe collection',
          voiceResponse: 'Opening your wardrobe',
        );
        
      default:
        return VoiceIntentResponse(
          success: false,
          action: 'none',
          parameters: {},
          message: 'Unknown voice command',
          voiceResponse: 'I didn\'t understand that command',
        );
    }
  }
  
  Future<VoiceIntentResponse> _executeShortcut(String shortcutId) async {
    // Execute shortcut and return response
    final intent = VoiceIntent(
      action: shortcutId.toUpperCase(),
      parameters: {},
      confidence: 1.0,
    );
    
    final result = await _processVoiceIntent(intent);
    return result;
  }
  
  Future<VoiceIntentResponse> _executeAction(String actionId) async {
    // Execute action and return response
    final intent = VoiceIntent(
      action: actionId.toUpperCase(),
      parameters: {},
      confidence: 1.0,
    );
    
    final result = await _processVoiceIntent(intent);
    return result;
  }
  
  Future<void> _logIntentUsage(VoiceIntent intent) async {
    final history = _getIntentHistory();
    
    final entry = {
      'intent': intent.toJson(),
      'timestamp': DateTime.now().toIso8601String(),
    };
    
    history.add(entry);
    
    // Keep only last 100 entries
    if (history.length > 100) {
      history.removeAt(0);
    }
    
    await _preferences.setString(_intentHistoryKey, json.encode(history));
  }
  
  Future<List<VoiceContextualSuggestion>> _generateContextualSuggestions(String context) async {
    // Generate contextual suggestions based on context
    final suggestions = <VoiceContextualSuggestion>[];
    
    if (context.toLowerCase().contains('morning')) {
      suggestions.add(VoiceContextualSuggestion(
        phrase: 'Show me morning outfits',
        title: 'Morning Outfits',
        description: 'View outfit suggestions for the morning',
        confidence: 0.9,
      ));
    }
    
    if (context.toLowerCase().contains('weather')) {
      suggestions.add(VoiceContextualSuggestion(
        phrase: 'Check weather for outfit',
        title: 'Weather Check',
        description: 'Check weather for outfit planning',
        confidence: 0.8,
      ));
    }
    
    if (context.toLowerCase().contains('work')) {
      suggestions.add(VoiceContextualSuggestion(
        phrase: 'Show work outfits',
        title: 'Work Outfits',
        description: 'View professional outfit suggestions',
        confidence: 0.85,
      ));
    }
    
    return suggestions;
  }
  
  Map<String, dynamic> _getVoiceAssistantConfig() {
    final configJson = _preferences.getString(_voiceAssistantConfigKey);
    if (configJson == null) {
      return {};
    }
    
    try {
      return json.decode(configJson);
    } catch (e) {
      return {};
    }
  }
  
  Future<void> _storeShortcuts(String type, List<Map<String, dynamic>> shortcuts) async {
    final shortcutsData = _getStoredShortcuts();
    shortcutsData[type] = shortcuts;
    
    await _preferences.setString(_shortcutsKey, json.encode(shortcutsData));
  }
  
  Map<String, dynamic> _getStoredShortcuts() {
    final shortcutsJson = _preferences.getString(_shortcutsKey);
    if (shortcutsJson == null) {
      return {};
    }
    
    try {
      return json.decode(shortcutsJson);
    } catch (e) {
      return {};
    }
  }
  
  List<Map<String, dynamic>> _getIntentHistory() {
    final historyJson = _preferences.getString(_intentHistoryKey);
    if (historyJson == null) {
      return [];
    }
    
    try {
      return List<Map<String, dynamic>>.from(json.decode(historyJson));
    } catch (e) {
      return [];
    }
  }
}

// Data classes

class VoiceAssistantSettings {
  final bool enabled;
  final bool siriEnabled;
  final bool googleAssistantEnabled;
  final bool customShortcutsEnabled;
  final bool contextualSuggestionsEnabled;
  final bool personalizedResponsesEnabled;
  final bool quickActionsEnabled;
  final bool outfitSuggestionsEnabled;
  final bool weatherIntegrationEnabled;
  final bool smartRemindersEnabled;
  final bool voiceResponseEnabled;
  final bool hapticFeedbackEnabled;
  
  const VoiceAssistantSettings({
    required this.enabled,
    required this.siriEnabled,
    required this.googleAssistantEnabled,
    required this.customShortcutsEnabled,
    required this.contextualSuggestionsEnabled,
    required this.personalizedResponsesEnabled,
    required this.quickActionsEnabled,
    required this.outfitSuggestionsEnabled,
    required this.weatherIntegrationEnabled,
    required this.smartRemindersEnabled,
    required this.voiceResponseEnabled,
    required this.hapticFeedbackEnabled,
  });
}

class SiriShortcut {
  final String identifier;
  final String phrase;
  final String title;
  final String subtitle;
  final String systemImageName;
  final String intentClass;
  
  const SiriShortcut({
    required this.identifier,
    required this.phrase,
    required this.title,
    required this.subtitle,
    required this.systemImageName,
    required this.intentClass,
  });
  
  Map<String, dynamic> toJson() => {
    'identifier': identifier,
    'phrase': phrase,
    'title': title,
    'subtitle': subtitle,
    'systemImageName': systemImageName,
    'intentClass': intentClass,
  };
}

class GoogleAssistantAction {
  final String identifier;
  final String displayName;
  final String description;
  final List<String> queryPatterns;
  final String action;
  
  const GoogleAssistantAction({
    required this.identifier,
    required this.displayName,
    required this.description,
    required this.queryPatterns,
    required this.action,
  });
  
  Map<String, dynamic> toJson() => {
    'identifier': identifier,
    'displayName': displayName,
    'description': description,
    'queryPatterns': queryPatterns,
    'action': action,
  };
}

class VoiceIntent {
  final String action;
  final Map<String, dynamic> parameters;
  final double confidence;
  
  const VoiceIntent({
    required this.action,
    required this.parameters,
    required this.confidence,
  });
  
  Map<String, dynamic> toJson() => {
    'action': action,
    'parameters': parameters,
    'confidence': confidence,
  };
  
  factory VoiceIntent.fromJson(Map<String, dynamic> json) {
    return VoiceIntent(
      action: json['action'],
      parameters: json['parameters'],
      confidence: json['confidence'],
    );
  }
}

class VoiceIntentResponse {
  final bool success;
  final String action;
  final Map<String, dynamic> parameters;
  final String message;
  final String voiceResponse;
  
  const VoiceIntentResponse({
    required this.success,
    required this.action,
    required this.parameters,
    required this.message,
    required this.voiceResponse,
  });
  
  Map<String, dynamic> toJson() => {
    'success': success,
    'action': action,
    'parameters': parameters,
    'message': message,
    'voiceResponse': voiceResponse,
  };
}

class CustomVoiceShortcut {
  final String id;
  final String phrase;
  final String title;
  final String description;
  final String action;
  final Map<String, dynamic> parameters;
  
  const CustomVoiceShortcut({
    required this.id,
    required this.phrase,
    required this.title,
    required this.description,
    required this.action,
    required this.parameters,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'phrase': phrase,
    'title': title,
    'description': description,
    'action': action,
    'parameters': parameters,
  };
}

class VoiceAssistantCapabilities {
  final bool siriAvailable;
  final bool googleAssistantAvailable;
  final bool customShortcutsSupported;
  final bool contextualSuggestionsSupported;
  final bool voiceResponseSupported;
  final bool hapticFeedbackSupported;
  final List<String> supportedIntents;
  
  const VoiceAssistantCapabilities({
    required this.siriAvailable,
    required this.googleAssistantAvailable,
    required this.customShortcutsSupported,
    required this.contextualSuggestionsSupported,
    required this.voiceResponseSupported,
    required this.hapticFeedbackSupported,
    required this.supportedIntents,
  });
  
  factory VoiceAssistantCapabilities.fromJson(Map<String, dynamic> json) {
    return VoiceAssistantCapabilities(
      siriAvailable: json['siriAvailable'],
      googleAssistantAvailable: json['googleAssistantAvailable'],
      customShortcutsSupported: json['customShortcutsSupported'],
      contextualSuggestionsSupported: json['contextualSuggestionsSupported'],
      voiceResponseSupported: json['voiceResponseSupported'],
      hapticFeedbackSupported: json['hapticFeedbackSupported'],
      supportedIntents: List<String>.from(json['supportedIntents']),
    );
  }
}

class VoiceShortcut {
  final String id;
  final String phrase;
  final String title;
  final String description;
  final String type;
  final bool enabled;
  
  const VoiceShortcut({
    required this.id,
    required this.phrase,
    required this.title,
    required this.description,
    required this.type,
    required this.enabled,
  });
  
  factory VoiceShortcut.fromJson(Map<String, dynamic> json) {
    return VoiceShortcut(
      id: json['id'],
      phrase: json['phrase'],
      title: json['title'],
      description: json['description'],
      type: json['type'],
      enabled: json['enabled'],
    );
  }
}

class VoiceIntentHistoryEntry {
  final VoiceIntent intent;
  final DateTime timestamp;
  
  const VoiceIntentHistoryEntry({
    required this.intent,
    required this.timestamp,
  });
  
  factory VoiceIntentHistoryEntry.fromJson(Map<String, dynamic> json) {
    return VoiceIntentHistoryEntry(
      intent: VoiceIntent.fromJson(json['intent']),
      timestamp: DateTime.parse(json['timestamp']),
    );
  }
}

class VoiceContextualSuggestion {
  final String phrase;
  final String title;
  final String description;
  final double confidence;
  
  const VoiceContextualSuggestion({
    required this.phrase,
    required this.title,
    required this.description,
    required this.confidence,
  });
}

class VoiceAssistantTestResult {
  final bool siriIntegrationWorking;
  final bool googleAssistantIntegrationWorking;
  final bool shortcutsRegistered;
  final bool actionsRegistered;
  final List<String> errors;
  final List<String> warnings;
  
  const VoiceAssistantTestResult({
    required this.siriIntegrationWorking,
    required this.googleAssistantIntegrationWorking,
    required this.shortcutsRegistered,
    required this.actionsRegistered,
    required this.errors,
    required this.warnings,
  });
  
  factory VoiceAssistantTestResult.fromJson(Map<String, dynamic> json) {
    return VoiceAssistantTestResult(
      siriIntegrationWorking: json['siriIntegrationWorking'],
      googleAssistantIntegrationWorking: json['googleAssistantIntegrationWorking'],
      shortcutsRegistered: json['shortcutsRegistered'],
      actionsRegistered: json['actionsRegistered'],
      errors: List<String>.from(json['errors']),
      warnings: List<String>.from(json['warnings']),
    );
  }
}