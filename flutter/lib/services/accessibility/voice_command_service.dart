import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:speech_to_text/speech_to_text.dart';
import 'package:flutter_tts/flutter_tts.dart';

/// Service for voice command integration
class VoiceCommandService {
  final SharedPreferences _preferences;
  final SpeechToText _speechToText;
  final FlutterTts _flutterTts;
  
  // Voice command settings keys
  static const String _voiceCommandsEnabledKey = 'voice_commands_enabled';
  static const String _voiceLanguageKey = 'voice_language';
  static const String _speechRateKey = 'speech_rate';
  static const String _speechPitchKey = 'speech_pitch';
  static const String _speechVolumeKey = 'speech_volume';
  static const String _wakeWordKey = 'wake_word';
  static const String _confidenceThresholdKey = 'confidence_threshold';
  
  VoiceCommandService({
    required SharedPreferences preferences,
    required SpeechToText speechToText,
    required FlutterTts flutterTts,
  }) : _preferences = preferences,
       _speechToText = speechToText,
       _flutterTts = flutterTts;
  
  /// Initialize voice command service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Initialize speech to text
      final speechAvailable = await _speechToText.initialize(
        onError: (error) => debugPrint('Speech error: $error'),
        onStatus: (status) => debugPrint('Speech status: $status'),
      );
      
      if (!speechAvailable) {
        return Left(ServiceFailure('Speech recognition not available'));
      }
      
      // Initialize text to speech
      await _flutterTts.setLanguage('en-US');
      await _flutterTts.setPitch(getVoiceSettings().speechPitch);
      await _flutterTts.setSpeechRate(getVoiceSettings().speechRate);
      await _flutterTts.setVolume(getVoiceSettings().speechVolume);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize voice commands: $e'));
    }
  }
  
  /// Get voice command settings
  VoiceCommandSettings getVoiceSettings() {
    return VoiceCommandSettings(
      enabled: _preferences.getBool(_voiceCommandsEnabledKey) ?? false,
      language: _preferences.getString(_voiceLanguageKey) ?? 'en-US',
      speechRate: _preferences.getDouble(_speechRateKey) ?? 0.5,
      speechPitch: _preferences.getDouble(_speechPitchKey) ?? 1.0,
      speechVolume: _preferences.getDouble(_speechVolumeKey) ?? 1.0,
      wakeWord: _preferences.getString(_wakeWordKey) ?? 'hey wardrobe',
      confidenceThreshold: _preferences.getDouble(_confidenceThresholdKey) ?? 0.7,
    );
  }
  
  /// Update voice command settings
  Future<Either<Failure, void>> updateVoiceSettings(
    VoiceCommandSettings settings,
  ) async {
    try {
      await _preferences.setBool(_voiceCommandsEnabledKey, settings.enabled);
      await _preferences.setString(_voiceLanguageKey, settings.language);
      await _preferences.setDouble(_speechRateKey, settings.speechRate);
      await _preferences.setDouble(_speechPitchKey, settings.speechPitch);
      await _preferences.setDouble(_speechVolumeKey, settings.speechVolume);
      await _preferences.setString(_wakeWordKey, settings.wakeWord);
      await _preferences.setDouble(_confidenceThresholdKey, settings.confidenceThreshold);
      
      // Update TTS settings
      await _flutterTts.setLanguage(settings.language);
      await _flutterTts.setPitch(settings.speechPitch);
      await _flutterTts.setSpeechRate(settings.speechRate);
      await _flutterTts.setVolume(settings.speechVolume);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update voice settings: $e'));
    }
  }
  
  /// Start listening for voice commands
  Future<Either<Failure, void>> startListening({
    required Function(String) onResult,
    required Function(String) onError,
  }) async {
    try {
      final settings = getVoiceSettings();
      
      if (!settings.enabled) {
        return Left(ServiceFailure('Voice commands are disabled'));
      }
      
      await _speechToText.listen(
        onResult: (result) {
          if (result.confidence >= settings.confidenceThreshold) {
            onResult(result.recognizedWords);
          }
        },
        localeId: settings.language,
        cancelOnError: true,
        listenMode: ListenMode.confirmation,
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to start listening: $e'));
    }
  }
  
  /// Stop listening for voice commands
  Future<Either<Failure, void>> stopListening() async {
    try {
      await _speechToText.stop();
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to stop listening: $e'));
    }
  }
  
  /// Speak text using TTS
  Future<Either<Failure, void>> speak(String text) async {
    try {
      await _flutterTts.speak(text);
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to speak text: $e'));
    }
  }
  
  /// Process voice command
  Future<Either<Failure, VoiceCommandResult>> processVoiceCommand(
    String command,
  ) async {
    try {
      final normalizedCommand = command.toLowerCase().trim();
      
      // Check for wake word
      final settings = getVoiceSettings();
      if (!normalizedCommand.contains(settings.wakeWord.toLowerCase())) {
        return Left(ServiceFailure('Wake word not detected'));
      }
      
      // Remove wake word from command
      final cleanCommand = normalizedCommand.replaceAll(settings.wakeWord.toLowerCase(), '').trim();
      
      // Match command to action
      final action = _matchCommandToAction(cleanCommand);
      
      if (action == null) {
        return Left(ServiceFailure('Command not recognized'));
      }
      
      return Right(VoiceCommandResult(
        originalCommand: command,
        processedCommand: cleanCommand,
        action: action,
        confidence: 1.0, // Would be calculated based on matching accuracy
      ));
    } catch (e) {
      return Left(ServiceFailure('Failed to process voice command: $e'));
    }
  }
  
  /// Get available voice commands
  List<VoiceCommand> getAvailableCommands() {
    return [
      // Navigation commands
      VoiceCommand(
        phrases: ['go to wardrobe', 'open wardrobe', 'show wardrobe'],
        action: VoiceCommandAction.navigateToWardrobe,
        description: 'Navigate to wardrobe screen',
      ),
      VoiceCommand(
        phrases: ['go to garments', 'open garments', 'show garments'],
        action: VoiceCommandAction.navigateToGarments,
        description: 'Navigate to garments screen',
      ),
      VoiceCommand(
        phrases: ['go to outfits', 'open outfits', 'show outfits'],
        action: VoiceCommandAction.navigateToOutfits,
        description: 'Navigate to outfits screen',
      ),
      VoiceCommand(
        phrases: ['go to settings', 'open settings', 'show settings'],
        action: VoiceCommandAction.navigateToSettings,
        description: 'Navigate to settings screen',
      ),
      VoiceCommand(
        phrases: ['go back', 'navigate back', 'return'],
        action: VoiceCommandAction.navigateBack,
        description: 'Navigate back to previous screen',
      ),
      
      // Camera commands
      VoiceCommand(
        phrases: ['take photo', 'capture image', 'take picture'],
        action: VoiceCommandAction.takePhoto,
        description: 'Take a photo with camera',
      ),
      VoiceCommand(
        phrases: ['open camera', 'launch camera', 'start camera'],
        action: VoiceCommandAction.openCamera,
        description: 'Open camera screen',
      ),
      
      // Search commands
      VoiceCommand(
        phrases: ['search for', 'find', 'look for'],
        action: VoiceCommandAction.search,
        description: 'Search for items',
      ),
      VoiceCommand(
        phrases: ['filter by', 'show only', 'display'],
        action: VoiceCommandAction.filter,
        description: 'Filter items by criteria',
      ),
      
      // Accessibility commands
      VoiceCommand(
        phrases: ['read screen', 'describe screen', 'what is on screen'],
        action: VoiceCommandAction.readScreen,
        description: 'Read screen content aloud',
      ),
      VoiceCommand(
        phrases: ['increase text size', 'make text bigger', 'larger text'],
        action: VoiceCommandAction.increaseTextSize,
        description: 'Increase text size',
      ),
      VoiceCommand(
        phrases: ['decrease text size', 'make text smaller', 'smaller text'],
        action: VoiceCommandAction.decreaseTextSize,
        description: 'Decrease text size',
      ),
      VoiceCommand(
        phrases: ['toggle high contrast', 'high contrast mode', 'contrast mode'],
        action: VoiceCommandAction.toggleHighContrast,
        description: 'Toggle high contrast mode',
      ),
      
      // Help commands
      VoiceCommand(
        phrases: ['help', 'what can I say', 'voice commands'],
        action: VoiceCommandAction.showHelp,
        description: 'Show available voice commands',
      ),
      VoiceCommand(
        phrases: ['repeat', 'say again', 'what did you say'],
        action: VoiceCommandAction.repeat,
        description: 'Repeat last announcement',
      ),
    ];
  }
  
  /// Get available languages
  Future<Either<Failure, List<String>>> getAvailableLanguages() async {
    try {
      final languages = await _speechToText.locales();
      return Right(languages.map((locale) => locale.localeId).toList());
    } catch (e) {
      return Left(ServiceFailure('Failed to get available languages: $e'));
    }
  }
  
  /// Check if speech recognition is available
  Future<Either<Failure, bool>> isSpeechRecognitionAvailable() async {
    try {
      final available = await _speechToText.initialize();
      return Right(available);
    } catch (e) {
      return Left(ServiceFailure('Failed to check speech recognition: $e'));
    }
  }
  
  /// Test voice command setup
  Future<Either<Failure, VoiceCommandTestResult>> testVoiceCommandSetup() async {
    try {
      final speechAvailable = await _speechToText.initialize();
      final ttsAvailable = await _testTts();
      
      return Right(VoiceCommandTestResult(
        speechToTextAvailable: speechAvailable,
        textToSpeechAvailable: ttsAvailable,
        microphone: await _speechToText.hasPermission,
        overallStatus: speechAvailable && ttsAvailable,
      ));
    } catch (e) {
      return Left(ServiceFailure('Failed to test voice command setup: $e'));
    }
  }
  
  // Private methods
  
  VoiceCommandAction? _matchCommandToAction(String command) {
    final commands = getAvailableCommands();
    
    for (final voiceCommand in commands) {
      for (final phrase in voiceCommand.phrases) {
        if (command.contains(phrase)) {
          return voiceCommand.action;
        }
      }
    }
    
    return null;
  }
  
  Future<bool> _testTts() async {
    try {
      await _flutterTts.speak('');
      return true;
    } catch (e) {
      return false;
    }
  }
}

// Data classes

class VoiceCommandSettings {
  final bool enabled;
  final String language;
  final double speechRate;
  final double speechPitch;
  final double speechVolume;
  final String wakeWord;
  final double confidenceThreshold;
  
  const VoiceCommandSettings({
    required this.enabled,
    required this.language,
    required this.speechRate,
    required this.speechPitch,
    required this.speechVolume,
    required this.wakeWord,
    required this.confidenceThreshold,
  });
}

class VoiceCommand {
  final List<String> phrases;
  final VoiceCommandAction action;
  final String description;
  
  const VoiceCommand({
    required this.phrases,
    required this.action,
    required this.description,
  });
}

class VoiceCommandResult {
  final String originalCommand;
  final String processedCommand;
  final VoiceCommandAction action;
  final double confidence;
  
  const VoiceCommandResult({
    required this.originalCommand,
    required this.processedCommand,
    required this.action,
    required this.confidence,
  });
}

class VoiceCommandTestResult {
  final bool speechToTextAvailable;
  final bool textToSpeechAvailable;
  final bool microphone;
  final bool overallStatus;
  
  const VoiceCommandTestResult({
    required this.speechToTextAvailable,
    required this.textToSpeechAvailable,
    required this.microphone,
    required this.overallStatus,
  });
}

// Enums

enum VoiceCommandAction {
  navigateToWardrobe,
  navigateToGarments,
  navigateToOutfits,
  navigateToSettings,
  navigateBack,
  takePhoto,
  openCamera,
  search,
  filter,
  readScreen,
  increaseTextSize,
  decreaseTextSize,
  toggleHighContrast,
  showHelp,
  repeat,
}