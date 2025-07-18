import 'package:flutter/services.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:typed_data';

/// Service for wearable device integration (Apple Watch & Wear OS)
class WearableService {
  final SharedPreferences _preferences;
  final MethodChannel _channel;
  
  // Wearable settings keys
  static const String _wearableEnabledKey = 'wearable_enabled';
  static const String _appleWatchEnabledKey = 'apple_watch_enabled';
  static const String _wearOSEnabledKey = 'wear_os_enabled';
  static const String _wearableConfigKey = 'wearable_config';
  static const String _wearableDataKey = 'wearable_data';
  static const String _lastSyncKey = 'last_wearable_sync';
  
  WearableService({
    required SharedPreferences preferences,
    MethodChannel? channel,
  }) : _preferences = preferences,
       _channel = channel ?? const MethodChannel('koutu/wearable');
  
  /// Initialize wearable service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Check wearable availability
      final availability = await _channel.invokeMethod<Map<dynamic, dynamic>>('checkWearableAvailability');
      
      if (availability == null) {
        return Left(ServiceFailure('Failed to check wearable availability'));
      }
      
      final appleWatchAvailable = availability['appleWatch'] ?? false;
      final wearOSAvailable = availability['wearOS'] ?? false;
      
      if (!appleWatchAvailable && !wearOSAvailable) {
        return Left(ServiceFailure('No wearable devices available'));
      }
      
      // Set up wearable communication handler
      _channel.setMethodCallHandler(_handleWearableMessage);
      
      // Initialize wearable apps
      await _initializeWearableApps();
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize wearable service: $e'));
    }
  }
  
  /// Get wearable settings
  WearableSettings getWearableSettings() {
    final config = _getWearableConfig();
    
    return WearableSettings(
      enabled: _preferences.getBool(_wearableEnabledKey) ?? false,
      appleWatchEnabled: _preferences.getBool(_appleWatchEnabledKey) ?? false,
      wearOSEnabled: _preferences.getBool(_wearOSEnabledKey) ?? false,
      syncInterval: Duration(minutes: config['syncInterval'] ?? 5),
      quickActionsEnabled: config['quickActions'] ?? true,
      outfitNotificationsEnabled: config['outfitNotifications'] ?? true,
      weatherIntegrationEnabled: config['weatherIntegration'] ?? true,
      hapticFeedbackEnabled: config['hapticFeedback'] ?? true,
      voiceControlEnabled: config['voiceControl'] ?? true,
      complicationEnabled: config['complication'] ?? true,
      heartRateIntegrationEnabled: config['heartRateIntegration'] ?? false,
      activityTrackingEnabled: config['activityTracking'] ?? false,
    );
  }
  
  /// Update wearable settings
  Future<Either<Failure, void>> updateWearableSettings(
    WearableSettings settings,
  ) async {
    try {
      await _preferences.setBool(_wearableEnabledKey, settings.enabled);
      await _preferences.setBool(_appleWatchEnabledKey, settings.appleWatchEnabled);
      await _preferences.setBool(_wearOSEnabledKey, settings.wearOSEnabled);
      
      final config = {
        'syncInterval': settings.syncInterval.inMinutes,
        'quickActions': settings.quickActionsEnabled,
        'outfitNotifications': settings.outfitNotificationsEnabled,
        'weatherIntegration': settings.weatherIntegrationEnabled,
        'hapticFeedback': settings.hapticFeedbackEnabled,
        'voiceControl': settings.voiceControlEnabled,
        'complication': settings.complicationEnabled,
        'heartRateIntegration': settings.heartRateIntegrationEnabled,
        'activityTracking': settings.activityTrackingEnabled,
      };
      
      await _preferences.setString(_wearableConfigKey, json.encode(config));
      
      // Update wearable apps
      if (settings.enabled) {
        await _syncWearableData();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update wearable settings: $e'));
    }
  }
  
  /// Send outfit data to wearable
  Future<Either<Failure, void>> sendOutfitToWearable(
    WearableOutfit outfit,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.enabled) {
        return Left(ServiceFailure('Wearable integration is disabled'));
      }
      
      final outfitData = {
        'type': 'outfit',
        'data': outfit.toJson(),
        'timestamp': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('sendToWearable', outfitData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to send outfit to wearable: $e'));
    }
  }
  
  /// Send weather data to wearable
  Future<Either<Failure, void>> sendWeatherToWearable(
    WearableWeather weather,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.enabled || !settings.weatherIntegrationEnabled) {
        return Left(ServiceFailure('Weather integration is disabled'));
      }
      
      final weatherData = {
        'type': 'weather',
        'data': weather.toJson(),
        'timestamp': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('sendToWearable', weatherData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to send weather to wearable: $e'));
    }
  }
  
  /// Send quick actions to wearable
  Future<Either<Failure, void>> sendQuickActionsToWearable(
    List<WearableQuickAction> actions,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.enabled || !settings.quickActionsEnabled) {
        return Left(ServiceFailure('Quick actions are disabled'));
      }
      
      final actionData = {
        'type': 'quickActions',
        'data': actions.map((action) => action.toJson()).toList(),
        'timestamp': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('sendToWearable', actionData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to send quick actions to wearable: $e'));
    }
  }
  
  /// Get wearable device info
  Future<Either<Failure, List<WearableDevice>>> getConnectedDevices() async {
    try {
      final devices = await _channel.invokeMethod<List<dynamic>>('getConnectedDevices');
      
      if (devices == null) {
        return const Right([]);
      }
      
      final wearableDevices = devices.map((device) => WearableDevice.fromJson(device)).toList();
      return Right(wearableDevices);
    } catch (e) {
      return Left(ServiceFailure('Failed to get connected devices: $e'));
    }
  }
  
  /// Install wearable app
  Future<Either<Failure, void>> installWearableApp(
    String deviceId,
    WearableAppInfo appInfo,
  ) async {
    try {
      await _channel.invokeMethod('installWearableApp', {
        'deviceId': deviceId,
        'appInfo': appInfo.toJson(),
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to install wearable app: $e'));
    }
  }
  
  /// Update wearable app
  Future<Either<Failure, void>> updateWearableApp(
    String deviceId,
    WearableAppInfo appInfo,
  ) async {
    try {
      await _channel.invokeMethod('updateWearableApp', {
        'deviceId': deviceId,
        'appInfo': appInfo.toJson(),
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update wearable app: $e'));
    }
  }
  
  /// Setup watch complications (Apple Watch)
  Future<Either<Failure, void>> setupWatchComplications(
    List<WatchComplication> complications,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.appleWatchEnabled || !settings.complicationEnabled) {
        return Left(ServiceFailure('Apple Watch complications are disabled'));
      }
      
      final complicationData = complications.map((comp) => comp.toJson()).toList();
      
      await _channel.invokeMethod('setupWatchComplications', {
        'complications': complicationData,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to setup watch complications: $e'));
    }
  }
  
  /// Setup Wear OS tiles
  Future<Either<Failure, void>> setupWearOSTiles(
    List<WearOSTile> tiles,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.wearOSEnabled) {
        return Left(ServiceFailure('Wear OS integration is disabled'));
      }
      
      final tileData = tiles.map((tile) => tile.toJson()).toList();
      
      await _channel.invokeMethod('setupWearOSTiles', {
        'tiles': tileData,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to setup Wear OS tiles: $e'));
    }
  }
  
  /// Sync wearable data
  Future<Either<Failure, void>> syncWearableData() async {
    try {
      await _syncWearableData();
      
      await _preferences.setString(
        _lastSyncKey,
        DateTime.now().toIso8601String(),
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to sync wearable data: $e'));
    }
  }
  
  /// Handle wearable voice commands
  Future<Either<Failure, void>> handleWearableVoiceCommand(
    String command,
    String deviceId,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.enabled || !settings.voiceControlEnabled) {
        return Left(ServiceFailure('Voice control is disabled'));
      }
      
      final response = await _processVoiceCommand(command);
      
      await _channel.invokeMethod('sendVoiceResponse', {
        'deviceId': deviceId,
        'response': response,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to handle voice command: $e'));
    }
  }
  
  /// Get wearable battery status
  Future<Either<Failure, Map<String, int>>> getWearableBatteryStatus() async {
    try {
      final batteryStatus = await _channel.invokeMethod<Map<dynamic, dynamic>>('getBatteryStatus');
      
      if (batteryStatus == null) {
        return const Right({});
      }
      
      final status = Map<String, int>.from(batteryStatus);
      return Right(status);
    } catch (e) {
      return Left(ServiceFailure('Failed to get battery status: $e'));
    }
  }
  
  /// Send haptic feedback to wearable
  Future<Either<Failure, void>> sendHapticFeedback(
    String deviceId,
    WearableHapticType type,
  ) async {
    try {
      final settings = getWearableSettings();
      
      if (!settings.enabled || !settings.hapticFeedbackEnabled) {
        return Left(ServiceFailure('Haptic feedback is disabled'));
      }
      
      await _channel.invokeMethod('sendHapticFeedback', {
        'deviceId': deviceId,
        'type': type.name,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to send haptic feedback: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _handleWearableMessage(MethodCall call) async {
    switch (call.method) {
      case 'wearableConnected':
        final deviceId = call.arguments['deviceId'] as String;
        await _handleWearableConnected(deviceId);
        break;
        
      case 'wearableDisconnected':
        final deviceId = call.arguments['deviceId'] as String;
        await _handleWearableDisconnected(deviceId);
        break;
        
      case 'wearableActionTriggered':
        final deviceId = call.arguments['deviceId'] as String;
        final action = call.arguments['action'] as String;
        await _handleWearableAction(deviceId, action);
        break;
        
      case 'wearableVoiceCommand':
        final deviceId = call.arguments['deviceId'] as String;
        final command = call.arguments['command'] as String;
        await handleWearableVoiceCommand(command, deviceId);
        break;
        
      case 'wearableHeartRateUpdate':
        final deviceId = call.arguments['deviceId'] as String;
        final heartRate = call.arguments['heartRate'] as int;
        await _handleHeartRateUpdate(deviceId, heartRate);
        break;
        
      case 'wearableActivityUpdate':
        final deviceId = call.arguments['deviceId'] as String;
        final activity = call.arguments['activity'] as Map<String, dynamic>;
        await _handleActivityUpdate(deviceId, activity);
        break;
    }
  }
  
  Future<void> _handleWearableConnected(String deviceId) async {
    // Handle wearable connection
    await _syncWearableData();
  }
  
  Future<void> _handleWearableDisconnected(String deviceId) async {
    // Handle wearable disconnection
  }
  
  Future<void> _handleWearableAction(String deviceId, String action) async {
    // Handle wearable action
    switch (action) {
      case 'quick_photo':
        await _channel.invokeMethod('openScreen', {'screen': 'camera'});
        break;
      case 'view_outfit':
        await _channel.invokeMethod('openScreen', {'screen': 'outfits'});
        break;
      case 'check_weather':
        await _channel.invokeMethod('openScreen', {'screen': 'weather'});
        break;
      case 'open_wardrobe':
        await _channel.invokeMethod('openScreen', {'screen': 'wardrobe'});
        break;
    }
  }
  
  Future<void> _handleHeartRateUpdate(String deviceId, int heartRate) async {
    final settings = getWearableSettings();
    
    if (!settings.heartRateIntegrationEnabled) {
      return;
    }
    
    // Store heart rate data
    await _storeHealthData('heartRate', {
      'deviceId': deviceId,
      'heartRate': heartRate,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }
  
  Future<void> _handleActivityUpdate(String deviceId, Map<String, dynamic> activity) async {
    final settings = getWearableSettings();
    
    if (!settings.activityTrackingEnabled) {
      return;
    }
    
    // Store activity data
    await _storeHealthData('activity', {
      'deviceId': deviceId,
      'activity': activity,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }
  
  Future<void> _initializeWearableApps() async {
    final settings = getWearableSettings();
    
    if (!settings.enabled) {
      return;
    }
    
    // Initialize Apple Watch app
    if (settings.appleWatchEnabled) {
      await _initializeAppleWatchApp();
    }
    
    // Initialize Wear OS app
    if (settings.wearOSEnabled) {
      await _initializeWearOSApp();
    }
  }
  
  Future<void> _initializeAppleWatchApp() async {
    final appInfo = WearableAppInfo(
      name: 'Koutu Watch',
      bundleId: 'com.koutu.watch',
      version: '1.0.0',
      capabilities: [
        'quickActions',
        'outfitViewer',
        'weatherIntegration',
        'voiceControl',
        'complications',
      ],
    );
    
    // Setup watch complications
    final complications = [
      WatchComplication(
        identifier: 'outfit',
        displayName: 'Today\'s Outfit',
        supportedFamilies: ['modularSmall', 'modularLarge', 'circularSmall'],
        complicationData: {},
      ),
      WatchComplication(
        identifier: 'weather',
        displayName: 'Weather',
        supportedFamilies: ['modularSmall', 'circularSmall'],
        complicationData: {},
      ),
    ];
    
    await setupWatchComplications(complications);
  }
  
  Future<void> _initializeWearOSApp() async {
    final appInfo = WearableAppInfo(
      name: 'Koutu Wear',
      bundleId: 'com.koutu.wear',
      version: '1.0.0',
      capabilities: [
        'quickActions',
        'outfitViewer',
        'weatherIntegration',
        'voiceControl',
        'tiles',
      ],
    );
    
    // Setup Wear OS tiles
    final tiles = [
      WearOSTile(
        id: 'outfit',
        displayName: 'Today\'s Outfit',
        refreshIntervalMillis: 300000, // 5 minutes
        tileData: {},
      ),
      WearOSTile(
        id: 'weather',
        displayName: 'Weather',
        refreshIntervalMillis: 600000, // 10 minutes
        tileData: {},
      ),
    ];
    
    await setupWearOSTiles(tiles);
  }
  
  Future<void> _syncWearableData() async {
    // Sync outfit data
    await _syncOutfitData();
    
    // Sync weather data
    await _syncWeatherData();
    
    // Sync quick actions
    await _syncQuickActions();
  }
  
  Future<void> _syncOutfitData() async {
    // This would fetch current outfit data
    // For now, we'll use placeholder data
    final outfit = WearableOutfit(
      id: 'today',
      name: 'Today\'s Outfit',
      garments: [],
      weather: null,
      imageUrl: null,
    );
    
    await sendOutfitToWearable(outfit);
  }
  
  Future<void> _syncWeatherData() async {
    // This would fetch current weather data
    // For now, we'll use placeholder data
    final weather = WearableWeather(
      temperature: 22,
      condition: 'Sunny',
      humidity: 65,
      windSpeed: 10,
      location: 'Current Location',
      icon: 'sunny',
    );
    
    await sendWeatherToWearable(weather);
  }
  
  Future<void> _syncQuickActions() async {
    final quickActions = [
      WearableQuickAction(
        id: 'quick_photo',
        title: 'Quick Photo',
        icon: 'camera',
        action: 'QUICK_PHOTO',
      ),
      WearableQuickAction(
        id: 'view_outfit',
        title: 'View Outfit',
        icon: 'outfit',
        action: 'VIEW_OUTFIT',
      ),
      WearableQuickAction(
        id: 'check_weather',
        title: 'Check Weather',
        icon: 'weather',
        action: 'CHECK_WEATHER',
      ),
      WearableQuickAction(
        id: 'open_wardrobe',
        title: 'Open Wardrobe',
        icon: 'wardrobe',
        action: 'OPEN_WARDROBE',
      ),
    ];
    
    await sendQuickActionsToWearable(quickActions);
  }
  
  Future<String> _processVoiceCommand(String command) async {
    // Process voice command and return response
    final lowerCommand = command.toLowerCase();
    
    if (lowerCommand.contains('outfit')) {
      return 'Here\'s your outfit for today';
    } else if (lowerCommand.contains('weather')) {
      return 'It\'s sunny and 22 degrees';
    } else if (lowerCommand.contains('photo')) {
      return 'Opening camera';
    } else if (lowerCommand.contains('wardrobe')) {
      return 'Opening wardrobe';
    } else {
      return 'I didn\'t understand that command';
    }
  }
  
  Future<void> _storeHealthData(String type, Map<String, dynamic> data) async {
    final healthData = _getStoredHealthData();
    
    if (!healthData.containsKey(type)) {
      healthData[type] = [];
    }
    
    healthData[type].add(data);
    
    // Keep only last 100 entries
    if (healthData[type].length > 100) {
      healthData[type] = healthData[type].sublist(healthData[type].length - 100);
    }
    
    await _preferences.setString('health_data', json.encode(healthData));
  }
  
  Map<String, dynamic> _getWearableConfig() {
    final configJson = _preferences.getString(_wearableConfigKey);
    if (configJson == null) {
      return {};
    }
    
    try {
      return json.decode(configJson);
    } catch (e) {
      return {};
    }
  }
  
  Map<String, dynamic> _getStoredHealthData() {
    final dataJson = _preferences.getString('health_data');
    if (dataJson == null) {
      return {};
    }
    
    try {
      return json.decode(dataJson);
    } catch (e) {
      return {};
    }
  }
}

// Data classes

class WearableSettings {
  final bool enabled;
  final bool appleWatchEnabled;
  final bool wearOSEnabled;
  final Duration syncInterval;
  final bool quickActionsEnabled;
  final bool outfitNotificationsEnabled;
  final bool weatherIntegrationEnabled;
  final bool hapticFeedbackEnabled;
  final bool voiceControlEnabled;
  final bool complicationEnabled;
  final bool heartRateIntegrationEnabled;
  final bool activityTrackingEnabled;
  
  const WearableSettings({
    required this.enabled,
    required this.appleWatchEnabled,
    required this.wearOSEnabled,
    required this.syncInterval,
    required this.quickActionsEnabled,
    required this.outfitNotificationsEnabled,
    required this.weatherIntegrationEnabled,
    required this.hapticFeedbackEnabled,
    required this.voiceControlEnabled,
    required this.complicationEnabled,
    required this.heartRateIntegrationEnabled,
    required this.activityTrackingEnabled,
  });
}

class WearableOutfit {
  final String id;
  final String name;
  final List<String> garments;
  final String? weather;
  final String? imageUrl;
  
  const WearableOutfit({
    required this.id,
    required this.name,
    required this.garments,
    this.weather,
    this.imageUrl,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'garments': garments,
    'weather': weather,
    'imageUrl': imageUrl,
  };
}

class WearableWeather {
  final int temperature;
  final String condition;
  final int humidity;
  final int windSpeed;
  final String location;
  final String icon;
  
  const WearableWeather({
    required this.temperature,
    required this.condition,
    required this.humidity,
    required this.windSpeed,
    required this.location,
    required this.icon,
  });
  
  Map<String, dynamic> toJson() => {
    'temperature': temperature,
    'condition': condition,
    'humidity': humidity,
    'windSpeed': windSpeed,
    'location': location,
    'icon': icon,
  };
}

class WearableQuickAction {
  final String id;
  final String title;
  final String icon;
  final String action;
  
  const WearableQuickAction({
    required this.id,
    required this.title,
    required this.icon,
    required this.action,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'icon': icon,
    'action': action,
  };
}

class WearableDevice {
  final String id;
  final String name;
  final String type;
  final String model;
  final String osVersion;
  final bool isConnected;
  final int? batteryLevel;
  
  const WearableDevice({
    required this.id,
    required this.name,
    required this.type,
    required this.model,
    required this.osVersion,
    required this.isConnected,
    this.batteryLevel,
  });
  
  factory WearableDevice.fromJson(Map<String, dynamic> json) {
    return WearableDevice(
      id: json['id'],
      name: json['name'],
      type: json['type'],
      model: json['model'],
      osVersion: json['osVersion'],
      isConnected: json['isConnected'],
      batteryLevel: json['batteryLevel'],
    );
  }
}

class WearableAppInfo {
  final String name;
  final String bundleId;
  final String version;
  final List<String> capabilities;
  
  const WearableAppInfo({
    required this.name,
    required this.bundleId,
    required this.version,
    required this.capabilities,
  });
  
  Map<String, dynamic> toJson() => {
    'name': name,
    'bundleId': bundleId,
    'version': version,
    'capabilities': capabilities,
  };
}

class WatchComplication {
  final String identifier;
  final String displayName;
  final List<String> supportedFamilies;
  final Map<String, dynamic> complicationData;
  
  const WatchComplication({
    required this.identifier,
    required this.displayName,
    required this.supportedFamilies,
    required this.complicationData,
  });
  
  Map<String, dynamic> toJson() => {
    'identifier': identifier,
    'displayName': displayName,
    'supportedFamilies': supportedFamilies,
    'complicationData': complicationData,
  };
}

class WearOSTile {
  final String id;
  final String displayName;
  final int refreshIntervalMillis;
  final Map<String, dynamic> tileData;
  
  const WearOSTile({
    required this.id,
    required this.displayName,
    required this.refreshIntervalMillis,
    required this.tileData,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'displayName': displayName,
    'refreshIntervalMillis': refreshIntervalMillis,
    'tileData': tileData,
  };
}

// Enums

enum WearableHapticType {
  light,
  medium,
  heavy,
  success,
  warning,
  error,
}