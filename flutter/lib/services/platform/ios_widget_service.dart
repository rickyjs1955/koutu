import 'package:flutter/services.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:typed_data';

/// Service for iOS widget integration
class IOSWidgetService {
  final SharedPreferences _preferences;
  final MethodChannel _channel;
  
  // Widget settings keys
  static const String _widgetsEnabledKey = 'ios_widgets_enabled';
  static const String _widgetConfigKey = 'ios_widget_config';
  static const String _widgetDataKey = 'ios_widget_data';
  static const String _lastWidgetUpdateKey = 'last_widget_update';
  
  IOSWidgetService({
    required SharedPreferences preferences,
    MethodChannel? channel,
  }) : _preferences = preferences,
       _channel = channel ?? const MethodChannel('koutu/ios_widgets');
  
  /// Initialize iOS widget service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Check if iOS widgets are available
      final isAvailable = await _channel.invokeMethod<bool>('isWidgetAvailable') ?? false;
      
      if (!isAvailable) {
        return Left(ServiceFailure('iOS widgets are not available'));
      }
      
      // Set up widget data handler
      _channel.setMethodCallHandler(_handleWidgetRequest);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize iOS widgets: $e'));
    }
  }
  
  /// Get iOS widget settings
  IOSWidgetSettings getWidgetSettings() {
    final config = _getWidgetConfig();
    
    return IOSWidgetSettings(
      enabled: _preferences.getBool(_widgetsEnabledKey) ?? false,
      outfitWidgetEnabled: config['outfitWidget'] ?? true,
      weatherWidgetEnabled: config['weatherWidget'] ?? true,
      quickActionsEnabled: config['quickActions'] ?? true,
      updateInterval: Duration(minutes: config['updateInterval'] ?? 15),
      showOutfitSuggestions: config['showOutfitSuggestions'] ?? true,
      showWeatherInfo: config['showWeatherInfo'] ?? true,
      maxOutfitsShown: config['maxOutfitsShown'] ?? 3,
    );
  }
  
  /// Update iOS widget settings
  Future<Either<Failure, void>> updateWidgetSettings(
    IOSWidgetSettings settings,
  ) async {
    try {
      await _preferences.setBool(_widgetsEnabledKey, settings.enabled);
      
      final config = {
        'outfitWidget': settings.outfitWidgetEnabled,
        'weatherWidget': settings.weatherWidgetEnabled,
        'quickActions': settings.quickActionsEnabled,
        'updateInterval': settings.updateInterval.inMinutes,
        'showOutfitSuggestions': settings.showOutfitSuggestions,
        'showWeatherInfo': settings.showWeatherInfo,
        'maxOutfitsShown': settings.maxOutfitsShown,
      };
      
      await _preferences.setString(_widgetConfigKey, json.encode(config));
      
      // Update widgets with new settings
      if (settings.enabled) {
        await _updateAllWidgets();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update widget settings: $e'));
    }
  }
  
  /// Create outfit widget
  Future<Either<Failure, void>> createOutfitWidget(
    OutfitWidgetData data,
  ) async {
    try {
      final settings = getWidgetSettings();
      
      if (!settings.enabled || !settings.outfitWidgetEnabled) {
        return Left(ServiceFailure('Outfit widget is disabled'));
      }
      
      final widgetData = {
        'type': 'outfit',
        'title': data.title,
        'outfits': data.outfits.map((outfit) => outfit.toJson()).toList(),
        'weatherInfo': data.weatherInfo?.toJson(),
        'lastUpdated': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('createWidget', {
        'identifier': 'OutfitWidget',
        'data': widgetData,
      });
      
      await _storeWidgetData('outfit', widgetData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create outfit widget: $e'));
    }
  }
  
  /// Create weather widget
  Future<Either<Failure, void>> createWeatherWidget(
    WeatherWidgetData data,
  ) async {
    try {
      final settings = getWidgetSettings();
      
      if (!settings.enabled || !settings.weatherWidgetEnabled) {
        return Left(ServiceFailure('Weather widget is disabled'));
      }
      
      final widgetData = {
        'type': 'weather',
        'title': data.title,
        'weather': data.weather.toJson(),
        'outfitSuggestions': data.outfitSuggestions.map((outfit) => outfit.toJson()).toList(),
        'lastUpdated': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('createWidget', {
        'identifier': 'WeatherWidget',
        'data': widgetData,
      });
      
      await _storeWidgetData('weather', widgetData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create weather widget: $e'));
    }
  }
  
  /// Update all widgets
  Future<Either<Failure, void>> updateAllWidgets() async {
    try {
      await _updateAllWidgets();
      
      await _preferences.setString(
        _lastWidgetUpdateKey,
        DateTime.now().toIso8601String(),
      );
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update widgets: $e'));
    }
  }
  
  /// Get widget data for external requests
  Future<Either<Failure, Map<String, dynamic>>> getWidgetData(
    String widgetType,
  ) async {
    try {
      final widgetData = _getStoredWidgetData();
      
      if (!widgetData.containsKey(widgetType)) {
        return Left(ServiceFailure('Widget type not found: $widgetType'));
      }
      
      return Right(widgetData[widgetType]);
    } catch (e) {
      return Left(ServiceFailure('Failed to get widget data: $e'));
    }
  }
  
  /// Remove widget
  Future<Either<Failure, void>> removeWidget(String widgetType) async {
    try {
      await _channel.invokeMethod('removeWidget', {
        'identifier': '${widgetType}Widget',
      });
      
      await _removeWidgetData(widgetType);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to remove widget: $e'));
    }
  }
  
  /// Check widget availability
  Future<Either<Failure, bool>> isWidgetAvailable() async {
    try {
      final isAvailable = await _channel.invokeMethod<bool>('isWidgetAvailable') ?? false;
      return Right(isAvailable);
    } catch (e) {
      return Left(ServiceFailure('Failed to check widget availability: $e'));
    }
  }
  
  /// Get widget timeline
  Future<Either<Failure, List<WidgetTimelineEntry>>> getWidgetTimeline(
    String widgetType,
  ) async {
    try {
      final timeline = await _channel.invokeMethod<List<dynamic>>('getWidgetTimeline', {
        'identifier': '${widgetType}Widget',
      });
      
      if (timeline == null) {
        return const Right([]);
      }
      
      final entries = timeline.map((entry) => WidgetTimelineEntry.fromJson(entry)).toList();
      return Right(entries);
    } catch (e) {
      return Left(ServiceFailure('Failed to get widget timeline: $e'));
    }
  }
  
  /// Setup widget intent handling
  Future<Either<Failure, void>> setupWidgetIntents() async {
    try {
      await _channel.invokeMethod('setupIntentHandling', {
        'intents': [
          'OpenOutfitIntent',
          'ViewWardrobeIntent',
          'TakePhotoIntent',
          'SearchGarmentsIntent',
        ],
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to setup widget intents: $e'));
    }
  }
  
  /// Handle widget configuration
  Future<Either<Failure, void>> configureWidget(
    String widgetType,
    Map<String, dynamic> configuration,
  ) async {
    try {
      await _channel.invokeMethod('configureWidget', {
        'identifier': '${widgetType}Widget',
        'configuration': configuration,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to configure widget: $e'));
    }
  }
  
  /// Get widget sizes
  Future<Either<Failure, List<WidgetSize>>> getAvailableWidgetSizes() async {
    try {
      final sizes = await _channel.invokeMethod<List<dynamic>>('getAvailableWidgetSizes');
      
      if (sizes == null) {
        return const Right([]);
      }
      
      final widgetSizes = sizes.map((size) => WidgetSize.fromJson(size)).toList();
      return Right(widgetSizes);
    } catch (e) {
      return Left(ServiceFailure('Failed to get widget sizes: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _handleWidgetRequest(MethodCall call) async {
    switch (call.method) {
      case 'requestWidgetData':
        final widgetType = call.arguments['type'] as String;
        final data = await getWidgetData(widgetType);
        
        data.fold(
          (failure) => _channel.invokeMethod('widgetDataResponse', {
            'error': failure.message,
          }),
          (widgetData) => _channel.invokeMethod('widgetDataResponse', {
            'data': widgetData,
          }),
        );
        break;
        
      case 'widgetTapped':
        final widgetType = call.arguments['type'] as String;
        final action = call.arguments['action'] as String?;
        await _handleWidgetTap(widgetType, action);
        break;
        
      case 'widgetNeedsUpdate':
        final widgetType = call.arguments['type'] as String;
        await _updateSpecificWidget(widgetType);
        break;
    }
  }
  
  Future<void> _handleWidgetTap(String widgetType, String? action) async {
    // Handle widget tap actions
    switch (widgetType) {
      case 'outfit':
        if (action == 'openOutfit') {
          // Open specific outfit
        } else {
          // Open outfit screen
        }
        break;
      case 'weather':
        if (action == 'openWeather') {
          // Open weather details
        } else {
          // Open main app
        }
        break;
    }
  }
  
  Future<void> _updateAllWidgets() async {
    final settings = getWidgetSettings();
    
    if (settings.outfitWidgetEnabled) {
      await _updateOutfitWidget();
    }
    
    if (settings.weatherWidgetEnabled) {
      await _updateWeatherWidget();
    }
  }
  
  Future<void> _updateSpecificWidget(String widgetType) async {
    switch (widgetType) {
      case 'outfit':
        await _updateOutfitWidget();
        break;
      case 'weather':
        await _updateWeatherWidget();
        break;
    }
  }
  
  Future<void> _updateOutfitWidget() async {
    // This would fetch current outfit data and update the widget
    // For now, we'll create a placeholder implementation
    final outfitData = OutfitWidgetData(
      title: 'Today\'s Outfits',
      outfits: [], // Would be populated with actual outfit data
      weatherInfo: null, // Would be populated with weather data
    );
    
    await createOutfitWidget(outfitData);
  }
  
  Future<void> _updateWeatherWidget() async {
    // This would fetch current weather data and update the widget
    // For now, we'll create a placeholder implementation
    final weatherData = WeatherWidgetData(
      title: 'Weather & Outfits',
      weather: WeatherInfo(
        temperature: 22,
        condition: 'Sunny',
        humidity: 65,
        windSpeed: 10,
        location: 'Current Location',
      ),
      outfitSuggestions: [], // Would be populated with outfit suggestions
    );
    
    await createWeatherWidget(weatherData);
  }
  
  Map<String, dynamic> _getWidgetConfig() {
    final configJson = _preferences.getString(_widgetConfigKey);
    if (configJson == null) {
      return {};
    }
    
    try {
      return json.decode(configJson);
    } catch (e) {
      return {};
    }
  }
  
  Future<void> _storeWidgetData(String widgetType, Map<String, dynamic> data) async {
    final widgetData = _getStoredWidgetData();
    widgetData[widgetType] = data;
    
    await _preferences.setString(_widgetDataKey, json.encode(widgetData));
  }
  
  Future<void> _removeWidgetData(String widgetType) async {
    final widgetData = _getStoredWidgetData();
    widgetData.remove(widgetType);
    
    await _preferences.setString(_widgetDataKey, json.encode(widgetData));
  }
  
  Map<String, dynamic> _getStoredWidgetData() {
    final dataJson = _preferences.getString(_widgetDataKey);
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

class IOSWidgetSettings {
  final bool enabled;
  final bool outfitWidgetEnabled;
  final bool weatherWidgetEnabled;
  final bool quickActionsEnabled;
  final Duration updateInterval;
  final bool showOutfitSuggestions;
  final bool showWeatherInfo;
  final int maxOutfitsShown;
  
  const IOSWidgetSettings({
    required this.enabled,
    required this.outfitWidgetEnabled,
    required this.weatherWidgetEnabled,
    required this.quickActionsEnabled,
    required this.updateInterval,
    required this.showOutfitSuggestions,
    required this.showWeatherInfo,
    required this.maxOutfitsShown,
  });
}

class OutfitWidgetData {
  final String title;
  final List<WidgetOutfit> outfits;
  final WeatherInfo? weatherInfo;
  
  const OutfitWidgetData({
    required this.title,
    required this.outfits,
    this.weatherInfo,
  });
}

class WeatherWidgetData {
  final String title;
  final WeatherInfo weather;
  final List<WidgetOutfit> outfitSuggestions;
  
  const WeatherWidgetData({
    required this.title,
    required this.weather,
    required this.outfitSuggestions,
  });
}

class WidgetOutfit {
  final String id;
  final String name;
  final String? imageUrl;
  final List<String> garmentIds;
  final String? description;
  final double? temperature;
  final String? occasion;
  
  const WidgetOutfit({
    required this.id,
    required this.name,
    this.imageUrl,
    required this.garmentIds,
    this.description,
    this.temperature,
    this.occasion,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'imageUrl': imageUrl,
    'garmentIds': garmentIds,
    'description': description,
    'temperature': temperature,
    'occasion': occasion,
  };
  
  factory WidgetOutfit.fromJson(Map<String, dynamic> json) {
    return WidgetOutfit(
      id: json['id'],
      name: json['name'],
      imageUrl: json['imageUrl'],
      garmentIds: List<String>.from(json['garmentIds']),
      description: json['description'],
      temperature: json['temperature'],
      occasion: json['occasion'],
    );
  }
}

class WeatherInfo {
  final int temperature;
  final String condition;
  final int humidity;
  final int windSpeed;
  final String location;
  
  const WeatherInfo({
    required this.temperature,
    required this.condition,
    required this.humidity,
    required this.windSpeed,
    required this.location,
  });
  
  Map<String, dynamic> toJson() => {
    'temperature': temperature,
    'condition': condition,
    'humidity': humidity,
    'windSpeed': windSpeed,
    'location': location,
  };
  
  factory WeatherInfo.fromJson(Map<String, dynamic> json) {
    return WeatherInfo(
      temperature: json['temperature'],
      condition: json['condition'],
      humidity: json['humidity'],
      windSpeed: json['windSpeed'],
      location: json['location'],
    );
  }
}

class WidgetTimelineEntry {
  final DateTime date;
  final String widgetType;
  final Map<String, dynamic> data;
  final String? relevance;
  
  const WidgetTimelineEntry({
    required this.date,
    required this.widgetType,
    required this.data,
    this.relevance,
  });
  
  factory WidgetTimelineEntry.fromJson(Map<String, dynamic> json) {
    return WidgetTimelineEntry(
      date: DateTime.parse(json['date']),
      widgetType: json['widgetType'],
      data: json['data'],
      relevance: json['relevance'],
    );
  }
}

class WidgetSize {
  final String name;
  final double width;
  final double height;
  final String family;
  
  const WidgetSize({
    required this.name,
    required this.width,
    required this.height,
    required this.family,
  });
  
  factory WidgetSize.fromJson(Map<String, dynamic> json) {
    return WidgetSize(
      name: json['name'],
      width: json['width'],
      height: json['height'],
      family: json['family'],
    );
  }
}