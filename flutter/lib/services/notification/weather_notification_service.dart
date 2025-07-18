import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/weather/weather_service.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for weather-based outfit notifications
class WeatherNotificationService {
  final WeatherService _weatherService;
  final PushNotificationService _notificationService;
  final RecommendationEngine _recommendationEngine;
  final AuthService _authService;
  
  // Settings
  WeatherNotificationSettings _settings = const WeatherNotificationSettings();
  
  // Timers
  Timer? _morningCheckTimer;
  Timer? _eveningCheckTimer;
  Timer? _extremeWeatherTimer;
  
  // Last notification times
  DateTime? _lastMorningNotification;
  DateTime? _lastEveningNotification;
  DateTime? _lastExtremeWeatherNotification;
  
  WeatherNotificationService({
    required WeatherService weatherService,
    required PushNotificationService notificationService,
    required RecommendationEngine recommendationEngine,
    required AuthService authService,
  })  : _weatherService = weatherService,
        _notificationService = notificationService,
        _recommendationEngine = recommendationEngine,
        _authService = authService;
  
  /// Initialize weather notification service
  Future<void> initialize() async {
    await _loadSettings();
    
    if (_settings.enabled) {
      _scheduleNotifications();
      _startExtremeWeatherMonitoring();
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(
    WeatherNotificationSettings settings,
  ) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Reschedule notifications
      _cancelAllTimers();
      if (settings.enabled) {
        _scheduleNotifications();
        _startExtremeWeatherMonitoring();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  WeatherNotificationSettings getSettings() => _settings;
  
  /// Send morning weather notification
  Future<void> sendMorningNotification() async {
    if (!_settings.morningNotification) return;
    
    // Check if already sent today
    if (_lastMorningNotification != null &&
        _isSameDay(_lastMorningNotification!, DateTime.now())) {
      return;
    }
    
    // Get weather data
    final weatherResult = await _weatherService.getCurrentWeather();
    if (weatherResult.isLeft()) return;
    
    final weather = weatherResult.getOrElse(() => throw Exception());
    final recommendation = _weatherService.getOutfitRecommendation(weather);
    
    // Get outfit suggestions
    final outfitResult = await _recommendationEngine.getOutfitRecommendations(
      context: RecommendationContext(
        considerWeather: true,
        season: _getCurrentSeason(),
      ),
      limit: 3,
    );
    
    final outfits = outfitResult.fold(
      (failure) => <OutfitRecommendation>[],
      (recommendations) => recommendations,
    );
    
    // Create notification
    final title = 'Good morning! ${weather.temperature.round()}°C ${weather.conditions}';
    final body = recommendation.advice;
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'weather_morning',
        'weather': weather.toJson(),
        'recommendation': {
          'layers': recommendation.recommendedLayers,
          'accessories': recommendation.accessories,
        },
        'outfitIds': outfits.map((o) => o.id).toList(),
      },
    );
    
    _lastMorningNotification = DateTime.now();
  }
  
  /// Send evening weather notification (for next day)
  Future<void> sendEveningNotification() async {
    if (!_settings.eveningNotification) return;
    
    // Check if already sent today
    if (_lastEveningNotification != null &&
        _isSameDay(_lastEveningNotification!, DateTime.now())) {
      return;
    }
    
    // Get tomorrow's forecast
    final forecastResult = await _weatherService.getWeatherForecast(days: 2);
    if (forecastResult.isLeft()) return;
    
    final forecasts = forecastResult.getOrElse(() => []);
    if (forecasts.length < 2) return;
    
    final tomorrowForecast = forecasts[1];
    
    // Create weather data from forecast
    final tomorrowWeather = WeatherData(
      temperature: tomorrowForecast.temperature,
      feelsLike: tomorrowForecast.temperature,
      minTemperature: tomorrowForecast.minTemperature,
      maxTemperature: tomorrowForecast.maxTemperature,
      conditions: tomorrowForecast.conditions,
      description: tomorrowForecast.conditions,
      icon: tomorrowForecast.icon,
      humidity: tomorrowForecast.humidity,
      windSpeed: tomorrowForecast.windSpeed,
      cityName: '',
      sunrise: DateTime.now(),
      sunset: DateTime.now(),
    );
    
    final recommendation = _weatherService.getOutfitRecommendation(tomorrowWeather);
    
    // Create notification
    final title = 'Tomorrow\'s forecast: ${tomorrowForecast.temperature.round()}°C';
    final body = 'Plan ahead! ${recommendation.advice}';
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'weather_evening',
        'weather': tomorrowWeather.toJson(),
        'recommendation': {
          'layers': recommendation.recommendedLayers,
          'accessories': recommendation.accessories,
        },
      },
    );
    
    _lastEveningNotification = DateTime.now();
  }
  
  /// Check for extreme weather conditions
  Future<void> checkExtremeWeather() async {
    if (!_settings.extremeWeatherAlerts) return;
    
    // Check if recently sent
    if (_lastExtremeWeatherNotification != null &&
        DateTime.now().difference(_lastExtremeWeatherNotification!) < 
        const Duration(hours: 6)) {
      return;
    }
    
    // Get current weather
    final weatherResult = await _weatherService.getCurrentWeather();
    if (weatherResult.isLeft()) return;
    
    final weather = weatherResult.getOrElse(() => throw Exception());
    
    // Check for extreme conditions
    String? alertTitle;
    String? alertBody;
    
    if (weather.temperature > 35) {
      alertTitle = 'Extreme Heat Alert! ${weather.temperature.round()}°C';
      alertBody = 'Stay hydrated and wear light, breathable clothing.';
    } else if (weather.temperature < -10) {
      alertTitle = 'Extreme Cold Alert! ${weather.temperature.round()}°C';
      alertBody = 'Bundle up with multiple layers and warm accessories.';
    } else if (weather.conditions.toLowerCase().contains('storm')) {
      alertTitle = 'Storm Alert!';
      alertBody = 'Severe weather expected. Dress appropriately and stay safe.';
    } else if (weather.windSpeed > 20) {
      alertTitle = 'High Wind Alert!';
      alertBody = 'Strong winds expected. Secure loose clothing and accessories.';
    }
    
    if (alertTitle != null) {
      await _notificationService.sendOutfitSuggestion(
        title: alertTitle,
        body: alertBody!,
        data: {
          'type': 'extreme_weather',
          'weather': weather.toJson(),
        },
      );
      
      _lastExtremeWeatherNotification = DateTime.now();
    }
  }
  
  /// Send rain alert
  Future<void> sendRainAlert() async {
    if (!_settings.rainAlerts) return;
    
    // Get current weather
    final weatherResult = await _weatherService.getCurrentWeather();
    if (weatherResult.isLeft()) return;
    
    final weather = weatherResult.getOrElse(() => throw Exception());
    
    if (weather.conditions.toLowerCase().contains('rain') ||
        weather.conditions.toLowerCase().contains('drizzle')) {
      await _notificationService.sendOutfitSuggestion(
        title: 'Rain Alert! ☔',
        body: 'Don\'t forget your umbrella and waterproof shoes!',
        data: {
          'type': 'rain_alert',
          'weather': weather.toJson(),
        },
      );
    }
  }
  
  /// Send temperature change alert
  Future<void> sendTemperatureChangeAlert() async {
    if (!_settings.temperatureChangeAlerts) return;
    
    // Get current and forecast
    final currentResult = await _weatherService.getCurrentWeather();
    final forecastResult = await _weatherService.getWeatherForecast(days: 1);
    
    if (currentResult.isLeft() || forecastResult.isLeft()) return;
    
    final current = currentResult.getOrElse(() => throw Exception());
    final forecasts = forecastResult.getOrElse(() => []);
    
    if (forecasts.isEmpty) return;
    
    // Check for significant temperature change
    final maxTempToday = forecasts
        .where((f) => _isSameDay(f.dateTime, DateTime.now()))
        .map((f) => f.maxTemperature)
        .fold(current.temperature, (max, temp) => temp > max ? temp : max);
    
    final minTempToday = forecasts
        .where((f) => _isSameDay(f.dateTime, DateTime.now()))
        .map((f) => f.minTemperature)
        .fold(current.temperature, (min, temp) => temp < min ? temp : min);
    
    final tempRange = maxTempToday - minTempToday;
    
    if (tempRange > 10) {
      await _notificationService.sendOutfitSuggestion(
        title: 'Large Temperature Change Today!',
        body: 'Expect ${minTempToday.round()}°C to ${maxTempToday.round()}°C. Layer your outfit!',
        data: {
          'type': 'temperature_change',
          'minTemp': minTempToday,
          'maxTemp': maxTempToday,
        },
      );
    }
  }
  
  // Private methods
  
  void _scheduleNotifications() {
    // Schedule morning notification
    if (_settings.morningNotification) {
      final now = DateTime.now();
      final morningTime = DateTime(
        now.year,
        now.month,
        now.day,
        _settings.morningTime.hour,
        _settings.morningTime.minute,
      );
      
      var nextMorning = morningTime;
      if (now.isAfter(morningTime)) {
        nextMorning = morningTime.add(const Duration(days: 1));
      }
      
      final durationUntilMorning = nextMorning.difference(now);
      
      _morningCheckTimer = Timer.periodic(
        const Duration(days: 1),
        (_) => sendMorningNotification(),
      );
      
      // Initial timer for first notification
      Timer(durationUntilMorning, () {
        sendMorningNotification();
      });
    }
    
    // Schedule evening notification
    if (_settings.eveningNotification) {
      final now = DateTime.now();
      final eveningTime = DateTime(
        now.year,
        now.month,
        now.day,
        _settings.eveningTime.hour,
        _settings.eveningTime.minute,
      );
      
      var nextEvening = eveningTime;
      if (now.isAfter(eveningTime)) {
        nextEvening = eveningTime.add(const Duration(days: 1));
      }
      
      final durationUntilEvening = nextEvening.difference(now);
      
      _eveningCheckTimer = Timer.periodic(
        const Duration(days: 1),
        (_) => sendEveningNotification(),
      );
      
      // Initial timer for first notification
      Timer(durationUntilEvening, () {
        sendEveningNotification();
      });
    }
  }
  
  void _startExtremeWeatherMonitoring() {
    if (_settings.extremeWeatherAlerts) {
      // Check every hour
      _extremeWeatherTimer = Timer.periodic(
        const Duration(hours: 1),
        (_) => checkExtremeWeather(),
      );
      
      // Initial check
      checkExtremeWeather();
    }
  }
  
  void _cancelAllTimers() {
    _morningCheckTimer?.cancel();
    _eveningCheckTimer?.cancel();
    _extremeWeatherTimer?.cancel();
  }
  
  bool _isSameDay(DateTime date1, DateTime date2) {
    return date1.year == date2.year &&
           date1.month == date2.month &&
           date1.day == date2.day;
  }
  
  String _getCurrentSeason() {
    final month = DateTime.now().month;
    if (month >= 3 && month <= 5) return 'Spring';
    if (month >= 6 && month <= 8) return 'Summer';
    if (month >= 9 && month <= 11) return 'Fall';
    return 'Winter';
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('weather_notification_settings');
    
    if (settingsJson != null) {
      _settings = WeatherNotificationSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'weather_notification_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  void dispose() {
    _cancelAllTimers();
  }
}

/// Weather notification settings
class WeatherNotificationSettings {
  final bool enabled;
  final bool morningNotification;
  final TimeOfDay morningTime;
  final bool eveningNotification;
  final TimeOfDay eveningTime;
  final bool extremeWeatherAlerts;
  final bool rainAlerts;
  final bool temperatureChangeAlerts;
  
  const WeatherNotificationSettings({
    this.enabled = true,
    this.morningNotification = true,
    this.morningTime = const TimeOfDay(hour: 7, minute: 0),
    this.eveningNotification = true,
    this.eveningTime = const TimeOfDay(hour: 20, minute: 0),
    this.extremeWeatherAlerts = true,
    this.rainAlerts = true,
    this.temperatureChangeAlerts = true,
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'morningNotification': morningNotification,
    'morningTime': {
      'hour': morningTime.hour,
      'minute': morningTime.minute,
    },
    'eveningNotification': eveningNotification,
    'eveningTime': {
      'hour': eveningTime.hour,
      'minute': eveningTime.minute,
    },
    'extremeWeatherAlerts': extremeWeatherAlerts,
    'rainAlerts': rainAlerts,
    'temperatureChangeAlerts': temperatureChangeAlerts,
  };
  
  factory WeatherNotificationSettings.fromJson(Map<String, dynamic> json) {
    return WeatherNotificationSettings(
      enabled: json['enabled'] ?? true,
      morningNotification: json['morningNotification'] ?? true,
      morningTime: TimeOfDay(
        hour: json['morningTime']['hour'] ?? 7,
        minute: json['morningTime']['minute'] ?? 0,
      ),
      eveningNotification: json['eveningNotification'] ?? true,
      eveningTime: TimeOfDay(
        hour: json['eveningTime']['hour'] ?? 20,
        minute: json['eveningTime']['minute'] ?? 0,
      ),
      extremeWeatherAlerts: json['extremeWeatherAlerts'] ?? true,
      rainAlerts: json['rainAlerts'] ?? true,
      temperatureChangeAlerts: json['temperatureChangeAlerts'] ?? true,
    );
  }
  
  WeatherNotificationSettings copyWith({
    bool? enabled,
    bool? morningNotification,
    TimeOfDay? morningTime,
    bool? eveningNotification,
    TimeOfDay? eveningTime,
    bool? extremeWeatherAlerts,
    bool? rainAlerts,
    bool? temperatureChangeAlerts,
  }) {
    return WeatherNotificationSettings(
      enabled: enabled ?? this.enabled,
      morningNotification: morningNotification ?? this.morningNotification,
      morningTime: morningTime ?? this.morningTime,
      eveningNotification: eveningNotification ?? this.eveningNotification,
      eveningTime: eveningTime ?? this.eveningTime,
      extremeWeatherAlerts: extremeWeatherAlerts ?? this.extremeWeatherAlerts,
      rainAlerts: rainAlerts ?? this.rainAlerts,
      temperatureChangeAlerts: temperatureChangeAlerts ?? this.temperatureChangeAlerts,
    );
  }
}