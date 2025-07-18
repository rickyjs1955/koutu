import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/weather/weather_service.dart';
import 'package:koutu/services/notification/weather_notification_service.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:dio/dio.dart';

/// Provider for weather service
final weatherServiceProvider = Provider<WeatherService>((ref) {
  final dio = ref.watch(dioProvider);
  
  final weatherService = WeatherService(dio: dio);
  
  // Initialize on creation
  weatherService.initialize();
  
  return weatherService;
});

/// Provider for current weather
final currentWeatherProvider = FutureProvider<WeatherData>((ref) async {
  final weatherService = ref.watch(weatherServiceProvider);
  final result = await weatherService.getCurrentWeather();
  
  return result.fold(
    (failure) => throw failure,
    (weather) => weather,
  );
});

/// Provider for weather forecast
final weatherForecastProvider = FutureProvider.family<
  List<WeatherForecast>,
  int
>((ref, days) async {
  final weatherService = ref.watch(weatherServiceProvider);
  final result = await weatherService.getWeatherForecast(days: days);
  
  return result.fold(
    (failure) => throw failure,
    (forecast) => forecast,
  );
});

/// Provider for outfit weather recommendation
final outfitWeatherRecommendationProvider = Provider.family<
  OutfitWeatherRecommendation?,
  WeatherData?
>((ref, weather) {
  if (weather == null) return null;
  
  final weatherService = ref.watch(weatherServiceProvider);
  return weatherService.getOutfitRecommendation(weather);
});

/// Provider for weather notification service
final weatherNotificationServiceProvider = Provider<WeatherNotificationService>((ref) {
  final weatherService = ref.watch(weatherServiceProvider);
  final notificationService = ref.watch(pushNotificationServiceProvider);
  final recommendationEngine = ref.watch(recommendationEngineProvider);
  final authService = ref.watch(authServiceProvider);
  
  final weatherNotificationService = WeatherNotificationService(
    weatherService: weatherService,
    notificationService: notificationService,
    recommendationEngine: recommendationEngine,
    authService: authService,
  );
  
  // Initialize on creation
  weatherNotificationService.initialize();
  
  // Dispose when provider is destroyed
  ref.onDispose(() {
    weatherNotificationService.dispose();
  });
  
  return weatherNotificationService;
});

/// Provider for weather notification settings
final weatherNotificationSettingsProvider = Provider<WeatherNotificationSettings>((ref) {
  final service = ref.watch(weatherNotificationServiceProvider);
  return service.getSettings();
});

/// Provider for saved weather locations
final savedWeatherLocationsProvider = FutureProvider<List<String>>((ref) async {
  final weatherService = ref.watch(weatherServiceProvider);
  return await weatherService.getSavedLocations();
});