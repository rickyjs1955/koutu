import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:dio/dio.dart';
import 'package:koutu/core/config/environment.dart';
import 'package:geolocator/geolocator.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';

/// Service for fetching weather data
class WeatherService {
  final Dio _dio;
  
  // Cache
  WeatherData? _cachedWeather;
  DateTime? _cacheTime;
  static const Duration _cacheExpiry = Duration(minutes: 30);
  
  // Location
  Position? _lastPosition;
  String? _preferredLocation;
  
  WeatherService({
    required Dio dio,
  }) : _dio = dio;
  
  /// Initialize weather service
  Future<void> initialize() async {
    await _loadPreferences();
  }
  
  /// Get current weather
  Future<Either<Failure, WeatherData>> getCurrentWeather({
    bool forceRefresh = false,
  }) async {
    try {
      // Check cache
      if (!forceRefresh && _isCacheValid()) {
        return Right(_cachedWeather!);
      }
      
      // Get location
      final locationResult = await _getLocation();
      if (locationResult.isLeft()) {
        return locationResult.fold(
          (failure) => Left(failure),
          (_) => Left(ServerFailure('Failed to get location')),
        );
      }
      
      final position = locationResult.getOrElse(() => _lastPosition!);
      
      // Fetch weather data
      final response = await _dio.get(
        'https://api.openweathermap.org/data/2.5/weather',
        queryParameters: {
          'lat': position.latitude,
          'lon': position.longitude,
          'appid': Environment.weatherApiKey,
          'units': 'metric',
        },
      );
      
      if (response.statusCode == 200) {
        final weather = WeatherData.fromJson(response.data);
        
        // Cache result
        _cachedWeather = weather;
        _cacheTime = DateTime.now();
        
        return Right(weather);
      } else {
        throw Exception('Failed to fetch weather: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get weather: $e'));
    }
  }
  
  /// Get weather forecast
  Future<Either<Failure, List<WeatherForecast>>> getWeatherForecast({
    int days = 5,
  }) async {
    try {
      // Get location
      final locationResult = await _getLocation();
      if (locationResult.isLeft()) {
        return locationResult.fold(
          (failure) => Left(failure),
          (_) => Left(ServerFailure('Failed to get location')),
        );
      }
      
      final position = locationResult.getOrElse(() => _lastPosition!);
      
      // Fetch forecast data
      final response = await _dio.get(
        'https://api.openweathermap.org/data/2.5/forecast',
        queryParameters: {
          'lat': position.latitude,
          'lon': position.longitude,
          'appid': Environment.weatherApiKey,
          'units': 'metric',
          'cnt': days * 8, // 8 forecasts per day (every 3 hours)
        },
      );
      
      if (response.statusCode == 200) {
        final List<dynamic> forecastList = response.data['list'];
        final forecasts = forecastList
            .map((json) => WeatherForecast.fromJson(json))
            .toList();
        
        // Group by day and get daily summary
        final dailyForecasts = _groupForecastsByDay(forecasts);
        
        return Right(dailyForecasts);
      } else {
        throw Exception('Failed to fetch forecast: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get forecast: $e'));
    }
  }
  
  /// Get outfit recommendations based on weather
  OutfitWeatherRecommendation getOutfitRecommendation(WeatherData weather) {
    final temp = weather.temperature;
    final conditions = weather.conditions.toLowerCase();
    final windSpeed = weather.windSpeed;
    final humidity = weather.humidity;
    
    // Temperature-based categories
    String tempCategory;
    List<String> recommendedLayers = [];
    List<String> accessories = [];
    String advice = '';
    
    if (temp < 0) {
      tempCategory = 'freezing';
      recommendedLayers = ['thermal underwear', 'heavy coat', 'warm layers'];
      accessories = ['gloves', 'scarf', 'warm hat', 'winter boots'];
      advice = 'Bundle up! It\'s freezing outside.';
    } else if (temp < 10) {
      tempCategory = 'cold';
      recommendedLayers = ['jacket', 'sweater', 'long pants'];
      accessories = ['light gloves', 'scarf'];
      advice = 'It\'s quite cold. Layer up!';
    } else if (temp < 20) {
      tempCategory = 'cool';
      recommendedLayers = ['light jacket', 'long sleeves'];
      accessories = [];
      advice = 'Perfect weather for a light jacket.';
    } else if (temp < 25) {
      tempCategory = 'mild';
      recommendedLayers = ['t-shirt', 'light cardigan'];
      accessories = ['sunglasses'];
      advice = 'Comfortable weather for light clothing.';
    } else if (temp < 30) {
      tempCategory = 'warm';
      recommendedLayers = ['t-shirt', 'shorts'];
      accessories = ['sunglasses', 'sun hat'];
      advice = 'Stay cool with breathable fabrics.';
    } else {
      tempCategory = 'hot';
      recommendedLayers = ['tank top', 'shorts', 'light fabrics'];
      accessories = ['sunglasses', 'sun hat', 'sunscreen'];
      advice = 'It\'s hot! Choose light colors and breathable materials.';
    }
    
    // Weather condition adjustments
    if (conditions.contains('rain') || conditions.contains('drizzle')) {
      accessories.add('umbrella');
      accessories.add('waterproof shoes');
      advice += ' Don\'t forget rain protection!';
    } else if (conditions.contains('snow')) {
      accessories.add('snow boots');
      accessories.add('waterproof gloves');
      advice += ' Snow expected - wear waterproof items.';
    }
    
    // Wind adjustments
    if (windSpeed > 10) {
      accessories.add('windbreaker');
      advice += ' It\'s windy - consider wind protection.';
    }
    
    // Humidity adjustments
    if (humidity > 70 && temp > 20) {
      advice += ' High humidity - choose moisture-wicking fabrics.';
    }
    
    return OutfitWeatherRecommendation(
      temperatureCategory: tempCategory,
      recommendedLayers: recommendedLayers,
      accessories: accessories,
      advice: advice,
      weather: weather,
    );
  }
  
  /// Set preferred location
  Future<Either<Failure, void>> setPreferredLocation(String location) async {
    try {
      _preferredLocation = location;
      await _savePreferences();
      
      // Clear cache to force refresh with new location
      _cachedWeather = null;
      _cacheTime = null;
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to set location: $e'));
    }
  }
  
  /// Get saved locations
  Future<List<String>> getSavedLocations() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList('saved_weather_locations') ?? [];
  }
  
  /// Add saved location
  Future<void> addSavedLocation(String location) async {
    final prefs = await SharedPreferences.getInstance();
    final locations = await getSavedLocations();
    if (!locations.contains(location)) {
      locations.add(location);
      await prefs.setStringList('saved_weather_locations', locations);
    }
  }
  
  // Private methods
  
  Future<Either<Failure, Position>> _getLocation() async {
    try {
      // Check if we should use preferred location
      if (_preferredLocation != null) {
        // In a real app, you'd geocode the location string
        // For now, we'll use the device location
      }
      
      // Check location permissions
      final permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        final requestedPermission = await Geolocator.requestPermission();
        if (requestedPermission == LocationPermission.denied) {
          return Left(PermissionFailure('Location permission denied'));
        }
      }
      
      if (permission == LocationPermission.deniedForever) {
        return Left(PermissionFailure('Location permission permanently denied'));
      }
      
      // Get current position
      final position = await Geolocator.getCurrentPosition(
        desiredAccuracy: LocationAccuracy.medium,
        timeLimit: const Duration(seconds: 10),
      );
      
      _lastPosition = position;
      return Right(position);
    } catch (e) {
      return Left(ServerFailure('Failed to get location: $e'));
    }
  }
  
  bool _isCacheValid() {
    if (_cachedWeather == null || _cacheTime == null) return false;
    return DateTime.now().difference(_cacheTime!) < _cacheExpiry;
  }
  
  List<WeatherForecast> _groupForecastsByDay(List<WeatherForecast> forecasts) {
    final Map<String, List<WeatherForecast>> groupedByDay = {};
    
    for (final forecast in forecasts) {
      final dayKey = '${forecast.dateTime.year}-${forecast.dateTime.month}-${forecast.dateTime.day}';
      groupedByDay.putIfAbsent(dayKey, () => []).add(forecast);
    }
    
    // Create daily summaries
    final dailyForecasts = <WeatherForecast>[];
    groupedByDay.forEach((day, dayForecasts) {
      // Get midday forecast or first available
      final middayForecast = dayForecasts.firstWhere(
        (f) => f.dateTime.hour >= 11 && f.dateTime.hour <= 13,
        orElse: () => dayForecasts.first,
      );
      
      // Calculate daily min/max
      final temps = dayForecasts.map((f) => f.temperature).toList();
      final minTemp = temps.reduce((a, b) => a < b ? a : b);
      final maxTemp = temps.reduce((a, b) => a > b ? a : b);
      
      dailyForecasts.add(WeatherForecast(
        dateTime: middayForecast.dateTime,
        temperature: middayForecast.temperature,
        minTemperature: minTemp,
        maxTemperature: maxTemp,
        conditions: middayForecast.conditions,
        icon: middayForecast.icon,
        humidity: middayForecast.humidity,
        windSpeed: middayForecast.windSpeed,
      ));
    });
    
    return dailyForecasts;
  }
  
  Future<void> _loadPreferences() async {
    final prefs = await SharedPreferences.getInstance();
    _preferredLocation = prefs.getString('preferred_weather_location');
  }
  
  Future<void> _savePreferences() async {
    final prefs = await SharedPreferences.getInstance();
    if (_preferredLocation != null) {
      await prefs.setString('preferred_weather_location', _preferredLocation!);
    }
  }
}

/// Weather data model
class WeatherData {
  final double temperature;
  final double feelsLike;
  final double minTemperature;
  final double maxTemperature;
  final String conditions;
  final String description;
  final String icon;
  final int humidity;
  final double windSpeed;
  final String cityName;
  final DateTime sunrise;
  final DateTime sunset;
  
  const WeatherData({
    required this.temperature,
    required this.feelsLike,
    required this.minTemperature,
    required this.maxTemperature,
    required this.conditions,
    required this.description,
    required this.icon,
    required this.humidity,
    required this.windSpeed,
    required this.cityName,
    required this.sunrise,
    required this.sunset,
  });
  
  factory WeatherData.fromJson(Map<String, dynamic> json) {
    return WeatherData(
      temperature: json['main']['temp'].toDouble(),
      feelsLike: json['main']['feels_like'].toDouble(),
      minTemperature: json['main']['temp_min'].toDouble(),
      maxTemperature: json['main']['temp_max'].toDouble(),
      conditions: json['weather'][0]['main'],
      description: json['weather'][0]['description'],
      icon: json['weather'][0]['icon'],
      humidity: json['main']['humidity'],
      windSpeed: json['wind']['speed'].toDouble(),
      cityName: json['name'],
      sunrise: DateTime.fromMillisecondsSinceEpoch(json['sys']['sunrise'] * 1000),
      sunset: DateTime.fromMillisecondsSinceEpoch(json['sys']['sunset'] * 1000),
    );
  }
  
  Map<String, dynamic> toJson() => {
    'temperature': temperature,
    'feelsLike': feelsLike,
    'minTemperature': minTemperature,
    'maxTemperature': maxTemperature,
    'conditions': conditions,
    'description': description,
    'icon': icon,
    'humidity': humidity,
    'windSpeed': windSpeed,
    'cityName': cityName,
    'sunrise': sunrise.millisecondsSinceEpoch ~/ 1000,
    'sunset': sunset.millisecondsSinceEpoch ~/ 1000,
  };
}

/// Weather forecast model
class WeatherForecast {
  final DateTime dateTime;
  final double temperature;
  final double minTemperature;
  final double maxTemperature;
  final String conditions;
  final String icon;
  final int humidity;
  final double windSpeed;
  
  const WeatherForecast({
    required this.dateTime,
    required this.temperature,
    required this.minTemperature,
    required this.maxTemperature,
    required this.conditions,
    required this.icon,
    required this.humidity,
    required this.windSpeed,
  });
  
  factory WeatherForecast.fromJson(Map<String, dynamic> json) {
    return WeatherForecast(
      dateTime: DateTime.fromMillisecondsSinceEpoch(json['dt'] * 1000),
      temperature: json['main']['temp'].toDouble(),
      minTemperature: json['main']['temp_min'].toDouble(),
      maxTemperature: json['main']['temp_max'].toDouble(),
      conditions: json['weather'][0]['main'],
      icon: json['weather'][0]['icon'],
      humidity: json['main']['humidity'],
      windSpeed: json['wind']['speed'].toDouble(),
    );
  }
}

/// Outfit weather recommendation
class OutfitWeatherRecommendation {
  final String temperatureCategory;
  final List<String> recommendedLayers;
  final List<String> accessories;
  final String advice;
  final WeatherData weather;
  
  const OutfitWeatherRecommendation({
    required this.temperatureCategory,
    required this.recommendedLayers,
    required this.accessories,
    required this.advice,
    required this.weather,
  });
}