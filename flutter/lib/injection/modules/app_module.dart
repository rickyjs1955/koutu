import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:injectable/injectable.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:local_auth/local_auth.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:koutu/env/env.dart';
import 'package:koutu/injection/injection.dart';
import 'package:koutu/data/local/database/app_database.dart';

/// Module for registering third-party dependencies
@module
abstract class AppModule {
  /// Provide environment configuration
  @Named('env')
  @singleton
  Env get env => Env.current;

  /// Provide Dio instance
  @singleton
  Dio dio(@Named('env') Env env) => Dio(
        BaseOptions(
          baseUrl: env.apiUrl,
          connectTimeout: Duration(seconds: env.apiTimeout),
          receiveTimeout: Duration(seconds: env.apiTimeout),
        ),
      );

  /// Provide SharedPreferences
  @preResolve
  @singleton
  Future<SharedPreferences> get sharedPreferences =>
      SharedPreferences.getInstance();

  /// Provide FlutterSecureStorage
  @Named('secureStorage')
  @singleton
  FlutterSecureStorage get secureStorage => const FlutterSecureStorage();

  /// Provide LocalAuthentication
  @singleton
  LocalAuthentication get localAuth => LocalAuthentication();

  /// Provide Connectivity
  @singleton
  Connectivity get connectivity => Connectivity();

  /// Provide AppDatabase
  @singleton
  AppDatabase get database => AppDatabase();
}

/// Module for registering environment-specific dependencies
@module
abstract class EnvironmentModule {
  /// Development-specific dependencies
  @dev
  @Named('apiUrl')
  String get devApiUrl => 'http://localhost:3000/api/v1';

  /// Staging-specific dependencies
  @staging
  @Named('apiUrl')
  String get stagingApiUrl => 'https://staging-api.koutu.app/api/v1';

  /// Production-specific dependencies
  @prod
  @Named('apiUrl')
  String get prodApiUrl => 'https://api.koutu.app/api/v1';

  /// Test-specific dependencies
  @test
  @Named('apiUrl')
  String get testApiUrl => 'http://localhost:3000/api/v1';
}