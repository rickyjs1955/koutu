import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:koutu/core/constants/storage_keys.dart';
import 'package:koutu/core/utils/logger.dart';

/// Interceptor for adding authentication token to requests
class AuthInterceptor extends Interceptor {
  static const _storage = FlutterSecureStorage();

  @override
  void onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    // Skip auth for login/register endpoints
    if (options.path.contains('/auth/login') ||
        options.path.contains('/auth/register')) {
      return handler.next(options);
    }

    // Add auth token if available
    final token = await _storage.read(key: StorageKeys.authToken);
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    if (err.response?.statusCode == 401) {
      // Token might be expired, try to refresh
      final refreshToken = await _storage.read(key: StorageKeys.refreshToken);
      if (refreshToken != null) {
        try {
          // TODO: Implement token refresh logic
          // For now, just pass the error
          handler.next(err);
        } catch (e) {
          // Refresh failed, clear tokens and redirect to login
          await _storage.delete(key: StorageKeys.authToken);
          await _storage.delete(key: StorageKeys.refreshToken);
          handler.next(err);
        }
      } else {
        handler.next(err);
      }
    } else {
      handler.next(err);
    }
  }
}

/// Interceptor for logging requests and responses
class LoggingInterceptor extends Interceptor {
  final bool enabled;

  LoggingInterceptor(this.enabled);

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (enabled) {
      Logger.debug('''
=ä REQUEST[${options.method}] => PATH: ${options.path}
Headers: ${options.headers}
Data: ${options.data}
QueryParameters: ${options.queryParameters}
''');
    }
    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (enabled) {
      Logger.debug('''
=å RESPONSE[${response.statusCode}] => PATH: ${response.requestOptions.path}
Headers: ${response.headers}
Data: ${response.data}
''');
    }
    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (enabled) {
      Logger.error('''
L ERROR[${err.response?.statusCode}] => PATH: ${err.requestOptions.path}
Message: ${err.message}
Data: ${err.response?.data}
''', error: err);
    }
    handler.next(err);
  }
}

/// Interceptor for retrying failed requests
class RetryInterceptor extends Interceptor {
  final Dio dio;
  final int maxRetries;

  RetryInterceptor({
    required this.dio,
    this.maxRetries = 3,
  });

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    final statusCode = err.response?.statusCode;
    final shouldRetry = err.type == DioExceptionType.connectionTimeout ||
        err.type == DioExceptionType.sendTimeout ||
        err.type == DioExceptionType.receiveTimeout ||
        (statusCode != null && statusCode >= 500);

    if (shouldRetry && err.requestOptions.extra['retryCount'] != maxRetries) {
      final retryCount = (err.requestOptions.extra['retryCount'] ?? 0) + 1;
      err.requestOptions.extra['retryCount'] = retryCount;

      Logger.debug('Retrying request... (attempt $retryCount/$maxRetries)');

      // Exponential backoff
      await Future.delayed(Duration(seconds: retryCount));

      try {
        final response = await dio.request(
          err.requestOptions.path,
          data: err.requestOptions.data,
          queryParameters: err.requestOptions.queryParameters,
          options: Options(
            method: err.requestOptions.method,
            headers: err.requestOptions.headers,
            extra: err.requestOptions.extra,
          ),
        );
        handler.resolve(response);
      } catch (e) {
        handler.next(err);
      }
    } else {
      handler.next(err);
    }
  }
}

/// Interceptor for handling common errors
class ErrorInterceptor extends Interceptor {
  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    DioException transformedError = err;

    switch (err.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        transformedError = DioException(
          requestOptions: err.requestOptions,
          error: 'Connection timeout. Please check your internet connection.',
          type: err.type,
        );
        break;
      case DioExceptionType.connectionError:
        if (err.error is SocketException) {
          transformedError = DioException(
            requestOptions: err.requestOptions,
            error: 'No internet connection. Please check your network settings.',
            type: err.type,
          );
        }
        break;
      case DioExceptionType.badResponse:
        final statusCode = err.response?.statusCode;
        String message;
        switch (statusCode) {
          case 400:
            message = 'Bad request. Please check your input.';
            break;
          case 401:
            message = 'Unauthorized. Please login again.';
            break;
          case 403:
            message = 'Forbidden. You don\'t have permission to access this resource.';
            break;
          case 404:
            message = 'Resource not found.';
            break;
          case 500:
            message = 'Server error. Please try again later.';
            break;
          default:
            message = 'Something went wrong. Please try again.';
        }
        transformedError = DioException(
          requestOptions: err.requestOptions,
          response: err.response,
          error: message,
          type: err.type,
        );
        break;
      default:
        break;
    }

    handler.next(transformedError);
  }
}