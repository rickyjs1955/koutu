import 'dart:developer' as developer;

/// Simple logger utility for the application
class Logger {
  static const String _name = 'Koutu';

  /// Log debug messages
  static void debug(String message, {Object? error, StackTrace? stackTrace}) {
    if (const bool.fromEnvironment('dart.vm.product') == false) {
      developer.log(
        message,
        name: _name,
        level: 500,
        error: error,
        stackTrace: stackTrace,
      );
    }
  }

  /// Log info messages
  static void info(String message, {Object? error, StackTrace? stackTrace}) {
    developer.log(
      message,
      name: _name,
      level: 800,
      error: error,
      stackTrace: stackTrace,
    );
  }

  /// Log warning messages
  static void warning(String message, {Object? error, StackTrace? stackTrace}) {
    developer.log(
      message,
      name: _name,
      level: 900,
      error: error,
      stackTrace: stackTrace,
    );
  }

  /// Log error messages
  static void error(String message, {Object? error, StackTrace? stackTrace}) {
    developer.log(
      message,
      name: _name,
      level: 1000,
      error: error,
      stackTrace: stackTrace,
    );
  }
}