import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:get_it/get_it.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/domain/repositories/i_auth_repository.dart';
import 'package:koutu/domain/repositories/i_wardrobe_repository.dart';
import 'package:koutu/domain/repositories/i_garment_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/data/datasources/local/app_database.dart';
import 'package:koutu/data/datasources/remote/api_client.dart';
import 'package:koutu/core/network/network_info.dart';
import 'package:koutu/services/storage/secure_storage_service.dart';
import 'package:koutu/services/storage/cache_service.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// Generate mocks for all dependencies
@GenerateMocks([
  IAuthRepository,
  IWardrobeRepository,
  IGarmentRepository,
  IImageRepository,
  AppDatabase,
  ApiClient,
  NetworkInfo,
  SecureStorageService,
  CacheService,
  Dio,
  SharedPreferences,
  FlutterSecureStorage,
])
void main() {}

/// Test helper utilities
class TestHelpers {
  /// Creates a testable widget with all necessary wrappers
  static Widget makeTestableWidget({
    required Widget child,
    List<BlocProvider>? blocProviders,
    NavigatorObserver? navigatorObserver,
    ThemeData? theme,
  }) {
    return MultiBlocProvider(
      providers: blocProviders ?? [],
      child: MaterialApp(
        theme: theme ?? ThemeData.light(),
        home: Scaffold(body: child),
        navigatorObservers: navigatorObserver != null ? [navigatorObserver] : [],
      ),
    );
  }

  /// Sets up GetIt for testing
  static void setupTestInjection() {
    final getIt = GetIt.instance;
    
    // Reset GetIt to ensure clean state
    getIt.reset();
    
    // Register test dependencies here
    // These would typically be mocks
  }

  /// Cleans up after tests
  static void tearDownTestInjection() {
    GetIt.instance.reset();
  }

  /// Pumps widget and settles for animations
  static Future<void> pumpAndSettle(
    WidgetTester tester, {
    Duration duration = const Duration(milliseconds: 100),
    int maxIterations = 10,
  }) async {
    for (int i = 0; i < maxIterations; i++) {
      await tester.pump(duration);
      if (!tester.binding.hasScheduledFrame) {
        break;
      }
    }
  }

  /// Finds widgets by key string
  static Finder findByKeyString(String key) {
    return find.byKey(Key(key));
  }

  /// Waits for a condition to be true
  static Future<void> waitFor(
    WidgetTester tester,
    bool Function() condition, {
    Duration timeout = const Duration(seconds: 5),
    Duration pollInterval = const Duration(milliseconds: 100),
  }) async {
    final end = DateTime.now().add(timeout);
    
    while (!condition() && DateTime.now().isBefore(end)) {
      await tester.pump(pollInterval);
    }
    
    if (!condition()) {
      throw TimeoutException('Condition not met within timeout');
    }
  }

  /// Creates a golden test variant for different screen sizes
  static Set<String> get screenVariants => {
    'phone_portrait',
    'phone_landscape',
    'tablet_portrait',
    'tablet_landscape',
  };

  /// Sets the screen size for golden tests
  static Future<void> setScreenSize(
    WidgetTester tester,
    String variant,
  ) async {
    final Map<String, Size> sizes = {
      'phone_portrait': const Size(375, 812), // iPhone X
      'phone_landscape': const Size(812, 375),
      'tablet_portrait': const Size(768, 1024), // iPad
      'tablet_landscape': const Size(1024, 768),
    };

    final size = sizes[variant] ?? sizes['phone_portrait']!;
    await tester.binding.setSurfaceSize(size);
    tester.binding.window.physicalSizeTestValue = size;
    tester.binding.window.devicePixelRatioTestValue = 1.0;
  }

  /// Matcher for finding widgets with specific text
  static Matcher hasText(String text) {
    return findsOneWidget.and(
      matchesWidgetText(text),
    );
  }

  /// Custom matcher for widget text
  static Matcher matchesWidgetText(String text) {
    return MatchesWidgetText(text);
  }
}

/// Custom matcher for widget text
class MatchesWidgetText extends Matcher {
  final String text;

  MatchesWidgetText(this.text);

  @override
  bool matches(Object? item, Map matchState) {
    if (item is Text) {
      return item.data == text || 
             (item.textSpan?.toPlainText() == text);
    }
    if (item is RichText) {
      return item.text.toPlainText() == text;
    }
    return false;
  }

  @override
  Description describe(Description description) {
    return description.add('widget with text "$text"');
  }
}

/// Test data builders for creating mock objects
class TestDataBuilder {
  static Map<String, dynamic> validUser() => {
    'id': '123',
    'email': 'test@example.com',
    'username': 'testuser',
    'fullName': 'Test User',
    'avatarUrl': 'https://example.com/avatar.jpg',
    'createdAt': DateTime.now().toIso8601String(),
    'updatedAt': DateTime.now().toIso8601String(),
  };

  static Map<String, dynamic> validWardrobe() => {
    'id': '456',
    'userId': '123',
    'name': 'Test Wardrobe',
    'description': 'A test wardrobe',
    'imageUrl': 'https://example.com/wardrobe.jpg',
    'colorTheme': 'blue',
    'iconName': 'wardrobe',
    'isDefault': false,
    'isShared': false,
    'garmentIds': <String>[],
    'createdAt': DateTime.now().toIso8601String(),
    'updatedAt': DateTime.now().toIso8601String(),
  };

  static Map<String, dynamic> validGarment() => {
    'id': '789',
    'wardrobeId': '456',
    'name': 'Test Garment',
    'category': 'tops',
    'subcategory': 'T-Shirt',
    'brand': 'Test Brand',
    'colors': ['blue', 'white'],
    'size': 'M',
    'material': 'Cotton',
    'price': 29.99,
    'purchaseDate': DateTime.now().subtract(const Duration(days: 30)).toIso8601String(),
    'tags': ['casual', 'summer'],
    'notes': 'Test notes',
    'images': [
      {
        'id': '001',
        'url': 'https://example.com/garment1.jpg',
        'thumbnailUrl': 'https://example.com/garment1_thumb.jpg',
        'width': 800,
        'height': 1200,
        'createdAt': DateTime.now().toIso8601String(),
      }
    ],
    'isFavorite': false,
    'wearCount': 5,
    'lastWornDate': DateTime.now().subtract(const Duration(days: 7)).toIso8601String(),
    'createdAt': DateTime.now().toIso8601String(),
    'updatedAt': DateTime.now().toIso8601String(),
  };
}

/// Extension for common test actions
extension WidgetTesterExtension on WidgetTester {
  /// Enters text into a text field with a specific key
  Future<void> enterTextByKey(String key, String text) async {
    await enterText(find.byKey(Key(key)), text);
    await pump();
  }

  /// Taps a widget with a specific key
  Future<void> tapByKey(String key) async {
    await tap(find.byKey(Key(key)));
    await pump();
  }

  /// Scrolls until a widget is visible
  Future<void> scrollUntilVisible(
    Finder finder, {
    double delta = 300,
    int maxScrolls = 10,
    Finder? scrollable,
  }) async {
    for (int i = 0; i < maxScrolls; i++) {
      if (finder.evaluate().isNotEmpty) {
        return;
      }
      
      await drag(
        scrollable ?? find.byType(Scrollable).first,
        Offset(0, -delta),
      );
      await pump();
    }
  }
}

/// Timeout exception for test helpers
class TimeoutException implements Exception {
  final String message;
  
  TimeoutException(this.message);
  
  @override
  String toString() => 'TimeoutException: $message';
}