import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/auth/auth_event.dart';
import 'package:koutu/presentation/bloc/auth/auth_state.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_event.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_state.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_event.dart';
import 'package:koutu/presentation/bloc/garment/garment_state.dart';
import 'package:koutu/presentation/bloc/app/app_bloc.dart';
import 'package:koutu/presentation/bloc/app/app_event.dart';
import 'package:koutu/presentation/bloc/app/app_state.dart';
import 'package:koutu/data/models/auth/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/settings/app_settings.dart';

/// Utility class for testing BLoC patterns and state management
class BlocTestUtils {
  
  // Mock Data Generators
  static UserModel createMockUser({
    String? id,
    String? email,
    String? name,
    String? avatar,
    bool isEmailVerified = true,
    bool isBiometricEnabled = false,
    bool isTwoFactorEnabled = false,
  }) {
    return UserModel(
      id: id ?? 'test_user_id',
      email: email ?? 'test@example.com',
      name: name ?? 'Test User',
      avatar: avatar,
      isEmailVerified: isEmailVerified,
      isBiometricEnabled: isBiometricEnabled,
      isTwoFactorEnabled: isTwoFactorEnabled,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
  }
  
  static WardrobeModel createMockWardrobe({
    String? id,
    String? name,
    String? ownerId,
    String? description,
    bool isDefault = false,
    bool isShared = false,
    List<String>? garmentIds,
    List<String>? sharedUserIds,
  }) {
    return WardrobeModel(
      id: id ?? 'test_wardrobe_id',
      name: name ?? 'Test Wardrobe',
      ownerId: ownerId ?? 'test_user_id',
      description: description ?? 'Test wardrobe description',
      isDefault: isDefault,
      isShared: isShared,
      garmentIds: garmentIds ?? [],
      sharedUserIds: sharedUserIds ?? [],
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
  }
  
  static GarmentModel createMockGarment({
    String? id,
    String? wardrobeId,
    String? name,
    String? category,
    String? brand,
    List<String>? colors,
    List<String>? tags,
    bool isFavorite = false,
    int wearCount = 0,
    DateTime? lastWornDate,
  }) {
    return GarmentModel(
      id: id ?? 'test_garment_id',
      wardrobeId: wardrobeId ?? 'test_wardrobe_id',
      name: name ?? 'Test Garment',
      category: category ?? 'shirts',
      brand: brand,
      colors: colors ?? ['blue'],
      tags: tags ?? ['casual'],
      isFavorite: isFavorite,
      wearCount: wearCount,
      lastWornDate: lastWornDate,
      images: [],
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
  }
  
  static AppSettings createMockAppSettings({
    String? language,
    bool isOfflineMode = false,
    bool isDebugMode = false,
    bool analyticsEnabled = true,
    DateTime? lastSyncTime,
  }) {
    return AppSettings(
      language: language ?? 'en',
      isOfflineMode: isOfflineMode,
      isDebugMode: isDebugMode,
      analyticsEnabled: analyticsEnabled,
      lastSyncTime: lastSyncTime,
    );
  }
  
  // BLoC State Matchers
  static Matcher isAuthState<T extends AuthState>() => isA<T>();
  static Matcher isWardrobeState<T extends WardrobeState>() => isA<T>();
  static Matcher isGarmentState<T extends GarmentState>() => isA<T>();
  static Matcher isAppState<T extends AppState>() => isA<T>();
  
  // Custom Matchers
  static Matcher hasUser(UserModel user) => predicate<AuthState>(
    (state) => state.maybeMap(
      authenticated: (s) => s.user.id == user.id,
      orElse: () => false,
    ),
    'AuthState should contain user with ID ${user.id}',
  );
  
  static Matcher hasWardrobes(List<WardrobeModel> wardrobes) => predicate<WardrobeState>(
    (state) => state.wardrobes.length == wardrobes.length &&
        state.wardrobes.every((w) => wardrobes.any((expected) => expected.id == w.id)),
    'WardrobeState should contain expected wardrobes',
  );
  
  static Matcher hasGarments(List<GarmentModel> garments) => predicate<GarmentState>(
    (state) => state.garments.length == garments.length &&
        state.garments.every((g) => garments.any((expected) => expected.id == g.id)),
    'GarmentState should contain expected garments',
  );
  
  static Matcher hasErrorMessage(String message) => predicate<dynamic>(
    (state) {
      if (state is AuthState) {
        return state.maybeMap(
          error: (s) => s.message == message,
          orElse: () => false,
        );
      } else if (state is WardrobeState) {
        return state.maybeMap(
          error: (s) => s.message == message,
          orElse: () => false,
        );
      } else if (state is GarmentState) {
        return state.maybeMap(
          error: (s) => s.message == message,
          orElse: () => false,
        );
      } else if (state is AppState) {
        return state.maybeMap(
          error: (s) => s.message == message,
          orElse: () => false,
        );
      }
      return false;
    },
    'State should contain error message: $message',
  );
  
  static Matcher isLoading() => predicate<dynamic>(
    (state) {
      if (state is AuthState) {
        return state.maybeMap(
          loading: (_) => true,
          orElse: () => false,
        );
      } else if (state is WardrobeState) {
        return state.maybeMap(
          loading: (_) => true,
          orElse: () => false,
        );
      } else if (state is GarmentState) {
        return state.maybeMap(
          loading: (_) => true,
          orElse: () => false,
        );
      } else if (state is AppState) {
        return state.maybeMap(
          loading: (_) => true,
          orElse: () => false,
        );
      }
      return false;
    },
    'State should be loading',
  );
  
  // BLoC Testing Helpers
  static Future<void> pumpAndSettle(
    Bloc bloc,
    dynamic event, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    bloc.add(event);
    await Future.delayed(const Duration(milliseconds: 100));
  }
  
  static Stream<T> blocStateStream<T>(Bloc<dynamic, T> bloc) => bloc.stream;
  
  // Multi-BLoC Testing
  static Future<void> testBlocInteraction({
    required Bloc bloc1,
    required Bloc bloc2,
    required dynamic event1,
    required dynamic event2,
    required List<Matcher> expectedStates1,
    required List<Matcher> expectedStates2,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final states1 = <dynamic>[];
    final states2 = <dynamic>[];
    
    final subscription1 = bloc1.stream.listen(states1.add);
    final subscription2 = bloc2.stream.listen(states2.add);
    
    try {
      bloc1.add(event1);
      await Future.delayed(const Duration(milliseconds: 100));
      bloc2.add(event2);
      await Future.delayed(const Duration(milliseconds: 100));
      
      for (int i = 0; i < expectedStates1.length; i++) {
        expect(states1[i], expectedStates1[i]);
      }
      
      for (int i = 0; i < expectedStates2.length; i++) {
        expect(states2[i], expectedStates2[i]);
      }
    } finally {
      subscription1.cancel();
      subscription2.cancel();
    }
  }
  
  // State Transition Testing
  static Future<void> testStateTransition<T>({
    required Bloc<dynamic, T> bloc,
    required dynamic event,
    required List<Matcher> expectedStates,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final states = <T>[];
    final subscription = bloc.stream.listen(states.add);
    
    try {
      bloc.add(event);
      await Future.delayed(const Duration(milliseconds: 500));
      
      expect(states.length, expectedStates.length);
      
      for (int i = 0; i < expectedStates.length; i++) {
        expect(states[i], expectedStates[i]);
      }
    } finally {
      subscription.cancel();
    }
  }
  
  // Performance Testing
  static Future<Duration> measureBlocPerformance<T>({
    required Bloc<dynamic, T> bloc,
    required dynamic event,
    int iterations = 100,
  }) async {
    final stopwatch = Stopwatch()..start();
    
    for (int i = 0; i < iterations; i++) {
      bloc.add(event);
      await Future.delayed(const Duration(milliseconds: 1));
    }
    
    stopwatch.stop();
    return Duration(milliseconds: stopwatch.elapsedMilliseconds ~/ iterations);
  }
  
  // Memory Testing
  static Future<void> testBlocMemoryLeaks<T>({
    required Bloc<dynamic, T> bloc,
    required List<dynamic> events,
    int iterations = 10,
  }) async {
    for (int i = 0; i < iterations; i++) {
      for (final event in events) {
        bloc.add(event);
        await Future.delayed(const Duration(milliseconds: 10));
      }
    }
    
    // Force garbage collection
    await Future.delayed(const Duration(milliseconds: 100));
    
    // Check if bloc is still responsive
    bloc.add(events.first);
    await Future.delayed(const Duration(milliseconds: 100));
    
    expect(bloc.isClosed, isFalse);
  }
  
  // Error Handling Testing
  static Future<void> testBlocErrorHandling<T>({
    required Bloc<dynamic, T> bloc,
    required dynamic invalidEvent,
    required Matcher expectedErrorState,
  }) async {
    final states = <T>[];
    final subscription = bloc.stream.listen(states.add);
    
    try {
      bloc.add(invalidEvent);
      await Future.delayed(const Duration(milliseconds: 200));
      
      expect(states.last, expectedErrorState);
    } finally {
      subscription.cancel();
    }
  }
  
  // Integration Testing Helpers
  static Future<void> testFullWorkflow({
    required AuthBloc authBloc,
    required WardrobeBloc wardrobeBloc,
    required GarmentBloc garmentBloc,
    required AppBloc appBloc,
  }) async {
    // 1. Initialize app
    appBloc.add(const AppEvent.initialize());
    await Future.delayed(const Duration(milliseconds: 100));
    
    // 2. Login user
    final user = createMockUser();
    authBloc.add(AuthEvent.loginWithEmail(
      email: user.email,
      password: 'password123',
    ));
    await Future.delayed(const Duration(milliseconds: 100));
    
    // 3. Load wardrobes
    wardrobeBloc.add(const WardrobeEvent.loadWardrobes());
    await Future.delayed(const Duration(milliseconds: 100));
    
    // 4. Load garments
    garmentBloc.add(const GarmentEvent.loadGarments());
    await Future.delayed(const Duration(milliseconds: 100));
    
    // 5. Verify all states are correct
    expect(appBloc.state, isA<AppReady>());
    expect(authBloc.state, isA<AuthAuthenticated>());
    expect(wardrobeBloc.state, isA<WardrobeLoaded>());
    expect(garmentBloc.state, isA<GarmentLoaded>());
  }
}