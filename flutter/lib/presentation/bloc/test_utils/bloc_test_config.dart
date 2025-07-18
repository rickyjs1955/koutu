import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/domain/repositories/i_auth_repository.dart';
import 'package:koutu/domain/repositories/i_wardrobe_repository.dart';
import 'package:koutu/domain/repositories/i_garment_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/domain/repositories/i_connectivity_repository.dart';
import 'package:koutu/domain/repositories/i_sync_repository.dart';
import 'package:koutu/domain/repositories/i_settings_repository.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/bloc/app/app_bloc.dart';
import 'package:koutu/data/models/auth/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/settings/app_settings.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Mock repositories for testing
class MockAuthRepository extends Mock implements IAuthRepository {}
class MockWardrobeRepository extends Mock implements IWardrobeRepository {}
class MockGarmentRepository extends Mock implements IGarmentRepository {}
class MockImageRepository extends Mock implements IImageRepository {}
class MockConnectivityRepository extends Mock implements IConnectivityRepository {}
class MockSyncRepository extends Mock implements ISyncRepository {}
class MockSettingsRepository extends Mock implements ISettingsRepository {}
class MockSharedPreferences extends Mock implements SharedPreferences {}

/// Test configuration for BLoC testing
class BlocTestConfig {
  // Mock repositories
  late MockAuthRepository mockAuthRepository;
  late MockWardrobeRepository mockWardrobeRepository;
  late MockGarmentRepository mockGarmentRepository;
  late MockImageRepository mockImageRepository;
  late MockConnectivityRepository mockConnectivityRepository;
  late MockSyncRepository mockSyncRepository;
  late MockSettingsRepository mockSettingsRepository;
  late MockSharedPreferences mockSharedPreferences;
  
  // BLoCs
  late AuthBloc authBloc;
  late WardrobeBloc wardrobeBloc;
  late GarmentBloc garmentBloc;
  late AppBloc appBloc;
  
  // Test data
  late UserModel testUser;
  late List<WardrobeModel> testWardrobes;
  late List<GarmentModel> testGarments;
  late AppSettings testSettings;
  
  BlocTestConfig() {
    _initializeMocks();
    _initializeTestData();
    _initializeBlocs();
    _setupDefaultMockBehaviors();
  }
  
  void _initializeMocks() {
    mockAuthRepository = MockAuthRepository();
    mockWardrobeRepository = MockWardrobeRepository();
    mockGarmentRepository = MockGarmentRepository();
    mockImageRepository = MockImageRepository();
    mockConnectivityRepository = MockConnectivityRepository();
    mockSyncRepository = MockSyncRepository();
    mockSettingsRepository = MockSettingsRepository();
    mockSharedPreferences = MockSharedPreferences();
  }
  
  void _initializeTestData() {
    testUser = UserModel(
      id: 'test_user_id',
      email: 'test@example.com',
      name: 'Test User',
      avatar: null,
      isEmailVerified: true,
      isBiometricEnabled: false,
      isTwoFactorEnabled: false,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );
    
    testWardrobes = [
      WardrobeModel(
        id: 'wardrobe_1',
        name: 'Default Wardrobe',
        ownerId: testUser.id,
        description: 'My main wardrobe',
        isDefault: true,
        isShared: false,
        garmentIds: ['garment_1', 'garment_2'],
        sharedUserIds: [],
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
      WardrobeModel(
        id: 'wardrobe_2',
        name: 'Shared Wardrobe',
        ownerId: testUser.id,
        description: 'Shared with family',
        isDefault: false,
        isShared: true,
        garmentIds: ['garment_3'],
        sharedUserIds: ['user_2'],
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
    ];
    
    testGarments = [
      GarmentModel(
        id: 'garment_1',
        wardrobeId: 'wardrobe_1',
        name: 'Blue Shirt',
        category: 'shirts',
        subcategory: 'casual',
        brand: 'Nike',
        colors: ['blue'],
        size: 'M',
        material: 'cotton',
        price: 29.99,
        purchaseDate: DateTime.now().subtract(const Duration(days: 30)),
        tags: ['casual', 'work'],
        notes: 'Comfortable for daily wear',
        images: [],
        isFavorite: true,
        wearCount: 5,
        lastWornDate: DateTime.now().subtract(const Duration(days: 2)),
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
      GarmentModel(
        id: 'garment_2',
        wardrobeId: 'wardrobe_1',
        name: 'Black Jeans',
        category: 'pants',
        subcategory: 'jeans',
        brand: 'Levi\'s',
        colors: ['black'],
        size: '32',
        material: 'denim',
        price: 79.99,
        purchaseDate: DateTime.now().subtract(const Duration(days: 60)),
        tags: ['casual', 'formal'],
        notes: 'Goes with everything',
        images: [],
        isFavorite: false,
        wearCount: 10,
        lastWornDate: DateTime.now().subtract(const Duration(days: 1)),
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
      GarmentModel(
        id: 'garment_3',
        wardrobeId: 'wardrobe_2',
        name: 'Red Dress',
        category: 'dresses',
        subcategory: 'formal',
        brand: 'Zara',
        colors: ['red'],
        size: 'S',
        material: 'polyester',
        price: 89.99,
        purchaseDate: DateTime.now().subtract(const Duration(days: 10)),
        tags: ['formal', 'special'],
        notes: 'For special occasions',
        images: [],
        isFavorite: true,
        wearCount: 1,
        lastWornDate: DateTime.now().subtract(const Duration(days: 5)),
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
    ];
    
    testSettings = AppSettings(
      language: 'en',
      isOfflineMode: false,
      isDebugMode: false,
      analyticsEnabled: true,
      lastSyncTime: DateTime.now().subtract(const Duration(hours: 1)),
    );
  }
  
  void _initializeBlocs() {
    authBloc = AuthBloc(mockAuthRepository);
    wardrobeBloc = WardrobeBloc(mockWardrobeRepository);
    garmentBloc = GarmentBloc(mockGarmentRepository, mockImageRepository);
    appBloc = AppBloc(
      authBloc,
      wardrobeBloc,
      garmentBloc,
      mockConnectivityRepository,
      mockSyncRepository,
      mockSettingsRepository,
      mockSharedPreferences,
    );
  }
  
  void _setupDefaultMockBehaviors() {
    // Auth Repository
    when(mockAuthRepository.getCurrentUser()).thenAnswer(
      (_) async => Right(testUser),
    );
    when(mockAuthRepository.loginWithEmail(any, any)).thenAnswer(
      (_) async => Right(testUser),
    );
    when(mockAuthRepository.logout()).thenAnswer(
      (_) async => const Right(null),
    );
    
    // Wardrobe Repository
    when(mockWardrobeRepository.getWardrobes()).thenAnswer(
      (_) async => Right(testWardrobes),
    );
    when(mockWardrobeRepository.createWardrobe(any)).thenAnswer(
      (_) async => Right(testWardrobes.first),
    );
    when(mockWardrobeRepository.updateWardrobe(any)).thenAnswer(
      (_) async => Right(testWardrobes.first),
    );
    when(mockWardrobeRepository.deleteWardrobe(any)).thenAnswer(
      (_) async => const Right(null),
    );
    
    // Garment Repository
    when(mockGarmentRepository.getGarments()).thenAnswer(
      (_) async => Right(testGarments),
    );
    when(mockGarmentRepository.getGarmentsByWardrobe(any)).thenAnswer(
      (_) async => Right(testGarments.where((g) => g.wardrobeId == 'wardrobe_1').toList()),
    );
    when(mockGarmentRepository.createGarment(any)).thenAnswer(
      (_) async => Right(testGarments.first),
    );
    when(mockGarmentRepository.updateGarment(any)).thenAnswer(
      (_) async => Right(testGarments.first),
    );
    when(mockGarmentRepository.deleteGarment(any)).thenAnswer(
      (_) async => const Right(null),
    );
    
    // Image Repository
    when(mockImageRepository.uploadImage(any)).thenAnswer(
      (_) async => const Right('https://example.com/image.jpg'),
    );
    
    // Connectivity Repository
    when(mockConnectivityRepository.isConnected()).thenAnswer(
      (_) async => true,
    );
    when(mockConnectivityRepository.connectivityStream).thenAnswer(
      (_) => Stream.value(true),
    );
    
    // Sync Repository
    when(mockSyncRepository.syncAll()).thenAnswer(
      (_) async => const Right(null),
    );
    when(mockSyncRepository.scheduleBackgroundSync()).thenAnswer(
      (_) async => const Right(null),
    );
    when(mockSyncRepository.cancelBackgroundSync()).thenAnswer(
      (_) async => const Right(null),
    );
    
    // Settings Repository
    when(mockSettingsRepository.getSettings()).thenAnswer(
      (_) async => testSettings,
    );
    when(mockSettingsRepository.updateSettings(any)).thenAnswer(
      (_) async => const Right(null),
    );
    when(mockSettingsRepository.clearCache()).thenAnswer(
      (_) async => const Right(null),
    );
    when(mockSettingsRepository.clearAll()).thenAnswer(
      (_) async => const Right(null),
    );
    
    // Shared Preferences
    when(mockSharedPreferences.getBool(any)).thenReturn(false);
    when(mockSharedPreferences.setBool(any, any)).thenAnswer(
      (_) async => true,
    );
    when(mockSharedPreferences.clear()).thenAnswer(
      (_) async => true,
    );
  }
  
  // Helper methods for setting up specific test scenarios
  void setupAuthError() {
    when(mockAuthRepository.loginWithEmail(any, any)).thenAnswer(
      (_) async => Left(ServerFailure('Invalid credentials')),
    );
  }
  
  void setupNetworkError() {
    when(mockConnectivityRepository.isConnected()).thenAnswer(
      (_) async => false,
    );
    when(mockConnectivityRepository.connectivityStream).thenAnswer(
      (_) => Stream.value(false),
    );
  }
  
  void setupSyncError() {
    when(mockSyncRepository.syncAll()).thenAnswer(
      (_) async => Left(NetworkFailure('Sync failed')),
    );
  }
  
  void setupOfflineMode() {
    when(mockSettingsRepository.getSettings()).thenAnswer(
      (_) async => testSettings.copyWith(isOfflineMode: true),
    );
  }
  
  void setupFirstTimeUser() {
    when(mockSharedPreferences.getBool(any)).thenReturn(true);
  }
  
  void setupEmptyWardrobes() {
    when(mockWardrobeRepository.getWardrobes()).thenAnswer(
      (_) async => const Right([]),
    );
  }
  
  void setupEmptyGarments() {
    when(mockGarmentRepository.getGarments()).thenAnswer(
      (_) async => const Right([]),
    );
  }
  
  // Clean up resources
  void dispose() {
    authBloc.close();
    wardrobeBloc.close();
    garmentBloc.close();
    appBloc.close();
  }
}