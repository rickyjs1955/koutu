import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:dartz/dartz.dart';
import 'package:koutu/data/repositories/wardrobe_repository.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:koutu/core/error/exceptions.dart';
import 'package:dio/dio.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late WardrobeRepository repository;
  late MockApiClient mockApiClient;
  late MockAppDatabase mockDatabase;
  late MockNetworkInfo mockNetworkInfo;
  late MockCacheService mockCacheService;

  setUp(() {
    mockApiClient = MockApiClient();
    mockDatabase = MockAppDatabase();
    mockNetworkInfo = MockNetworkInfo();
    mockCacheService = MockCacheService();

    repository = WardrobeRepository(
      apiClient: mockApiClient,
      database: mockDatabase,
      networkInfo: mockNetworkInfo,
      cacheService: mockCacheService,
    );
  });

  group('getWardrobes', () {
    test('should return cached wardrobes when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.wardrobeDao.getAllWardrobes())
          .thenAnswer((_) async => MockData.testWardrobes);

      // act
      final result = await repository.getWardrobes();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobes) {
          expect(wardrobes, equals(MockData.testWardrobes));
        },
      );
      
      verifyNever(mockApiClient.getWardrobes());
    });

    test('should fetch from API and cache when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getWardrobes())
          .thenAnswer((_) async => MockData.testWardrobes);
      when(mockDatabase.wardrobeDao.insertWardrobes(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.getWardrobes();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobes) {
          expect(wardrobes, equals(MockData.testWardrobes));
        },
      );
      
      verify(mockApiClient.getWardrobes()).called(1);
      verify(mockDatabase.wardrobeDao.insertWardrobes(MockData.testWardrobes)).called(1);
    });

    test('should return cached data when API fails', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getWardrobes()).thenThrow(
        ServerException('Server error'),
      );
      when(mockDatabase.wardrobeDao.getAllWardrobes())
          .thenAnswer((_) async => MockData.testWardrobes);

      // act
      final result = await repository.getWardrobes();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobes) {
          expect(wardrobes, equals(MockData.testWardrobes));
        },
      );
    });

    test('should return CacheFailure when offline and no cached data', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.wardrobeDao.getAllWardrobes())
          .thenAnswer((_) async => []);

      // act
      final result = await repository.getWardrobes();

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<CacheFailure>());
        },
        (_) => fail('Should not return success'),
      );
    });
  });

  group('getWardrobe', () {
    final wardrobeId = MockData.testWardrobe.id;

    test('should return wardrobe when found in cache', () async {
      // arrange
      when(mockDatabase.wardrobeDao.getWardrobe(wardrobeId))
          .thenAnswer((_) async => MockData.testWardrobe);

      // act
      final result = await repository.getWardrobe(wardrobeId);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobe) {
          expect(wardrobe, equals(MockData.testWardrobe));
        },
      );
    });

    test('should fetch from API when not in cache and online', () async {
      // arrange
      when(mockDatabase.wardrobeDao.getWardrobe(wardrobeId))
          .thenAnswer((_) async => null);
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getWardrobe(wardrobeId))
          .thenAnswer((_) async => MockData.testWardrobe);
      when(mockDatabase.wardrobeDao.insertWardrobe(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.getWardrobe(wardrobeId);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobe) {
          expect(wardrobe, equals(MockData.testWardrobe));
        },
      );
      
      verify(mockApiClient.getWardrobe(wardrobeId)).called(1);
    });
  });

  group('createWardrobe', () {
    test('should create wardrobe successfully when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.createWardrobe(MockData.testWardrobe))
          .thenAnswer((_) async => MockData.testWardrobe);
      when(mockDatabase.wardrobeDao.insertWardrobe(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.createWardrobe(MockData.testWardrobe);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobe) {
          expect(wardrobe, equals(MockData.testWardrobe));
        },
      );
    });

    test('should queue for sync when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.wardrobeDao.insertWardrobe(any))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.syncQueueDao.addToQueue(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.createWardrobe(MockData.testWardrobe);

      // assert
      expect(result.isRight(), true);
      verify(mockDatabase.syncQueueDao.addToQueue(any)).called(1);
    });
  });

  group('updateWardrobe', () {
    test('should update wardrobe successfully when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.updateWardrobe(MockData.testWardrobe))
          .thenAnswer((_) async => MockData.testWardrobe);
      when(mockDatabase.wardrobeDao.updateWardrobe(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.updateWardrobe(MockData.testWardrobe);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (wardrobe) {
          expect(wardrobe, equals(MockData.testWardrobe));
        },
      );
    });

    test('should return ServerFailure when API update fails', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.updateWardrobe(MockData.testWardrobe)).thenThrow(
        DioException(
          requestOptions: RequestOptions(path: '/wardrobes'),
          type: DioExceptionType.badResponse,
          response: Response(
            requestOptions: RequestOptions(path: '/wardrobes'),
            statusCode: 400,
            data: {'error': 'Invalid data'},
          ),
        ),
      );

      // act
      final result = await repository.updateWardrobe(MockData.testWardrobe);

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<ServerFailure>());
        },
        (_) => fail('Should not return success'),
      );
    });
  });

  group('deleteWardrobe', () {
    final wardrobeId = MockData.testWardrobe.id;

    test('should delete wardrobe successfully when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.deleteWardrobe(wardrobeId))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.wardrobeDao.deleteWardrobe(wardrobeId))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.garmentDao.deleteGarmentsByWardrobe(wardrobeId))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.deleteWardrobe(wardrobeId);

      // assert
      expect(result.isRight(), true);
      verify(mockApiClient.deleteWardrobe(wardrobeId)).called(1);
      verify(mockDatabase.wardrobeDao.deleteWardrobe(wardrobeId)).called(1);
      verify(mockDatabase.garmentDao.deleteGarmentsByWardrobe(wardrobeId)).called(1);
    });

    test('should queue for deletion when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.wardrobeDao.deleteWardrobe(wardrobeId))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.garmentDao.deleteGarmentsByWardrobe(wardrobeId))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.syncQueueDao.addToQueue(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.deleteWardrobe(wardrobeId);

      // assert
      expect(result.isRight(), true);
      verify(mockDatabase.syncQueueDao.addToQueue(any)).called(1);
      verifyNever(mockApiClient.deleteWardrobe(any));
    });
  });

  group('shareWardrobe', () {
    final wardrobeId = MockData.testWardrobe.id;
    const email = 'friend@example.com';

    test('should share wardrobe successfully', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.shareWardrobe(wardrobeId, email))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.shareWardrobe(wardrobeId, email);

      // assert
      expect(result.isRight(), true);
      verify(mockApiClient.shareWardrobe(wardrobeId, email)).called(1);
    });

    test('should return NetworkFailure when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);

      // act
      final result = await repository.shareWardrobe(wardrobeId, email);

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<NetworkFailure>());
        },
        (_) => fail('Should not return success'),
      );
    });
  });
}