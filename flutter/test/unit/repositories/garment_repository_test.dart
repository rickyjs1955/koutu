import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/data/repositories/garment_repository.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/core/error/exceptions.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late GarmentRepository repository;
  late MockApiClient mockApiClient;
  late MockAppDatabase mockDatabase;
  late MockNetworkInfo mockNetworkInfo;

  setUp(() {
    mockApiClient = MockApiClient();
    mockDatabase = MockAppDatabase();
    mockNetworkInfo = MockNetworkInfo();
    repository = GarmentRepository(
      apiClient: mockApiClient,
      database: mockDatabase,
      networkInfo: mockNetworkInfo,
    );
  });

  group('createGarment', () {
    final garmentModel = MockData.testGarmentModel;

    test('should create garment online when connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.createGarment(any))
          .thenAnswer((_) async => garmentModel);
      when(mockDatabase.insertGarment(any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.createGarment(
        wardrobeId: 'wardrobe123',
        name: 'Blue T-Shirt',
        category: 'Tops',
        imageId: 'image123',
      );

      // assert
      expect(result, Right(garmentModel.toDomain()));
      verify(mockApiClient.createGarment(any)).called(1);
      verify(mockDatabase.insertGarment(any)).called(1);
    });

    test('should create garment offline when not connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.insertGarment(any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.createGarment(
        wardrobeId: 'wardrobe123',
        name: 'Blue T-Shirt',
        category: 'Tops',
        imageId: 'image123',
      );

      // assert
      expect(result.isRight(), true);
      verifyNever(mockApiClient.createGarment(any));
      verify(mockDatabase.insertGarment(any)).called(1);
    });

    test('should return ServerFailure when API call fails', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.createGarment(any))
          .thenThrow(const ServerException('Server error'));

      // act
      final result = await repository.createGarment(
        wardrobeId: 'wardrobe123',
        name: 'Blue T-Shirt',
        category: 'Tops',
        imageId: 'image123',
      );

      // assert
      expect(result, const Left(ServerFailure('Server error')));
    });
  });

  group('getGarmentsByWardrobe', () {
    final garmentModels = MockData.testGarmentModelList;

    test('should get garments from API when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getGarmentsByWardrobe(any))
          .thenAnswer((_) async => garmentModels);
      when(mockDatabase.insertGarments(any)).thenAnswer((_) async => [1, 2]);

      // act
      final result = await repository.getGarmentsByWardrobe('wardrobe123');

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return garments'),
        (garments) => expect(garments.length, garmentModels.length),
      );
      verify(mockApiClient.getGarmentsByWardrobe('wardrobe123')).called(1);
    });

    test('should get garments from cache when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.getGarmentsByWardrobe(any))
          .thenAnswer((_) async => garmentModels);

      // act
      final result = await repository.getGarmentsByWardrobe('wardrobe123');

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return garments'),
        (garments) => expect(garments.length, garmentModels.length),
      );
      verifyNever(mockApiClient.getGarmentsByWardrobe(any));
      verify(mockDatabase.getGarmentsByWardrobe('wardrobe123')).called(1);
    });
  });

  group('updateGarment', () {
    final garmentModel = MockData.testGarmentModel;

    test('should update garment online when connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.updateGarment(any, any))
          .thenAnswer((_) async => garmentModel);
      when(mockDatabase.updateGarment(any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.updateGarment(
        'garment123',
        {
          'name': 'Updated T-Shirt',
          'tags': ['casual', 'summer'],
        },
      );

      // assert
      expect(result, Right(garmentModel.toDomain()));
      verify(mockApiClient.updateGarment('garment123', any)).called(1);
      verify(mockDatabase.updateGarment(any)).called(1);
    });

    test('should queue update when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.updateGarment(any)).thenAnswer((_) async => 1);
      when(mockDatabase.getGarmentById(any))
          .thenAnswer((_) async => garmentModel);

      // act
      final result = await repository.updateGarment(
        'garment123',
        {'name': 'Updated T-Shirt'},
      );

      // assert
      expect(result.isRight(), true);
      verifyNever(mockApiClient.updateGarment(any, any));
      verify(mockDatabase.updateGarment(any)).called(1);
    });
  });

  group('deleteGarment', () {
    test('should delete garment online when connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.deleteGarment(any)).thenAnswer((_) async => {});
      when(mockDatabase.deleteGarment(any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.deleteGarment('garment123');

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.deleteGarment('garment123')).called(1);
      verify(mockDatabase.deleteGarment('garment123')).called(1);
    });

    test('should mark as deleted when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.markGarmentAsDeleted(any))
          .thenAnswer((_) async => 1);

      // act
      final result = await repository.deleteGarment('garment123');

      // assert
      expect(result, const Right(null));
      verifyNever(mockApiClient.deleteGarment(any));
      verify(mockDatabase.markGarmentAsDeleted('garment123')).called(1);
    });
  });

  group('recordWear', () {
    test('should record wear online when connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.recordWear(any, any))
          .thenAnswer((_) async => {'wearCount': 6});
      when(mockDatabase.recordWear(any, any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.recordWear('garment123');

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.recordWear('garment123', any)).called(1);
      verify(mockDatabase.recordWear('garment123', any)).called(1);
    });

    test('should record wear locally when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.recordWear(any, any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.recordWear('garment123');

      // assert
      expect(result, const Right(null));
      verifyNever(mockApiClient.recordWear(any, any));
      verify(mockDatabase.recordWear('garment123', any)).called(1);
    });
  });

  group('searchGarments', () {
    final garmentModels = MockData.testGarmentModelList;

    test('should search garments from API when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.searchGarments(any))
          .thenAnswer((_) async => garmentModels);

      // act
      final result = await repository.searchGarments('blue');

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return garments'),
        (garments) => expect(garments.length, garmentModels.length),
      );
      verify(mockApiClient.searchGarments('blue')).called(1);
    });

    test('should search garments locally when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.searchGarments(any))
          .thenAnswer((_) async => garmentModels);

      // act
      final result = await repository.searchGarments('blue');

      // assert
      expect(result.isRight(), true);
      verifyNever(mockApiClient.searchGarments(any));
      verify(mockDatabase.searchGarments('blue')).called(1);
    });
  });

  group('getGarmentsByCategory', () {
    final garmentModels = MockData.testGarmentModelList
        .where((g) => g.category == 'Tops')
        .toList();

    test('should filter garments by category', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getGarmentsByCategory(any, any))
          .thenAnswer((_) async => garmentModels);

      // act
      final result = await repository.getGarmentsByCategory(
        'wardrobe123',
        'Tops',
      );

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return garments'),
        (garments) {
          expect(garments.length, garmentModels.length);
          expect(garments.every((g) => g.category == 'Tops'), true);
        },
      );
    });
  });

  group('bulkOperations', () {
    test('should delete multiple garments', () async {
      // arrange
      final ids = ['garment1', 'garment2', 'garment3'];
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.bulkDeleteGarments(any))
          .thenAnswer((_) async => {});
      when(mockDatabase.bulkDeleteGarments(any))
          .thenAnswer((_) async => ids.length);

      // act
      final result = await repository.bulkDeleteGarments(ids);

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.bulkDeleteGarments(ids)).called(1);
      verify(mockDatabase.bulkDeleteGarments(ids)).called(1);
    });

    test('should update multiple garments', () async {
      // arrange
      final ids = ['garment1', 'garment2'];
      final updates = {'tags': ['updated']};
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.bulkUpdateGarments(any, any))
          .thenAnswer((_) async => {});
      when(mockDatabase.bulkUpdateGarments(any, any))
          .thenAnswer((_) async => ids.length);

      // act
      final result = await repository.bulkUpdateGarments(ids, updates);

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.bulkUpdateGarments(ids, updates)).called(1);
      verify(mockDatabase.bulkUpdateGarments(ids, updates)).called(1);
    });
  });
}