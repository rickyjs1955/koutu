import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/data/repositories/image_repository.dart';
import 'package:koutu/data/models/image/image_model.dart';
import 'package:koutu/core/error/exceptions.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';
import 'dart:io';
import 'dart:typed_data';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late ImageRepository repository;
  late MockApiClient mockApiClient;
  late MockAppDatabase mockDatabase;
  late MockNetworkInfo mockNetworkInfo;
  late MockImageUploadService mockImageUploadService;
  late MockImageProcessingService mockImageProcessingService;

  setUp(() {
    mockApiClient = MockApiClient();
    mockDatabase = MockAppDatabase();
    mockNetworkInfo = MockNetworkInfo();
    mockImageUploadService = MockImageUploadService();
    mockImageProcessingService = MockImageProcessingService();
    
    repository = ImageRepository(
      apiClient: mockApiClient,
      database: mockDatabase,
      networkInfo: mockNetworkInfo,
      imageUploadService: mockImageUploadService,
      imageProcessingService: mockImageProcessingService,
    );
  });

  group('uploadImage', () {
    final imageModel = MockData.testImageModel;
    final mockFile = File('test.jpg');
    final processedData = Uint8List.fromList([1, 2, 3, 4]);

    test('should upload image successfully when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockImageProcessingService.processImage(any))
          .thenAnswer((_) async => processedData);
      when(mockImageUploadService.uploadImage(any, any))
          .thenAnswer((_) async => 'https://example.com/image.jpg');
      when(mockApiClient.createImage(any))
          .thenAnswer((_) async => imageModel);
      when(mockDatabase.insertImage(any)).thenAnswer((_) async => 1);

      // act
      final result = await repository.uploadImage(
        mockFile,
        'garment123',
        ImageType.garment,
      );

      // assert
      expect(result, Right(imageModel.toDomain()));
      verify(mockImageProcessingService.processImage(mockFile)).called(1);
      verify(mockImageUploadService.uploadImage(processedData, any)).called(1);
      verify(mockApiClient.createImage(any)).called(1);
      verify(mockDatabase.insertImage(any)).called(1);
    });

    test('should queue upload when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockImageProcessingService.processImage(any))
          .thenAnswer((_) async => processedData);
      when(mockDatabase.insertImage(any)).thenAnswer((_) async => 1);
      when(mockDatabase.queueImageUpload(any, any))
          .thenAnswer((_) async => 1);

      // act
      final result = await repository.uploadImage(
        mockFile,
        'garment123',
        ImageType.garment,
      );

      // assert
      expect(result.isRight(), true);
      verify(mockImageProcessingService.processImage(mockFile)).called(1);
      verify(mockDatabase.insertImage(any)).called(1);
      verify(mockDatabase.queueImageUpload(any, any)).called(1);
      verifyNever(mockImageUploadService.uploadImage(any, any));
      verifyNever(mockApiClient.createImage(any));
    });

    test('should return failure when processing fails', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockImageProcessingService.processImage(any))
          .thenThrow(Exception('Processing failed'));

      // act
      final result = await repository.uploadImage(
        mockFile,
        'garment123',
        ImageType.garment,
      );

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) => expect(failure, isA<ProcessingFailure>()),
        (_) => fail('Should return failure'),
      );
    });
  });

  group('getImagesByEntity', () {
    final imageModels = MockData.testImageModelList;

    test('should get images from API when online', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getImagesByEntity(any, any))
          .thenAnswer((_) async => imageModels);
      when(mockDatabase.insertImages(any)).thenAnswer((_) async => [1, 2]);

      // act
      final result = await repository.getImagesByEntity(
        'garment123',
        ImageType.garment,
      );

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return images'),
        (images) => expect(images.length, imageModels.length),
      );
      verify(mockApiClient.getImagesByEntity('garment123', 'garment')).called(1);
    });

    test('should get images from cache when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.getImagesByEntity(any, any))
          .thenAnswer((_) async => imageModels);

      // act
      final result = await repository.getImagesByEntity(
        'garment123',
        ImageType.garment,
      );

      // assert
      expect(result.isRight(), true);
      verifyNever(mockApiClient.getImagesByEntity(any, any));
      verify(mockDatabase.getImagesByEntity('garment123', 'garment')).called(1);
    });
  });

  group('deleteImage', () {
    test('should delete image online when connected', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.deleteImage(any)).thenAnswer((_) async => {});
      when(mockDatabase.deleteImage(any)).thenAnswer((_) async => 1);
      when(mockImageUploadService.deleteImage(any))
          .thenAnswer((_) async => {});

      // act
      final result = await repository.deleteImage('image123');

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.deleteImage('image123')).called(1);
      verify(mockDatabase.deleteImage('image123')).called(1);
      verify(mockImageUploadService.deleteImage(any)).called(1);
    });

    test('should queue deletion when offline', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);
      when(mockDatabase.markImageAsDeleted(any))
          .thenAnswer((_) async => 1);
      when(mockDatabase.queueImageDeletion(any))
          .thenAnswer((_) async => 1);

      // act
      final result = await repository.deleteImage('image123');

      // assert
      expect(result, const Right(null));
      verifyNever(mockApiClient.deleteImage(any));
      verify(mockDatabase.markImageAsDeleted('image123')).called(1);
      verify(mockDatabase.queueImageDeletion('image123')).called(1);
    });
  });

  group('setPrimaryImage', () {
    test('should set primary image successfully', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.setPrimaryImage(any, any))
          .thenAnswer((_) async => {});
      when(mockDatabase.setPrimaryImage(any, any))
          .thenAnswer((_) async => 1);

      // act
      final result = await repository.setPrimaryImage(
        'garment123',
        'image123',
      );

      // assert
      expect(result, const Right(null));
      verify(mockApiClient.setPrimaryImage('garment123', 'image123')).called(1);
      verify(mockDatabase.setPrimaryImage('garment123', 'image123')).called(1);
    });
  });

  group('processImages', () {
    test('should remove background from image', () async {
      // arrange
      final mockFile = File('test.jpg');
      final processedData = Uint8List.fromList([5, 6, 7, 8]);
      
      when(mockImageProcessingService.removeBackground(any))
          .thenAnswer((_) async => processedData);

      // act
      final result = await repository.removeBackground(mockFile);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return processed data'),
        (data) => expect(data, processedData),
      );
      verify(mockImageProcessingService.removeBackground(mockFile)).called(1);
    });

    test('should extract colors from image', () async {
      // arrange
      final mockFile = File('test.jpg');
      final colors = ['#FF0000', '#00FF00', '#0000FF'];
      
      when(mockImageProcessingService.extractColors(any))
          .thenAnswer((_) async => colors);

      // act
      final result = await repository.extractColors(mockFile);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (l) => fail('Should return colors'),
        (extractedColors) => expect(extractedColors, colors),
      );
      verify(mockImageProcessingService.extractColors(mockFile)).called(1);
    });
  });

  group('syncPendingImages', () {
    test('should sync pending uploads when online', () async {
      // arrange
      final pendingUploads = [
        {'id': 'img1', 'path': 'path1.jpg', 'entityId': 'garment1'},
        {'id': 'img2', 'path': 'path2.jpg', 'entityId': 'garment2'},
      ];
      
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockDatabase.getPendingImageUploads())
          .thenAnswer((_) async => pendingUploads);
      when(mockImageUploadService.uploadImage(any, any))
          .thenAnswer((_) async => 'https://example.com/uploaded.jpg');
      when(mockApiClient.createImage(any))
          .thenAnswer((_) async => MockData.testImageModel);
      when(mockDatabase.updateImageUrl(any, any))
          .thenAnswer((_) async => 1);
      when(mockDatabase.removePendingImageUpload(any))
          .thenAnswer((_) async => 1);

      // act
      await repository.syncPendingImages();

      // assert
      verify(mockDatabase.getPendingImageUploads()).called(1);
      verify(mockImageUploadService.uploadImage(any, any))
          .called(pendingUploads.length);
      verify(mockDatabase.removePendingImageUpload(any))
          .called(pendingUploads.length);
    });

    test('should sync pending deletions when online', () async {
      // arrange
      final pendingDeletions = ['img1', 'img2', 'img3'];
      
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockDatabase.getPendingImageDeletions())
          .thenAnswer((_) async => pendingDeletions);
      when(mockApiClient.deleteImage(any)).thenAnswer((_) async => {});
      when(mockImageUploadService.deleteImage(any))
          .thenAnswer((_) async => {});
      when(mockDatabase.removePendingImageDeletion(any))
          .thenAnswer((_) async => 1);

      // act
      await repository.syncPendingImages();

      // assert
      verify(mockDatabase.getPendingImageDeletions()).called(1);
      verify(mockApiClient.deleteImage(any))
          .called(pendingDeletions.length);
      verify(mockDatabase.removePendingImageDeletion(any))
          .called(pendingDeletions.length);
    });
  });
}