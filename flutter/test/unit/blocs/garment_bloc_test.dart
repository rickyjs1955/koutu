import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late GarmentBloc garmentBloc;
  late MockIGarmentRepository mockGarmentRepository;

  setUp(() {
    mockGarmentRepository = MockIGarmentRepository();
    garmentBloc = GarmentBloc(
      garmentRepository: mockGarmentRepository,
    );
  });

  tearDown(() {
    garmentBloc.close();
  });

  group('GarmentBloc', () {
    test('initial state should be GarmentState.initial', () {
      expect(garmentBloc.state, const GarmentState.initial());
    });

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when LoadGarments succeeds',
      build: () {
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const LoadGarments(wardrobeId: 'wardrobe123')),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, error] when LoadGarments fails',
      build: () {
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => const Left(ServerFailure('Failed to load garments')));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const LoadGarments(wardrobeId: 'wardrobe123')),
      expect: () => [
        const GarmentState.loading(),
        const GarmentState.error('Failed to load garments'),
      ],
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when CreateGarment succeeds',
      build: () {
        when(mockGarmentRepository.createGarment(
          wardrobeId: anyNamed('wardrobeId'),
          name: anyNamed('name'),
          category: anyNamed('category'),
          imageId: anyNamed('imageId'),
          brand: anyNamed('brand'),
          color: anyNamed('color'),
          size: anyNamed('size'),
          price: anyNamed('price'),
          tags: anyNamed('tags'),
        )).thenAnswer((_) async => Right(MockData.testGarment));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const CreateGarment(
        wardrobeId: 'wardrobe123',
        name: 'Blue T-Shirt',
        category: 'Tops',
        imageId: 'image123',
        brand: 'Nike',
        color: 'blue',
        size: 'M',
        price: 29.99,
        tags: ['casual', 'summer'],
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.createGarment(
          wardrobeId: 'wardrobe123',
          name: 'Blue T-Shirt',
          category: 'Tops',
          imageId: 'image123',
          brand: 'Nike',
          color: 'blue',
          size: 'M',
          price: 29.99,
          tags: ['casual', 'summer'],
        )).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, error] when CreateGarment fails',
      build: () {
        when(mockGarmentRepository.createGarment(
          wardrobeId: anyNamed('wardrobeId'),
          name: anyNamed('name'),
          category: anyNamed('category'),
          imageId: anyNamed('imageId'),
          brand: anyNamed('brand'),
          color: anyNamed('color'),
          size: anyNamed('size'),
          price: anyNamed('price'),
          tags: anyNamed('tags'),
        )).thenAnswer((_) async => const Left(ServerFailure('Failed to create garment')));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const CreateGarment(
        wardrobeId: 'wardrobe123',
        name: 'Blue T-Shirt',
        category: 'Tops',
        imageId: 'image123',
      )),
      expect: () => [
        const GarmentState.loading(),
        const GarmentState.error('Failed to create garment'),
      ],
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when UpdateGarment succeeds',
      build: () {
        when(mockGarmentRepository.updateGarment(any, any))
            .thenAnswer((_) async => Right(MockData.testGarment));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const UpdateGarment(
        garmentId: 'garment123',
        wardrobeId: 'wardrobe123',
        updates: {'name': 'Updated T-Shirt'},
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.updateGarment(
          'garment123',
          {'name': 'Updated T-Shirt'},
        )).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when DeleteGarment succeeds',
      build: () {
        when(mockGarmentRepository.deleteGarment(any))
            .thenAnswer((_) async => const Right(null));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const DeleteGarment(
        garmentId: 'garment123',
        wardrobeId: 'wardrobe123',
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.deleteGarment('garment123')).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when RecordWear succeeds',
      build: () {
        when(mockGarmentRepository.recordWear(any))
            .thenAnswer((_) async => const Right(null));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const RecordWear(
        garmentId: 'garment123',
        wardrobeId: 'wardrobe123',
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.recordWear('garment123')).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when SearchGarments succeeds',
      build: () {
        when(mockGarmentRepository.searchGarments(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const SearchGarments(query: 'blue')),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.searchGarments('blue')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when FilterGarments succeeds',
      build: () {
        when(mockGarmentRepository.getGarmentsByCategory(any, any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const FilterGarments(
        wardrobeId: 'wardrobe123',
        category: 'Tops',
        color: 'blue',
        size: 'M',
        tags: ['casual'],
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.getGarmentsByCategory('wardrobe123', 'Tops')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when BulkDeleteGarments succeeds',
      build: () {
        when(mockGarmentRepository.bulkDeleteGarments(any))
            .thenAnswer((_) async => const Right(null));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const BulkDeleteGarments(
        garmentIds: ['garment1', 'garment2'],
        wardrobeId: 'wardrobe123',
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.bulkDeleteGarments(['garment1', 'garment2'])).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when BulkUpdateGarments succeeds',
      build: () {
        when(mockGarmentRepository.bulkUpdateGarments(any, any))
            .thenAnswer((_) async => const Right(null));
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const BulkUpdateGarments(
        garmentIds: ['garment1', 'garment2'],
        wardrobeId: 'wardrobe123',
        updates: {'tags': ['updated']},
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.bulkUpdateGarments(
          ['garment1', 'garment2'],
          {'tags': ['updated']},
        )).called(1);
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when LoadGarmentDetail succeeds',
      build: () {
        when(mockGarmentRepository.getGarmentDetail(any))
            .thenAnswer((_) async => Right(MockData.testGarment));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const LoadGarmentDetail(garmentId: 'garment123')),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.detail(MockData.testGarment),
      ],
      verify: (_) {
        verify(mockGarmentRepository.getGarmentDetail('garment123')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, error] when LoadGarmentDetail fails',
      build: () {
        when(mockGarmentRepository.getGarmentDetail(any))
            .thenAnswer((_) async => const Left(ServerFailure('Garment not found')));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const LoadGarmentDetail(garmentId: 'garment123')),
      expect: () => [
        const GarmentState.loading(),
        const GarmentState.error('Garment not found'),
      ],
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when LoadGarmentsByCategory succeeds',
      build: () {
        when(mockGarmentRepository.getGarmentsByCategory(any, any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      act: (bloc) => bloc.add(const LoadGarmentsByCategory(
        wardrobeId: 'wardrobe123',
        category: 'Tops',
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.getGarmentsByCategory('wardrobe123', 'Tops')).called(1);
      },
    );

    blocTest<GarmentBloc, GarmentState>(
      'should emit [loading, loaded] when SortGarments succeeds',
      build: () {
        when(mockGarmentRepository.getGarmentsByWardrobe(any))
            .thenAnswer((_) async => Right(MockData.testGarmentList));
        return garmentBloc;
      },
      seed: () => GarmentState.loaded(MockData.testGarmentList),
      act: (bloc) => bloc.add(const SortGarments(
        wardrobeId: 'wardrobe123',
        sortBy: 'name',
        ascending: true,
      )),
      expect: () => [
        const GarmentState.loading(),
        GarmentState.loaded(MockData.testGarmentList),
      ],
      verify: (_) {
        verify(mockGarmentRepository.getGarmentsByWardrobe('wardrobe123')).called(1);
      },
    );
  });
}