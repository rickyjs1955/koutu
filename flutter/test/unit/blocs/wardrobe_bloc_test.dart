import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late WardrobeBloc wardrobeBloc;
  late MockIWardrobeRepository mockWardrobeRepository;

  setUp(() {
    mockWardrobeRepository = MockIWardrobeRepository();
    wardrobeBloc = WardrobeBloc(
      wardrobeRepository: mockWardrobeRepository,
    );
  });

  tearDown(() {
    wardrobeBloc.close();
  });

  group('WardrobeBloc', () {
    test('initial state should be WardrobeState.initial', () {
      expect(wardrobeBloc.state, const WardrobeState.initial());
    });

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when LoadWardrobes succeeds',
      build: () {
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const LoadWardrobes()),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, error] when LoadWardrobes fails',
      build: () {
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => const Left(ServerFailure('Failed to load wardrobes')));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const LoadWardrobes()),
      expect: () => [
        const WardrobeState.loading(),
        const WardrobeState.error('Failed to load wardrobes'),
      ],
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when CreateWardrobe succeeds',
      build: () {
        when(mockWardrobeRepository.createWardrobe(
          name: anyNamed('name'),
          description: anyNamed('description'),
          colorTheme: anyNamed('colorTheme'),
          icon: anyNamed('icon'),
        )).thenAnswer((_) async => Right(MockData.testWardrobe));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const CreateWardrobe(
        name: 'Summer Collection',
        description: 'My summer wardrobe',
        colorTheme: 'blue',
        icon: 'wardrobe',
      )),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.createWardrobe(
          name: 'Summer Collection',
          description: 'My summer wardrobe',
          colorTheme: 'blue',
          icon: 'wardrobe',
        )).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, error] when CreateWardrobe fails',
      build: () {
        when(mockWardrobeRepository.createWardrobe(
          name: anyNamed('name'),
          description: anyNamed('description'),
          colorTheme: anyNamed('colorTheme'),
          icon: anyNamed('icon'),
        )).thenAnswer((_) async => const Left(ServerFailure('Failed to create wardrobe')));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const CreateWardrobe(
        name: 'Summer Collection',
        description: 'My summer wardrobe',
        colorTheme: 'blue',
        icon: 'wardrobe',
      )),
      expect: () => [
        const WardrobeState.loading(),
        const WardrobeState.error('Failed to create wardrobe'),
      ],
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when UpdateWardrobe succeeds',
      build: () {
        when(mockWardrobeRepository.updateWardrobe(any, any))
            .thenAnswer((_) async => Right(MockData.testWardrobe));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const UpdateWardrobe(
        wardrobeId: 'wardrobe123',
        updates: {'name': 'Updated Wardrobe'},
      )),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.updateWardrobe(
          'wardrobe123',
          {'name': 'Updated Wardrobe'},
        )).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when DeleteWardrobe succeeds',
      build: () {
        when(mockWardrobeRepository.deleteWardrobe(any))
            .thenAnswer((_) async => const Right(null));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const DeleteWardrobe(wardrobeId: 'wardrobe123')),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.deleteWardrobe('wardrobe123')).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when ShareWardrobe succeeds',
      build: () {
        when(mockWardrobeRepository.shareWardrobe(any, any))
            .thenAnswer((_) async => const Right(null));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const ShareWardrobe(
        wardrobeId: 'wardrobe123',
        email: 'friend@example.com',
      )),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.shareWardrobe(
          'wardrobe123',
          'friend@example.com',
        )).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, error] when ShareWardrobe fails',
      build: () {
        when(mockWardrobeRepository.shareWardrobe(any, any))
            .thenAnswer((_) async => const Left(ServerFailure('Failed to share wardrobe')));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const ShareWardrobe(
        wardrobeId: 'wardrobe123',
        email: 'friend@example.com',
      )),
      expect: () => [
        const WardrobeState.loading(),
        const WardrobeState.error('Failed to share wardrobe'),
      ],
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when SetDefaultWardrobe succeeds',
      build: () {
        when(mockWardrobeRepository.setDefaultWardrobe(any))
            .thenAnswer((_) async => const Right(null));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const SetDefaultWardrobe(wardrobeId: 'wardrobe123')),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.setDefaultWardrobe('wardrobe123')).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when LoadSharedWardrobes succeeds',
      build: () {
        when(mockWardrobeRepository.getSharedWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const LoadSharedWardrobes()),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.sharedLoaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.getSharedWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when AcceptWardrobeInvite succeeds',
      build: () {
        when(mockWardrobeRepository.acceptWardrobeInvite(any))
            .thenAnswer((_) async => const Right(null));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const AcceptWardrobeInvite(inviteId: 'invite123')),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.acceptWardrobeInvite('invite123')).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when RejectWardrobeInvite succeeds',
      build: () {
        when(mockWardrobeRepository.rejectWardrobeInvite(any))
            .thenAnswer((_) async => const Right(null));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      act: (bloc) => bloc.add(const RejectWardrobeInvite(inviteId: 'invite123')),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.loaded(MockData.testWardrobeList),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.rejectWardrobeInvite('invite123')).called(1);
        verify(mockWardrobeRepository.getWardrobes()).called(1);
      },
    );

    blocTest<WardrobeBloc, WardrobeState>(
      'should emit [loading, loaded] when GenerateShareLink succeeds',
      build: () {
        when(mockWardrobeRepository.generateShareLink(any))
            .thenAnswer((_) async => const Right('https://example.com/share/wardrobe123'));
        when(mockWardrobeRepository.getWardrobes())
            .thenAnswer((_) async => Right(MockData.testWardrobeList));
        return wardrobeBloc;
      },
      seed: () => WardrobeState.loaded(MockData.testWardrobeList),
      act: (bloc) => bloc.add(const GenerateShareLink(wardrobeId: 'wardrobe123')),
      expect: () => [
        const WardrobeState.loading(),
        WardrobeState.shareLink('https://example.com/share/wardrobe123'),
      ],
      verify: (_) {
        verify(mockWardrobeRepository.generateShareLink('wardrobe123')).called(1);
      },
    );
  });
}