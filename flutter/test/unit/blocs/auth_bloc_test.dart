import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:dartz/dartz.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late AuthBloc authBloc;
  late MockIAuthRepository mockAuthRepository;
  late MockSecureStorageService mockSecureStorageService;

  setUp(() {
    mockAuthRepository = MockIAuthRepository();
    mockSecureStorageService = MockSecureStorageService();
    authBloc = AuthBloc(
      authRepository: mockAuthRepository,
      secureStorageService: mockSecureStorageService,
    );
  });

  tearDown(() {
    authBloc.close();
  });

  group('AuthBloc', () {
    test('initial state should be AuthState.initial', () {
      expect(authBloc.state, const AuthState.initial());
    });

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, authenticated] when Login succeeds',
      build: () {
        when(mockAuthRepository.login(any, any))
            .thenAnswer((_) async => Right(MockData.testAuthResponse));
        return authBloc;
      },
      act: (bloc) => bloc.add(const Login(
        email: 'test@example.com',
        password: 'password123',
      )),
      expect: () => [
        const AuthState.loading(),
        AuthState.authenticated(MockData.testUser),
      ],
      verify: (_) {
        verify(mockAuthRepository.login('test@example.com', 'password123'))
            .called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, error] when Login fails',
      build: () {
        when(mockAuthRepository.login(any, any))
            .thenAnswer((_) async => const Left(ServerFailure('Invalid credentials')));
        return authBloc;
      },
      act: (bloc) => bloc.add(const Login(
        email: 'test@example.com',
        password: 'wrongpassword',
      )),
      expect: () => [
        const AuthState.loading(),
        const AuthState.error('Invalid credentials'),
      ],
      verify: (_) {
        verify(mockAuthRepository.login('test@example.com', 'wrongpassword'))
            .called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, authenticated] when Register succeeds',
      build: () {
        when(mockAuthRepository.register(any, any, any))
            .thenAnswer((_) async => Right(MockData.testAuthResponse));
        return authBloc;
      },
      act: (bloc) => bloc.add(const Register(
        email: 'test@example.com',
        password: 'password123',
        fullName: 'Test User',
      )),
      expect: () => [
        const AuthState.loading(),
        AuthState.authenticated(MockData.testUser),
      ],
      verify: (_) {
        verify(mockAuthRepository.register(
          'test@example.com',
          'password123',
          'Test User',
        )).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, error] when Register fails',
      build: () {
        when(mockAuthRepository.register(any, any, any))
            .thenAnswer((_) async => const Left(ServerFailure('Email already exists')));
        return authBloc;
      },
      act: (bloc) => bloc.add(const Register(
        email: 'existing@example.com',
        password: 'password123',
        fullName: 'Test User',
      )),
      expect: () => [
        const AuthState.loading(),
        const AuthState.error('Email already exists'),
      ],
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, initial] when ForgotPassword succeeds',
      build: () {
        when(mockAuthRepository.forgotPassword(any))
            .thenAnswer((_) async => const Right(null));
        return authBloc;
      },
      act: (bloc) => bloc.add(const ForgotPassword(
        email: 'test@example.com',
      )),
      expect: () => [
        const AuthState.loading(),
        const AuthState.initial(),
      ],
      verify: (_) {
        verify(mockAuthRepository.forgotPassword('test@example.com'))
            .called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, error] when ForgotPassword fails',
      build: () {
        when(mockAuthRepository.forgotPassword(any))
            .thenAnswer((_) async => const Left(ServerFailure('User not found')));
        return authBloc;
      },
      act: (bloc) => bloc.add(const ForgotPassword(
        email: 'nonexistent@example.com',
      )),
      expect: () => [
        const AuthState.loading(),
        const AuthState.error('User not found'),
      ],
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, initial] when Logout succeeds',
      build: () {
        when(mockAuthRepository.logout())
            .thenAnswer((_) async => const Right(null));
        when(mockSecureStorageService.deleteToken())
            .thenAnswer((_) async => {});
        return authBloc;
      },
      seed: () => AuthState.authenticated(MockData.testUser),
      act: (bloc) => bloc.add(const Logout()),
      expect: () => [
        const AuthState.loading(),
        const AuthState.initial(),
      ],
      verify: (_) {
        verify(mockAuthRepository.logout()).called(1);
        verify(mockSecureStorageService.deleteToken()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [authenticated] when CheckAuthStatus finds valid token',
      build: () {
        when(mockSecureStorageService.getToken())
            .thenAnswer((_) async => 'valid_token');
        when(mockAuthRepository.verifyToken(any))
            .thenAnswer((_) async => Right(MockData.testUser));
        return authBloc;
      },
      act: (bloc) => bloc.add(const CheckAuthStatus()),
      expect: () => [
        AuthState.authenticated(MockData.testUser),
      ],
      verify: (_) {
        verify(mockSecureStorageService.getToken()).called(1);
        verify(mockAuthRepository.verifyToken('valid_token')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [initial] when CheckAuthStatus finds no token',
      build: () {
        when(mockSecureStorageService.getToken())
            .thenAnswer((_) async => null);
        return authBloc;
      },
      act: (bloc) => bloc.add(const CheckAuthStatus()),
      expect: () => [
        const AuthState.initial(),
      ],
      verify: (_) {
        verify(mockSecureStorageService.getToken()).called(1);
        verifyNever(mockAuthRepository.verifyToken(any));
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [initial] when CheckAuthStatus finds invalid token',
      build: () {
        when(mockSecureStorageService.getToken())
            .thenAnswer((_) async => 'invalid_token');
        when(mockAuthRepository.verifyToken(any))
            .thenAnswer((_) async => const Left(ServerFailure('Invalid token')));
        when(mockSecureStorageService.deleteToken())
            .thenAnswer((_) async => {});
        return authBloc;
      },
      act: (bloc) => bloc.add(const CheckAuthStatus()),
      expect: () => [
        const AuthState.initial(),
      ],
      verify: (_) {
        verify(mockSecureStorageService.getToken()).called(1);
        verify(mockAuthRepository.verifyToken('invalid_token')).called(1);
        verify(mockSecureStorageService.deleteToken()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, authenticated] when RefreshToken succeeds',
      build: () {
        when(mockAuthRepository.refreshToken())
            .thenAnswer((_) async => Right(MockData.testAuthResponse));
        return authBloc;
      },
      seed: () => AuthState.authenticated(MockData.testUser),
      act: (bloc) => bloc.add(const RefreshToken()),
      expect: () => [
        const AuthState.loading(),
        AuthState.authenticated(MockData.testUser),
      ],
      verify: (_) {
        verify(mockAuthRepository.refreshToken()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, initial] when RefreshToken fails',
      build: () {
        when(mockAuthRepository.refreshToken())
            .thenAnswer((_) async => const Left(ServerFailure('Refresh token expired')));
        when(mockSecureStorageService.deleteToken())
            .thenAnswer((_) async => {});
        return authBloc;
      },
      seed: () => AuthState.authenticated(MockData.testUser),
      act: (bloc) => bloc.add(const RefreshToken()),
      expect: () => [
        const AuthState.loading(),
        const AuthState.initial(),
      ],
      verify: (_) {
        verify(mockAuthRepository.refreshToken()).called(1);
        verify(mockSecureStorageService.deleteToken()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, authenticated] when UpdateProfile succeeds',
      build: () {
        final updatedUser = MockData.testUser.copyWith(fullName: 'Updated Name');
        when(mockAuthRepository.updateProfile(any))
            .thenAnswer((_) async => Right(updatedUser));
        return authBloc;
      },
      seed: () => AuthState.authenticated(MockData.testUser),
      act: (bloc) => bloc.add(const UpdateProfile({
        'fullName': 'Updated Name',
      })),
      expect: () => [
        const AuthState.loading(),
        AuthState.authenticated(MockData.testUser.copyWith(fullName: 'Updated Name')),
      ],
      verify: (_) {
        verify(mockAuthRepository.updateProfile({
          'fullName': 'Updated Name',
        })).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'should emit [loading, error] when UpdateProfile fails',
      build: () {
        when(mockAuthRepository.updateProfile(any))
            .thenAnswer((_) async => const Left(ServerFailure('Update failed')));
        return authBloc;
      },
      seed: () => AuthState.authenticated(MockData.testUser),
      act: (bloc) => bloc.add(const UpdateProfile({
        'fullName': 'Updated Name',
      })),
      expect: () => [
        const AuthState.loading(),
        const AuthState.error('Update failed'),
      ],
    );
  });
}