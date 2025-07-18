import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:dartz/dartz.dart';
import 'package:koutu/data/repositories/auth_repository.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:koutu/core/error/exceptions.dart';
import 'package:koutu/data/models/auth/auth_request_model.dart';
import 'package:dio/dio.dart';

import '../../test_helpers/test_helpers.mocks.dart';
import '../../test_helpers/mock_data.dart';

void main() {
  late AuthRepository repository;
  late MockApiClient mockApiClient;
  late MockAppDatabase mockDatabase;
  late MockSecureStorageService mockSecureStorage;
  late MockNetworkInfo mockNetworkInfo;

  setUp(() {
    mockApiClient = MockApiClient();
    mockDatabase = MockAppDatabase();
    mockSecureStorage = MockSecureStorageService();
    mockNetworkInfo = MockNetworkInfo();

    repository = AuthRepository(
      apiClient: mockApiClient,
      database: mockDatabase,
      secureStorage: mockSecureStorage,
      networkInfo: mockNetworkInfo,
    );
  });

  group('login', () {
    final loginRequest = LoginRequest(
      email: 'test@example.com',
      password: 'password123',
    );

    test('should return AuthResponse when login is successful', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.login(loginRequest))
          .thenAnswer((_) async => MockData.testAuthResponse);
      when(mockSecureStorage.saveTokens(any, any))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.userDao.insertUser(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.login(loginRequest);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (response) {
          expect(response, equals(MockData.testAuthResponse));
        },
      );
      
      verify(mockApiClient.login(loginRequest)).called(1);
      verify(mockSecureStorage.saveTokens(
        MockData.testAuthResponse.accessToken,
        MockData.testAuthResponse.refreshToken,
      )).called(1);
    });

    test('should return NetworkFailure when there is no internet connection', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);

      // act
      final result = await repository.login(loginRequest);

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<NetworkFailure>());
        },
        (_) => fail('Should not return success'),
      );
      
      verifyNever(mockApiClient.login(any));
    });

    test('should return ServerFailure when API throws ServerException', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.login(loginRequest))
          .thenThrow(ServerException('Invalid credentials'));

      // act
      final result = await repository.login(loginRequest);

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<ServerFailure>());
          expect((failure as ServerFailure).message, 'Invalid credentials');
        },
        (_) => fail('Should not return success'),
      );
    });

    test('should return ServerFailure when DioError occurs', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.login(loginRequest)).thenThrow(
        DioException(
          requestOptions: RequestOptions(path: '/auth/login'),
          type: DioExceptionType.connectionTimeout,
        ),
      );

      // act
      final result = await repository.login(loginRequest);

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

  group('register', () {
    final registerRequest = RegisterRequest(
      email: 'test@example.com',
      password: 'password123',
      username: 'testuser',
      fullName: 'Test User',
    );

    test('should return AuthResponse when registration is successful', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.register(registerRequest))
          .thenAnswer((_) async => MockData.testAuthResponse);
      when(mockSecureStorage.saveTokens(any, any))
          .thenAnswer((_) async => Future.value());
      when(mockDatabase.userDao.insertUser(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.register(registerRequest);

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (response) {
          expect(response, equals(MockData.testAuthResponse));
        },
      );
    });
  });

  group('logout', () {
    test('should clear all stored data when logout is successful', () async {
      // arrange
      when(mockApiClient.logout()).thenAnswer((_) async => Future.value());
      when(mockSecureStorage.clearTokens()).thenAnswer((_) async => Future.value());
      when(mockDatabase.clearAllData()).thenAnswer((_) async => Future.value());

      // act
      final result = await repository.logout();

      // assert
      expect(result.isRight(), true);
      verify(mockApiClient.logout()).called(1);
      verify(mockSecureStorage.clearTokens()).called(1);
      verify(mockDatabase.clearAllData()).called(1);
    });

    test('should still clear local data when API logout fails', () async {
      // arrange
      when(mockApiClient.logout()).thenThrow(
        ServerException('Network error'),
      );
      when(mockSecureStorage.clearTokens()).thenAnswer((_) async => Future.value());
      when(mockDatabase.clearAllData()).thenAnswer((_) async => Future.value());

      // act
      final result = await repository.logout();

      // assert
      expect(result.isRight(), true);
      verify(mockSecureStorage.clearTokens()).called(1);
      verify(mockDatabase.clearAllData()).called(1);
    });
  });

  group('refreshToken', () {
    const refreshToken = 'test_refresh_token';
    
    test('should return new AuthResponse when refresh is successful', () async {
      // arrange
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockSecureStorage.getRefreshToken())
          .thenAnswer((_) async => refreshToken);
      when(mockApiClient.refreshToken(refreshToken))
          .thenAnswer((_) async => MockData.testAuthResponse);
      when(mockSecureStorage.saveTokens(any, any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.refreshToken();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (response) {
          expect(response, equals(MockData.testAuthResponse));
        },
      );
    });

    test('should return AuthFailure when no refresh token is stored', () async {
      // arrange
      when(mockSecureStorage.getRefreshToken())
          .thenAnswer((_) async => null);

      // act
      final result = await repository.refreshToken();

      // assert
      expect(result.isLeft(), true);
      result.fold(
        (failure) {
          expect(failure, isA<AuthFailure>());
        },
        (_) => fail('Should not return success'),
      );
    });
  });

  group('getCurrentUser', () {
    test('should return cached user when available', () async {
      // arrange
      when(mockDatabase.userDao.getCurrentUser())
          .thenAnswer((_) async => MockData.testUser);

      // act
      final result = await repository.getCurrentUser();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (user) {
          expect(user, equals(MockData.testUser));
        },
      );
      
      verifyNever(mockApiClient.getCurrentUser());
    });

    test('should fetch from API when no cached user exists', () async {
      // arrange
      when(mockDatabase.userDao.getCurrentUser())
          .thenAnswer((_) async => null);
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => true);
      when(mockApiClient.getCurrentUser())
          .thenAnswer((_) async => MockData.testUser);
      when(mockDatabase.userDao.insertUser(any))
          .thenAnswer((_) async => Future.value());

      // act
      final result = await repository.getCurrentUser();

      // assert
      expect(result.isRight(), true);
      result.fold(
        (failure) => fail('Should not return failure'),
        (user) {
          expect(user, equals(MockData.testUser));
        },
      );
      
      verify(mockApiClient.getCurrentUser()).called(1);
      verify(mockDatabase.userDao.insertUser(any)).called(1);
    });

    test('should return CacheFailure when offline and no cached user', () async {
      // arrange
      when(mockDatabase.userDao.getCurrentUser())
          .thenAnswer((_) async => null);
      when(mockNetworkInfo.isConnected).thenAnswer((_) async => false);

      // act
      final result = await repository.getCurrentUser();

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

  group('isAuthenticated', () {
    test('should return true when access token exists', () async {
      // arrange
      when(mockSecureStorage.getAccessToken())
          .thenAnswer((_) async => 'test_token');

      // act
      final result = await repository.isAuthenticated();

      // assert
      expect(result, true);
    });

    test('should return false when no access token exists', () async {
      // arrange
      when(mockSecureStorage.getAccessToken())
          .thenAnswer((_) async => null);

      // act
      final result = await repository.isAuthenticated();

      // assert
      expect(result, false);
    });
  });
}