import 'package:dartz/dartz.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/domain/entities/user.dart';
import 'package:koutu/domain/repositories/i_auth_repository.dart';

/// Implementation of auth repository
@LazySingleton(as: IAuthRepository)
class AuthRepository implements IAuthRepository {
  @override
  Future<Either<Failure, User>> login({
    required String email,
    required String password,
  }) async {
    // TODO: Implement actual login logic
    await Future.delayed(const Duration(seconds: 1));
    return Right(
      User(
        id: '1',
        email: email,
        username: email.split('@')[0],
        firstName: 'Test',
        lastName: 'User',
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
    );
  }

  @override
  Future<Either<Failure, User>> register({
    required String email,
    required String password,
    required String name,
  }) async {
    // TODO: Implement actual registration logic
    await Future.delayed(const Duration(seconds: 1));
    return Right(
      User(
        id: '1',
        email: email,
        username: email.split('@')[0],
        firstName: name.split(' ')[0],
        lastName: name.split(' ').length > 1 ? name.split(' ')[1] : '',
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      ),
    );
  }

  @override
  Future<Either<Failure, void>> logout() async {
    // TODO: Implement actual logout logic
    await Future.delayed(const Duration(milliseconds: 500));
    return const Right(null);
  }

  @override
  Future<Either<Failure, User?>> getCurrentUser() async {
    // TODO: Implement actual get current user logic
    await Future.delayed(const Duration(milliseconds: 500));
    return const Right(null);
  }

  @override
  Future<Either<Failure, void>> refreshToken() async {
    // TODO: Implement actual token refresh logic
    await Future.delayed(const Duration(milliseconds: 500));
    return const Right(null);
  }

  @override
  Future<bool> get isAuthenticated async {
    // TODO: Implement actual auth check
    return false;
  }

  @override
  Future<Either<Failure, void>> resetPassword(String email) async {
    // TODO: Implement actual password reset logic
    await Future.delayed(const Duration(seconds: 1));
    return const Right(null);
  }

  @override
  Future<Either<Failure, User>> updateProfile(User user) async {
    // TODO: Implement actual profile update logic
    await Future.delayed(const Duration(seconds: 1));
    return Right(user);
  }
}