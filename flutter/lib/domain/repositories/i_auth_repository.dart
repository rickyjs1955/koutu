import 'package:dartz/dartz.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/domain/entities/user.dart';

/// Auth repository interface
abstract class IAuthRepository {
  /// Login with email and password
  Future<Either<Failure, User>> login({
    required String email,
    required String password,
  });

  /// Register new user
  Future<Either<Failure, User>> register({
    required String email,
    required String password,
    required String name,
  });

  /// Logout current user
  Future<Either<Failure, void>> logout();

  /// Get current user
  Future<Either<Failure, User?>> getCurrentUser();

  /// Refresh auth token
  Future<Either<Failure, void>> refreshToken();

  /// Check if user is authenticated
  Future<bool> get isAuthenticated;

  /// Reset password
  Future<Either<Failure, void>> resetPassword(String email);

  /// Update user profile
  Future<Either<Failure, User>> updateProfile(User user);
}