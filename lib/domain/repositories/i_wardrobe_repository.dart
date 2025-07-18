import 'package:dartz/dartz.dart';
import '../entities/wardrobe.dart';
import '../failures/failures.dart';

abstract class IWardrobeRepository {
  /// Creates a new wardrobe for the current user
  Future<Either<Failure, Wardrobe>> createWardrobe({
    required String name,
    String? description,
  });

  /// Gets all wardrobes for the current user
  Future<Either<Failure, List<Wardrobe>>> getAllWardrobes();

  /// Gets a specific wardrobe by ID
  Future<Either<Failure, Wardrobe>> getWardrobeById(String wardrobeId);

  /// Updates an existing wardrobe
  Future<Either<Failure, Wardrobe>> updateWardrobe({
    required String wardrobeId,
    String? name,
    String? description,
  });

  /// Deletes a wardrobe and all its associated garments
  Future<Either<Failure, Unit>> deleteWardrobe(String wardrobeId);

  /// Shares a wardrobe with another user
  Future<Either<Failure, Unit>> shareWardrobe({
    required String wardrobeId,
    required String userId,
    required SharePermission permission,
  });

  /// Removes sharing permissions for a user
  Future<Either<Failure, Unit>> unshareWardrobe({
    required String wardrobeId,
    required String userId,
  });

  /// Gets all users who have access to a wardrobe
  Future<Either<Failure, List<WardrobeShare>>> getWardrobeShares(
    String wardrobeId,
  );

  /// Gets all wardrobes shared with the current user
  Future<Either<Failure, List<Wardrobe>>> getSharedWardrobes();

  /// Watches wardrobe changes in real-time
  Stream<Either<Failure, List<Wardrobe>>> watchWardrobes();

  /// Watches a specific wardrobe for changes
  Stream<Either<Failure, Wardrobe>> watchWardrobe(String wardrobeId);
}

/// Permission levels for shared wardrobes
enum SharePermission {
  view,
  edit,
  admin,
}

/// Represents a user's access to a shared wardrobe
class WardrobeShare {
  final String userId;
  final String userName;
  final String? userPhotoUrl;
  final SharePermission permission;
  final DateTime sharedAt;

  const WardrobeShare({
    required this.userId,
    required this.userName,
    this.userPhotoUrl,
    required this.permission,
    required this.sharedAt,
  });
}