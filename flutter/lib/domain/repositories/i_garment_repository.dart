import 'package:dartz/dartz.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Repository interface for garment operations
abstract class IGarmentRepository {
  /// Get all garments for the current user
  Future<Either<Failure, List<GarmentModel>>> getGarments();

  /// Get garments for a specific wardrobe
  Future<Either<Failure, List<GarmentModel>>> getGarmentsByWardrobe(String wardrobeId);

  /// Get a specific garment by ID
  Future<Either<Failure, GarmentModel>> getGarment(String garmentId);

  /// Create a new garment
  Future<Either<Failure, GarmentModel>> createGarment(GarmentModel garment);

  /// Update an existing garment
  Future<Either<Failure, GarmentModel>> updateGarment(GarmentModel garment);

  /// Delete a garment
  Future<Either<Failure, void>> deleteGarment(String garmentId);

  /// Search garments by query
  Future<Either<Failure, List<GarmentModel>>> searchGarments(String query);

  /// Get garments by category
  Future<Either<Failure, List<GarmentModel>>> getGarmentsByCategory(String category);

  /// Get favorite garments
  Future<Either<Failure, List<GarmentModel>>> getFavoriteGarments();

  /// Get recently worn garments
  Future<Either<Failure, List<GarmentModel>>> getRecentlyWornGarments(int limit);

  /// Record a wear for a garment
  Future<Either<Failure, GarmentModel>> recordWear(String garmentId, DateTime wornDate);

  /// Move garment to another wardrobe
  Future<Either<Failure, GarmentModel>> moveToWardrobe(String garmentId, String wardrobeId);

  /// Duplicate a garment
  Future<Either<Failure, GarmentModel>> duplicateGarment(String garmentId);

  /// Bulk update garments (for batch operations)
  Future<Either<Failure, List<GarmentModel>>> bulkUpdateGarments(List<GarmentModel> garments);

  /// Bulk delete garments
  Future<Either<Failure, void>> bulkDeleteGarments(List<String> garmentIds);
}