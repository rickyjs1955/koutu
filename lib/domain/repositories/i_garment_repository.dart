import 'package:dartz/dartz.dart';
import '../entities/garment.dart';
import '../failures/failures.dart';

abstract class IGarmentRepository {
  /// Adds a new garment to a wardrobe
  Future<Either<Failure, Garment>> addGarment({
    required String wardrobeId,
    required String name,
    required GarmentType type,
    required String color,
    required List<String> tags,
    String? brand,
    String? size,
    String? material,
    double? price,
    String? purchaseDate,
    String? notes,
    String? imageUrl,
  });

  /// Gets all garments in a specific wardrobe
  Future<Either<Failure, List<Garment>>> getGarmentsByWardrobe(
    String wardrobeId,
  );

  /// Gets a specific garment by ID
  Future<Either<Failure, Garment>> getGarmentById({
    required String wardrobeId,
    required String garmentId,
  });

  /// Updates an existing garment
  Future<Either<Failure, Garment>> updateGarment({
    required String wardrobeId,
    required String garmentId,
    String? name,
    GarmentType? type,
    String? color,
    List<String>? tags,
    String? brand,
    String? size,
    String? material,
    double? price,
    String? purchaseDate,
    String? notes,
    String? imageUrl,
  });

  /// Removes a garment from a wardrobe
  Future<Either<Failure, Unit>> removeGarment({
    required String wardrobeId,
    required String garmentId,
  });

  /// Searches garments by name or tags
  Future<Either<Failure, List<Garment>>> searchGarments({
    required String wardrobeId,
    required String query,
  });

  /// Filters garments by various criteria
  Future<Either<Failure, List<Garment>>> filterGarments({
    required String wardrobeId,
    GarmentType? type,
    List<String>? colors,
    List<String>? tags,
    String? brand,
    String? size,
    double? minPrice,
    double? maxPrice,
    DateTime? purchasedAfter,
    DateTime? purchasedBefore,
  });

  /// Gets garments by type
  Future<Either<Failure, List<Garment>>> getGarmentsByType({
    required String wardrobeId,
    required GarmentType type,
  });

  /// Gets garments by color
  Future<Either<Failure, List<Garment>>> getGarmentsByColor({
    required String wardrobeId,
    required String color,
  });

  /// Gets garments by tags
  Future<Either<Failure, List<Garment>>> getGarmentsByTags({
    required String wardrobeId,
    required List<String> tags,
    bool matchAll = false,
  });

  /// Batch add multiple garments
  Future<Either<Failure, List<Garment>>> addGarmentsBatch({
    required String wardrobeId,
    required List<GarmentCreateData> garments,
  });

  /// Batch delete multiple garments
  Future<Either<Failure, Unit>> removeGarmentsBatch({
    required String wardrobeId,
    required List<String> garmentIds,
  });

  /// Watches garments in a wardrobe for real-time updates
  Stream<Either<Failure, List<Garment>>> watchGarments(String wardrobeId);

  /// Watches a specific garment for changes
  Stream<Either<Failure, Garment>> watchGarment({
    required String wardrobeId,
    required String garmentId,
  });

  /// Gets garment statistics for a wardrobe
  Future<Either<Failure, GarmentStatistics>> getGarmentStatistics(
    String wardrobeId,
  );
}

/// Data class for creating a garment
class GarmentCreateData {
  final String name;
  final GarmentType type;
  final String color;
  final List<String> tags;
  final String? brand;
  final String? size;
  final String? material;
  final double? price;
  final String? purchaseDate;
  final String? notes;
  final String? imageUrl;

  const GarmentCreateData({
    required this.name,
    required this.type,
    required this.color,
    required this.tags,
    this.brand,
    this.size,
    this.material,
    this.price,
    this.purchaseDate,
    this.notes,
    this.imageUrl,
  });
}

/// Statistics about garments in a wardrobe
class GarmentStatistics {
  final int totalGarments;
  final Map<GarmentType, int> garmentsByType;
  final Map<String, int> garmentsByColor;
  final Map<String, int> garmentsByBrand;
  final double totalValue;
  final double averagePrice;
  final List<String> topTags;
  final DateTime? oldestPurchase;
  final DateTime? newestPurchase;

  const GarmentStatistics({
    required this.totalGarments,
    required this.garmentsByType,
    required this.garmentsByColor,
    required this.garmentsByBrand,
    required this.totalValue,
    required this.averagePrice,
    required this.topTags,
    this.oldestPurchase,
    this.newestPurchase,
  });
}