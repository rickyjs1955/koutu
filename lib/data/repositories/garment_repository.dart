import 'package:dartz/dartz.dart';
import 'package:injectable/injectable.dart';
import 'package:rxdart/rxdart.dart';

import '../../domain/entities/garment.dart';
import '../../domain/failures/failures.dart';
import '../../domain/repositories/i_garment_repository.dart';

@LazySingleton(as: IGarmentRepository)
class GarmentRepository implements IGarmentRepository {
  // In-memory storage for stub data
  final Map<String, List<Garment>> _garmentsByWardrobe = {};
  final Map<String, BehaviorSubject<List<Garment>>> _garmentStreams = {};

  GarmentRepository() {
    // Initialize with some stub data
    _initializeStubData();
  }

  void _initializeStubData() {
    final now = DateTime.now();
    _garmentsByWardrobe['wardrobe-1'] = [
      Garment(
        id: 'garment-1',
        wardrobeId: 'wardrobe-1',
        name: 'Blue Jeans',
        type: GarmentType.bottom,
        color: '#0000FF',
        tags: ['casual', 'denim', 'everyday'],
        brand: 'Levi\'s',
        size: '32',
        material: 'Denim',
        price: 59.99,
        purchaseDate: now.subtract(const Duration(days: 90)),
        createdAt: now.subtract(const Duration(days: 90)),
        updatedAt: now,
        wearCount: 15,
        lastWorn: now.subtract(const Duration(days: 2)),
        isFavorite: true,
      ),
      Garment(
        id: 'garment-2',
        wardrobeId: 'wardrobe-1',
        name: 'White T-Shirt',
        type: GarmentType.top,
        color: '#FFFFFF',
        tags: ['casual', 'basic', 'everyday'],
        brand: 'Uniqlo',
        size: 'M',
        material: 'Cotton',
        price: 19.99,
        purchaseDate: now.subtract(const Duration(days: 60)),
        createdAt: now.subtract(const Duration(days: 60)),
        updatedAt: now,
        wearCount: 20,
        lastWorn: now.subtract(const Duration(days: 1)),
      ),
      Garment(
        id: 'garment-3',
        wardrobeId: 'wardrobe-1',
        name: 'Black Leather Jacket',
        type: GarmentType.outerwear,
        color: '#000000',
        tags: ['formal', 'leather', 'winter'],
        brand: 'Zara',
        size: 'L',
        material: 'Leather',
        price: 199.99,
        purchaseDate: now.subtract(const Duration(days: 180)),
        createdAt: now.subtract(const Duration(days: 180)),
        updatedAt: now,
        wearCount: 8,
        lastWorn: now.subtract(const Duration(days: 10)),
        isFavorite: true,
      ),
    ];

    _garmentsByWardrobe['wardrobe-2'] = [
      Garment(
        id: 'garment-4',
        wardrobeId: 'wardrobe-2',
        name: 'Floral Summer Dress',
        type: GarmentType.dress,
        color: '#FF69B4',
        tags: ['summer', 'floral', 'casual'],
        brand: 'H&M',
        size: 'S',
        material: 'Cotton blend',
        price: 39.99,
        purchaseDate: now.subtract(const Duration(days: 30)),
        createdAt: now.subtract(const Duration(days: 30)),
        updatedAt: now,
        wearCount: 5,
        lastWorn: now.subtract(const Duration(days: 5)),
      ),
    ];
  }

  @override
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
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 500));

    final now = DateTime.now();
    final garment = Garment(
      id: 'garment-${now.millisecondsSinceEpoch}',
      wardrobeId: wardrobeId,
      name: name,
      type: type,
      color: color,
      tags: tags,
      brand: brand,
      size: size,
      material: material,
      price: price,
      purchaseDate: purchaseDate != null ? DateTime.parse(purchaseDate) : null,
      notes: notes,
      imageUrl: imageUrl,
      createdAt: now,
      updatedAt: now,
    );

    _garmentsByWardrobe[wardrobeId] ??= [];
    _garmentsByWardrobe[wardrobeId]!.add(garment);
    _notifyGarmentUpdate(wardrobeId);

    return Right(garment);
  }

  @override
  Future<Either<Failure, List<Garment>>> getGarmentsByWardrobe(
    String wardrobeId,
  ) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    return Right(List.from(garments));
  }

  @override
  Future<Either<Failure, Garment>> getGarmentById({
    required String wardrobeId,
    required String garmentId,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    try {
      final garment = garments.firstWhere((g) => g.id == garmentId);
      return Right(garment);
    } catch (_) {
      return Left(Failure.notFound(
        message: 'Garment not found',
        resourceType: 'Garment',
        resourceId: garmentId,
      ));
    }
  }

  @override
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
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 400));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    final index = garments.indexWhere((g) => g.id == garmentId);
    
    if (index == -1) {
      return Left(Failure.notFound(
        message: 'Garment not found',
        resourceType: 'Garment',
        resourceId: garmentId,
      ));
    }

    final garment = garments[index];
    final updated = garment.copyWith(
      name: name ?? garment.name,
      type: type ?? garment.type,
      color: color ?? garment.color,
      tags: tags ?? garment.tags,
      brand: brand ?? garment.brand,
      size: size ?? garment.size,
      material: material ?? garment.material,
      price: price ?? garment.price,
      purchaseDate: purchaseDate != null ? DateTime.parse(purchaseDate) : garment.purchaseDate,
      notes: notes ?? garment.notes,
      imageUrl: imageUrl ?? garment.imageUrl,
      updatedAt: DateTime.now(),
    );

    garments[index] = updated;
    _notifyGarmentUpdate(wardrobeId);

    return Right(updated);
  }

  @override
  Future<Either<Failure, Unit>> removeGarment({
    required String wardrobeId,
    required String garmentId,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    garments.removeWhere((g) => g.id == garmentId);
    _notifyGarmentUpdate(wardrobeId);

    return const Right(unit);
  }

  @override
  Future<Either<Failure, List<Garment>>> searchGarments({
    required String wardrobeId,
    required String query,
  }) async {
    // TODO: Implement actual API call with backend search
    await Future.delayed(const Duration(milliseconds: 200));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    final queryLower = query.toLowerCase();
    
    final results = garments.where((garment) {
      return garment.name.toLowerCase().contains(queryLower) ||
          garment.tags.any((tag) => tag.toLowerCase().contains(queryLower)) ||
          (garment.brand?.toLowerCase().contains(queryLower) ?? false) ||
          (garment.material?.toLowerCase().contains(queryLower) ?? false);
    }).toList();

    return Right(results);
  }

  @override
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
  }) async {
    // TODO: Implement actual API call with backend filtering
    await Future.delayed(const Duration(milliseconds: 300));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    
    final results = garments.where((garment) {
      if (type != null && garment.type != type) return false;
      if (colors != null && !colors.contains(garment.color)) return false;
      if (tags != null && tags.isNotEmpty && 
          !garment.tags.any((tag) => tags.contains(tag))) return false;
      if (brand != null && garment.brand != brand) return false;
      if (size != null && garment.size != size) return false;
      if (minPrice != null && (garment.price ?? 0) < minPrice) return false;
      if (maxPrice != null && (garment.price ?? 0) > maxPrice) return false;
      if (purchasedAfter != null && garment.purchaseDate != null &&
          garment.purchaseDate!.isBefore(purchasedAfter)) return false;
      if (purchasedBefore != null && garment.purchaseDate != null &&
          garment.purchaseDate!.isAfter(purchasedBefore)) return false;
      
      return true;
    }).toList();

    return Right(results);
  }

  @override
  Future<Either<Failure, List<Garment>>> getGarmentsByType({
    required String wardrobeId,
    required GarmentType type,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    final results = garments.where((g) => g.type == type).toList();
    
    return Right(results);
  }

  @override
  Future<Either<Failure, List<Garment>>> getGarmentsByColor({
    required String wardrobeId,
    required String color,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    final results = garments.where((g) => g.color == color).toList();
    
    return Right(results);
  }

  @override
  Future<Either<Failure, List<Garment>>> getGarmentsByTags({
    required String wardrobeId,
    required List<String> tags,
    bool matchAll = false,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    
    final results = garments.where((garment) {
      if (matchAll) {
        return tags.every((tag) => garment.tags.contains(tag));
      } else {
        return tags.any((tag) => garment.tags.contains(tag));
      }
    }).toList();
    
    return Right(results);
  }

  @override
  Future<Either<Failure, List<Garment>>> addGarmentsBatch({
    required String wardrobeId,
    required List<GarmentCreateData> garments,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 800));

    final results = <Garment>[];
    final now = DateTime.now();
    
    for (final data in garments) {
      final garment = Garment(
        id: 'garment-${now.millisecondsSinceEpoch}-${results.length}',
        wardrobeId: wardrobeId,
        name: data.name,
        type: data.type,
        color: data.color,
        tags: data.tags,
        brand: data.brand,
        size: data.size,
        material: data.material,
        price: data.price,
        purchaseDate: data.purchaseDate != null ? DateTime.parse(data.purchaseDate!) : null,
        notes: data.notes,
        imageUrl: data.imageUrl,
        createdAt: now,
        updatedAt: now,
      );
      results.add(garment);
    }
    
    _garmentsByWardrobe[wardrobeId] ??= [];
    _garmentsByWardrobe[wardrobeId]!.addAll(results);
    _notifyGarmentUpdate(wardrobeId);

    return Right(results);
  }

  @override
  Future<Either<Failure, Unit>> removeGarmentsBatch({
    required String wardrobeId,
    required List<String> garmentIds,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 500));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    garments.removeWhere((g) => garmentIds.contains(g.id));
    _notifyGarmentUpdate(wardrobeId);

    return const Right(unit);
  }

  @override
  Stream<Either<Failure, List<Garment>>> watchGarments(String wardrobeId) {
    // TODO: Implement actual real-time subscription
    _garmentStreams[wardrobeId] ??= BehaviorSubject.seeded(
      _garmentsByWardrobe[wardrobeId] ?? [],
    );
    
    return _garmentStreams[wardrobeId]!.stream.map((garments) => Right(garments));
  }

  @override
  Stream<Either<Failure, Garment>> watchGarment({
    required String wardrobeId,
    required String garmentId,
  }) {
    // TODO: Implement actual real-time subscription
    return watchGarments(wardrobeId).map((either) {
      return either.fold(
        (failure) => Left(failure),
        (garments) {
          try {
            final garment = garments.firstWhere((g) => g.id == garmentId);
            return Right(garment);
          } catch (_) {
            return Left(Failure.notFound(
              message: 'Garment not found',
              resourceType: 'Garment',
              resourceId: garmentId,
            ));
          }
        },
      );
    });
  }

  @override
  Future<Either<Failure, GarmentStatistics>> getGarmentStatistics(
    String wardrobeId,
  ) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));

    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    
    // Calculate statistics
    final garmentsByType = <GarmentType, int>{};
    final garmentsByColor = <String, int>{};
    final garmentsByBrand = <String, int>{};
    final tagCounts = <String, int>{};
    double totalValue = 0;
    DateTime? oldestPurchase;
    DateTime? newestPurchase;
    
    for (final garment in garments) {
      // Count by type
      garmentsByType[garment.type] = (garmentsByType[garment.type] ?? 0) + 1;
      
      // Count by color
      garmentsByColor[garment.color] = (garmentsByColor[garment.color] ?? 0) + 1;
      
      // Count by brand
      if (garment.brand != null) {
        garmentsByBrand[garment.brand!] = (garmentsByBrand[garment.brand!] ?? 0) + 1;
      }
      
      // Count tags
      for (final tag in garment.tags) {
        tagCounts[tag] = (tagCounts[tag] ?? 0) + 1;
      }
      
      // Calculate value
      if (garment.price != null) {
        totalValue += garment.price!;
      }
      
      // Track purchase dates
      if (garment.purchaseDate != null) {
        if (oldestPurchase == null || garment.purchaseDate!.isBefore(oldestPurchase)) {
          oldestPurchase = garment.purchaseDate;
        }
        if (newestPurchase == null || garment.purchaseDate!.isAfter(newestPurchase)) {
          newestPurchase = garment.purchaseDate;
        }
      }
    }
    
    // Get top tags
    final sortedTags = tagCounts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    final topTags = sortedTags.take(10).map((e) => e.key).toList();
    
    final stats = GarmentStatistics(
      totalGarments: garments.length,
      garmentsByType: garmentsByType,
      garmentsByColor: garmentsByColor,
      garmentsByBrand: garmentsByBrand,
      totalValue: totalValue,
      averagePrice: garments.isEmpty ? 0 : totalValue / garments.length,
      topTags: topTags,
      oldestPurchase: oldestPurchase,
      newestPurchase: newestPurchase,
    );
    
    return Right(stats);
  }

  void _notifyGarmentUpdate(String wardrobeId) {
    final garments = _garmentsByWardrobe[wardrobeId] ?? [];
    _garmentStreams[wardrobeId]?.add(garments);
  }

  void dispose() {
    for (final stream in _garmentStreams.values) {
      stream.close();
    }
  }
}