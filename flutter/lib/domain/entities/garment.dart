import 'package:equatable/equatable.dart';

/// Garment entity representing a clothing item in the domain layer
class Garment extends Equatable {
  final String id;
  final String wardrobeId;
  final String userId;
  final String name;
  final String? description;
  final String category;
  final String? subcategory;
  final String? brand;
  final String? size;
  final List<String> colors;
  final List<String> tags;
  final List<String> imageIds;
  final String? primaryImageId;
  final double? purchasePrice;
  final DateTime? purchaseDate;
  final String? purchaseLocation;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isFavorite;
  final int wearCount;
  final DateTime? lastWornDate;

  const Garment({
    required this.id,
    required this.wardrobeId,
    required this.userId,
    required this.name,
    this.description,
    required this.category,
    this.subcategory,
    this.brand,
    this.size,
    this.colors = const [],
    this.tags = const [],
    this.imageIds = const [],
    this.primaryImageId,
    this.purchasePrice,
    this.purchaseDate,
    this.purchaseLocation,
    this.metadata,
    required this.createdAt,
    required this.updatedAt,
    this.isFavorite = false,
    this.wearCount = 0,
    this.lastWornDate,
  });

  /// Check if the garment has images
  bool get hasImages => imageIds.isNotEmpty;

  /// Get the primary color (first color in the list)
  String? get primaryColor => colors.isNotEmpty ? colors.first : null;

  /// Check if the garment has been worn
  bool get hasBeenWorn => wearCount > 0;

  /// Calculate cost per wear
  double? get costPerWear {
    if (purchasePrice != null && wearCount > 0) {
      return purchasePrice! / wearCount;
    }
    return null;
  }

  /// Create a copy of Garment with updated fields
  Garment copyWith({
    String? id,
    String? wardrobeId,
    String? userId,
    String? name,
    String? description,
    String? category,
    String? subcategory,
    String? brand,
    String? size,
    List<String>? colors,
    List<String>? tags,
    List<String>? imageIds,
    String? primaryImageId,
    double? purchasePrice,
    DateTime? purchaseDate,
    String? purchaseLocation,
    Map<String, dynamic>? metadata,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isFavorite,
    int? wearCount,
    DateTime? lastWornDate,
  }) {
    return Garment(
      id: id ?? this.id,
      wardrobeId: wardrobeId ?? this.wardrobeId,
      userId: userId ?? this.userId,
      name: name ?? this.name,
      description: description ?? this.description,
      category: category ?? this.category,
      subcategory: subcategory ?? this.subcategory,
      brand: brand ?? this.brand,
      size: size ?? this.size,
      colors: colors ?? this.colors,
      tags: tags ?? this.tags,
      imageIds: imageIds ?? this.imageIds,
      primaryImageId: primaryImageId ?? this.primaryImageId,
      purchasePrice: purchasePrice ?? this.purchasePrice,
      purchaseDate: purchaseDate ?? this.purchaseDate,
      purchaseLocation: purchaseLocation ?? this.purchaseLocation,
      metadata: metadata ?? this.metadata,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isFavorite: isFavorite ?? this.isFavorite,
      wearCount: wearCount ?? this.wearCount,
      lastWornDate: lastWornDate ?? this.lastWornDate,
    );
  }

  @override
  List<Object?> get props => [
        id,
        wardrobeId,
        userId,
        name,
        description,
        category,
        subcategory,
        brand,
        size,
        colors,
        tags,
        imageIds,
        primaryImageId,
        purchasePrice,
        purchaseDate,
        purchaseLocation,
        metadata,
        createdAt,
        updatedAt,
        isFavorite,
        wearCount,
        lastWornDate,
      ];
}