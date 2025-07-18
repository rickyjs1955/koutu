import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/domain/entities/garment.dart';

part 'garment_model.freezed.dart';
part 'garment_model.g.dart';

@freezed
class GarmentModel with _$GarmentModel {
  const GarmentModel._();

  const factory GarmentModel({
    required String id,
    @JsonKey(name: 'wardrobe_id') required String wardrobeId,
    @JsonKey(name: 'user_id') required String userId,
    required String name,
    String? description,
    required String category,
    String? subcategory,
    String? brand,
    String? size,
    @Default([]) List<String> colors,
    @Default([]) List<String> tags,
    @JsonKey(name: 'image_ids') @Default([]) List<String> imageIds,
    @JsonKey(name: 'primary_image_id') String? primaryImageId,
    @JsonKey(name: 'purchase_price') double? purchasePrice,
    @JsonKey(name: 'purchase_date') DateTime? purchaseDate,
    @JsonKey(name: 'purchase_location') String? purchaseLocation,
    @JsonKey(name: 'wear_count') @Default(0) int wearCount,
    @JsonKey(name: 'last_worn_date') DateTime? lastWornDate,
    @JsonKey(name: 'is_favorite') @Default(false) bool isFavorite,
    @JsonKey(name: 'season') List<String>? season,
    @JsonKey(name: 'occasion') List<String>? occasion,
    @JsonKey(name: 'material') List<String>? material,
    @JsonKey(name: 'care_instructions') String? careInstructions,
    @JsonKey(name: 'notes') String? notes,
    @Default({}) Map<String, dynamic> metadata,
    @JsonKey(name: 'created_at') required DateTime createdAt,
    @JsonKey(name: 'updated_at') required DateTime updatedAt,
    @JsonKey(name: 'is_active') @Default(true) bool isActive,
    @JsonKey(name: 'outfit_ids') @Default([]) List<String> outfitIds,
  }) = _GarmentModel;

  factory GarmentModel.fromJson(Map<String, dynamic> json) =>
      _$GarmentModelFromJson(json);

  /// Convert to domain entity
  Garment toEntity() {
    return Garment(
      id: id,
      wardrobeId: wardrobeId,
      userId: userId,
      name: name,
      description: description,
      category: category,
      subcategory: subcategory,
      brand: brand,
      size: size,
      colors: colors,
      tags: tags,
      imageIds: imageIds,
      primaryImageId: primaryImageId,
      purchasePrice: purchasePrice,
      purchaseDate: purchaseDate,
      purchaseLocation: purchaseLocation,
      wearCount: wearCount,
      lastWornDate: lastWornDate,
      isFavorite: isFavorite,
      metadata: metadata,
      createdAt: createdAt,
      updatedAt: updatedAt,
    );
  }

  /// Create from domain entity
  factory GarmentModel.fromEntity(Garment garment) {
    return GarmentModel(
      id: garment.id,
      wardrobeId: garment.wardrobeId,
      userId: garment.userId,
      name: garment.name,
      description: garment.description,
      category: garment.category,
      subcategory: garment.subcategory,
      brand: garment.brand,
      size: garment.size,
      colors: garment.colors,
      tags: garment.tags,
      imageIds: garment.imageIds,
      primaryImageId: garment.primaryImageId,
      purchasePrice: garment.purchasePrice,
      purchaseDate: garment.purchaseDate,
      purchaseLocation: garment.purchaseLocation,
      wearCount: garment.wearCount,
      lastWornDate: garment.lastWornDate,
      isFavorite: garment.isFavorite,
      metadata: garment.metadata,
      createdAt: garment.createdAt,
      updatedAt: garment.updatedAt,
    );
  }

  /// Get cost per wear
  double? get costPerWear {
    if (purchasePrice != null && wearCount > 0) {
      return purchasePrice! / wearCount;
    }
    return null;
  }

  /// Get days since last worn
  int? get daysSinceLastWorn {
    if (lastWornDate != null) {
      return DateTime.now().difference(lastWornDate!).inDays;
    }
    return null;
  }

  /// Check if garment is new (never worn)
  bool get isNew => wearCount == 0;

  /// Check if garment has images
  bool get hasImages => imageIds.isNotEmpty;

  /// Get primary color
  String? get primaryColor => colors.isNotEmpty ? colors.first : null;

  /// Check if garment matches season
  bool matchesSeason(String seasonName) {
    return season?.contains(seasonName) ?? false;
  }

  /// Check if garment matches occasion
  bool matchesOccasion(String occasionName) {
    return occasion?.contains(occasionName) ?? false;
  }

  /// Get all searchable text
  String get searchableText {
    return [
      name,
      description,
      category,
      subcategory,
      brand,
      ...colors,
      ...tags,
      notes,
    ].where((text) => text != null).join(' ').toLowerCase();
  }
}