import 'package:freezed_annotation/freezed_annotation.dart';

part 'garment.freezed.dart';
part 'garment.g.dart';

@freezed
class Garment with _$Garment {
  const factory Garment({
    required String id,
    required String wardrobeId,
    required String name,
    required GarmentType type,
    required String color,
    required List<String> tags,
    String? brand,
    String? size,
    String? material,
    double? price,
    DateTime? purchaseDate,
    String? notes,
    String? imageUrl,
    required DateTime createdAt,
    required DateTime updatedAt,
    @Default(0) int wearCount,
    DateTime? lastWorn,
    @Default(false) bool isFavorite,
  }) = _Garment;

  factory Garment.fromJson(Map<String, dynamic> json) =>
      _$GarmentFromJson(json);
}

enum GarmentType {
  @JsonValue('top')
  top,
  @JsonValue('bottom')
  bottom,
  @JsonValue('dress')
  dress,
  @JsonValue('outerwear')
  outerwear,
  @JsonValue('shoes')
  shoes,
  @JsonValue('accessory')
  accessory,
  @JsonValue('underwear')
  underwear,
  @JsonValue('other')
  other,
}