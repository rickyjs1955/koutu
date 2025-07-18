import 'package:freezed_annotation/freezed_annotation.dart';

part 'wardrobe.freezed.dart';
part 'wardrobe.g.dart';

@freezed
class Wardrobe with _$Wardrobe {
  const factory Wardrobe({
    required String id,
    required String userId,
    required String name,
    String? description,
    required DateTime createdAt,
    required DateTime updatedAt,
    @Default(false) bool isShared,
    @Default([]) List<String> sharedWith,
    @Default(0) int garmentCount,
    String? coverImageUrl,
  }) = _Wardrobe;

  factory Wardrobe.fromJson(Map<String, dynamic> json) =>
      _$WardrobeFromJson(json);
}