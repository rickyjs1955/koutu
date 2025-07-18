import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/domain/entities/wardrobe.dart';

part 'wardrobe_model.freezed.dart';
part 'wardrobe_model.g.dart';

@freezed
class WardrobeModel with _$WardrobeModel {
  const WardrobeModel._();

  const factory WardrobeModel({
    required String id,
    @JsonKey(name: 'user_id') required String userId,
    required String name,
    String? description,
    @JsonKey(name: 'image_url') String? imageUrl,
    @JsonKey(name: 'garment_ids') @Default([]) List<String> garmentIds,
    @JsonKey(name: 'is_shared') @Default(false) bool isShared,
    @JsonKey(name: 'shared_with_user_ids') @Default([]) List<String> sharedWithUserIds,
    @JsonKey(name: 'share_settings') Map<String, dynamic>? shareSettings,
    @Default({}) Map<String, dynamic> metadata,
    @JsonKey(name: 'created_at') required DateTime createdAt,
    @JsonKey(name: 'updated_at') required DateTime updatedAt,
    @JsonKey(name: 'last_accessed_at') DateTime? lastAccessedAt,
    @JsonKey(name: 'is_default') @Default(false) bool isDefault,
    @JsonKey(name: 'sort_order') @Default(0) int sortOrder,
    @JsonKey(name: 'color_theme') String? colorTheme,
    @JsonKey(name: 'icon_name') String? iconName,
  }) = _WardrobeModel;

  factory WardrobeModel.fromJson(Map<String, dynamic> json) =>
      _$WardrobeModelFromJson(json);

  /// Convert to domain entity
  Wardrobe toEntity() {
    return Wardrobe(
      id: id,
      userId: userId,
      name: name,
      description: description,
      imageUrl: imageUrl,
      garmentIds: garmentIds,
      isShared: isShared,
      sharedWithUserIds: sharedWithUserIds,
      metadata: metadata,
      createdAt: createdAt,
      updatedAt: updatedAt,
    );
  }

  /// Create from domain entity
  factory WardrobeModel.fromEntity(Wardrobe wardrobe) {
    return WardrobeModel(
      id: wardrobe.id,
      userId: wardrobe.userId,
      name: wardrobe.name,
      description: wardrobe.description,
      imageUrl: wardrobe.imageUrl,
      garmentIds: wardrobe.garmentIds,
      isShared: wardrobe.isShared,
      sharedWithUserIds: wardrobe.sharedWithUserIds,
      metadata: wardrobe.metadata,
      createdAt: wardrobe.createdAt,
      updatedAt: wardrobe.updatedAt,
    );
  }

  /// Get garment count
  int get garmentCount => garmentIds.length;

  /// Check if wardrobe is empty
  bool get isEmpty => garmentIds.isEmpty;

  /// Get share permission for a user
  String? getSharePermission(String userId) {
    if (shareSettings != null && shareSettings!['permissions'] != null) {
      final permissions = shareSettings!['permissions'] as Map<String, dynamic>;
      return permissions[userId] as String?;
    }
    return null;
  }

  /// Check if user has edit permission
  bool canEdit(String currentUserId) {
    if (userId == currentUserId) return true;
    final permission = getSharePermission(currentUserId);
    return permission == 'edit' || permission == 'admin';
  }

  /// Check if user has admin permission
  bool canAdmin(String currentUserId) {
    if (userId == currentUserId) return true;
    final permission = getSharePermission(currentUserId);
    return permission == 'admin';
  }
}