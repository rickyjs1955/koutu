import 'package:equatable/equatable.dart';

/// Wardrobe entity representing a collection of garments in the domain layer
class Wardrobe extends Equatable {
  final String id;
  final String userId;
  final String name;
  final String? description;
  final String? imageUrl;
  final List<String> garmentIds;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isShared;
  final List<String> sharedWithUserIds;

  const Wardrobe({
    required this.id,
    required this.userId,
    required this.name,
    this.description,
    this.imageUrl,
    this.garmentIds = const [],
    this.metadata,
    required this.createdAt,
    required this.updatedAt,
    this.isShared = false,
    this.sharedWithUserIds = const [],
  });

  /// Get the number of garments in the wardrobe
  int get garmentCount => garmentIds.length;

  /// Check if the wardrobe is empty
  bool get isEmpty => garmentIds.isEmpty;

  /// Check if the wardrobe is shared with a specific user
  bool isSharedWithUser(String userId) => sharedWithUserIds.contains(userId);

  /// Create a copy of Wardrobe with updated fields
  Wardrobe copyWith({
    String? id,
    String? userId,
    String? name,
    String? description,
    String? imageUrl,
    List<String>? garmentIds,
    Map<String, dynamic>? metadata,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isShared,
    List<String>? sharedWithUserIds,
  }) {
    return Wardrobe(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      name: name ?? this.name,
      description: description ?? this.description,
      imageUrl: imageUrl ?? this.imageUrl,
      garmentIds: garmentIds ?? this.garmentIds,
      metadata: metadata ?? this.metadata,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isShared: isShared ?? this.isShared,
      sharedWithUserIds: sharedWithUserIds ?? this.sharedWithUserIds,
    );
  }

  @override
  List<Object?> get props => [
        id,
        userId,
        name,
        description,
        imageUrl,
        garmentIds,
        metadata,
        createdAt,
        updatedAt,
        isShared,
        sharedWithUserIds,
      ];
}