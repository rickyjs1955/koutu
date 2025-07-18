import 'package:equatable/equatable.dart';

/// User entity representing a user in the domain layer
class User extends Equatable {
  final String id;
  final String email;
  final String username;
  final String? firstName;
  final String? lastName;
  final String? profilePictureUrl;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isEmailVerified;
  final List<String> wardrobeIds;

  const User({
    required this.id,
    required this.email,
    required this.username,
    this.firstName,
    this.lastName,
    this.profilePictureUrl,
    required this.createdAt,
    required this.updatedAt,
    this.isEmailVerified = false,
    this.wardrobeIds = const [],
  });

  /// Get the full name of the user
  String get fullName {
    if (firstName != null && lastName != null) {
      return '$firstName $lastName';
    } else if (firstName != null) {
      return firstName!;
    } else if (lastName != null) {
      return lastName!;
    }
    return username;
  }

  /// Get the display name (username or full name)
  String get displayName => fullName != username ? fullName : username;

  /// Create a copy of User with updated fields
  User copyWith({
    String? id,
    String? email,
    String? username,
    String? firstName,
    String? lastName,
    String? profilePictureUrl,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isEmailVerified,
    List<String>? wardrobeIds,
  }) {
    return User(
      id: id ?? this.id,
      email: email ?? this.email,
      username: username ?? this.username,
      firstName: firstName ?? this.firstName,
      lastName: lastName ?? this.lastName,
      profilePictureUrl: profilePictureUrl ?? this.profilePictureUrl,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isEmailVerified: isEmailVerified ?? this.isEmailVerified,
      wardrobeIds: wardrobeIds ?? this.wardrobeIds,
    );
  }

  @override
  List<Object?> get props => [
        id,
        email,
        username,
        firstName,
        lastName,
        profilePictureUrl,
        createdAt,
        updatedAt,
        isEmailVerified,
        wardrobeIds,
      ];
}