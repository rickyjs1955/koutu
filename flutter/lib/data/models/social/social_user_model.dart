import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/image/image_model.dart';

part 'social_user_model.freezed.dart';
part 'social_user_model.g.dart';

/// Enhanced user model with social features
@freezed
class SocialUserModel with _$SocialUserModel {
  const factory SocialUserModel({
    required String id,
    required String email,
    required String username,
    required String displayName,
    String? bio,
    String? location,
    String? website,
    ImageModel? avatarImage,
    ImageModel? coverImage,
    required DateTime createdAt,
    required DateTime updatedAt,
    @Default(false) bool isVerified,
    @Default(false) bool isPrivate,
    @Default(0) int followersCount,
    @Default(0) int followingCount,
    @Default(0) int postsCount,
    @Default(0) int likesCount,
    @Default([]) List<String> interests,
    @Default([]) List<String> favoriteColors,
    @Default([]) List<String> favoriteStyles,
    @Default([]) List<String> favoriteBrands,
    SocialUserSettings? settings,
    SocialUserStats? stats,
  }) = _SocialUserModel;

  factory SocialUserModel.fromJson(Map<String, dynamic> json) =>
      _$SocialUserModelFromJson(json);
}

/// User settings for social features
@freezed
class SocialUserSettings with _$SocialUserSettings {
  const factory SocialUserSettings({
    @Default(true) bool allowFollowing,
    @Default(true) bool allowComments,
    @Default(true) bool allowRatings,
    @Default(true) bool allowMessages,
    @Default(true) bool showOnlineStatus,
    @Default(true) bool showStats,
    @Default(false) bool requireFollowApproval,
    @Default(NotificationSettings()) NotificationSettings notifications,
    @Default(PrivacySettings()) PrivacySettings privacy,
  }) = _SocialUserSettings;

  factory SocialUserSettings.fromJson(Map<String, dynamic> json) =>
      _$SocialUserSettingsFromJson(json);
}

/// Notification settings
@freezed
class NotificationSettings with _$NotificationSettings {
  const factory NotificationSettings({
    @Default(true) bool likes,
    @Default(true) bool comments,
    @Default(true) bool follows,
    @Default(true) bool mentions,
    @Default(true) bool challenges,
    @Default(true) bool recommendations,
    @Default(false) bool marketing,
  }) = _NotificationSettings;

  factory NotificationSettings.fromJson(Map<String, dynamic> json) =>
      _$NotificationSettingsFromJson(json);
}

/// Privacy settings
@freezed
class PrivacySettings with _$PrivacySettings {
  const factory PrivacySettings({
    @Default(ProfileVisibility.public) ProfileVisibility profileVisibility,
    @Default(PostVisibility.public) PostVisibility defaultPostVisibility,
    @Default(true) bool showFollowersCount,
    @Default(true) bool showFollowingCount,
    @Default(true) bool showPostsCount,
    @Default(true) bool showLikesCount,
    @Default(true) bool allowTagging,
    @Default(true) bool allowSharing,
  }) = _PrivacySettings;

  factory PrivacySettings.fromJson(Map<String, dynamic> json) =>
      _$PrivacySettingsFromJson(json);
}

/// User statistics
@freezed
class SocialUserStats with _$SocialUserStats {
  const factory SocialUserStats({
    @Default(0) int totalOutfits,
    @Default(0) int totalGarments,
    @Default(0) int totalWardrobes,
    @Default(0) int totalLikesReceived,
    @Default(0) int totalCommentsReceived,
    @Default(0) int totalShares,
    @Default(0) int totalViews,
    @Default(0) int challengesWon,
    @Default(0) int challengesParticipated,
    @Default(0) int streak,
    DateTime? lastActive,
  }) = _SocialUserStats;

  factory SocialUserStats.fromJson(Map<String, dynamic> json) =>
      _$SocialUserStatsFromJson(json);
}

/// Profile visibility options
enum ProfileVisibility {
  @JsonValue('public')
  public,
  @JsonValue('followers')
  followers,
  @JsonValue('private')
  private,
}

/// Post visibility options
enum PostVisibility {
  @JsonValue('public')
  public,
  @JsonValue('followers')
  followers,
  @JsonValue('private')
  private,
  @JsonValue('friends')
  friends,
}

/// Social authentication provider
enum SocialAuthProvider {
  @JsonValue('google')
  google,
  @JsonValue('facebook')
  facebook,
  @JsonValue('apple')
  apple,
  @JsonValue('instagram')
  instagram,
  @JsonValue('twitter')
  twitter,
}

/// Social authentication result
@freezed
class SocialAuthResult with _$SocialAuthResult {
  const factory SocialAuthResult({
    required SocialAuthProvider provider,
    required String providerId,
    required String accessToken,
    String? refreshToken,
    String? email,
    String? displayName,
    String? photoUrl,
    DateTime? expiresAt,
    Map<String, dynamic>? additionalData,
  }) = _SocialAuthResult;

  factory SocialAuthResult.fromJson(Map<String, dynamic> json) =>
      _$SocialAuthResultFromJson(json);
}

/// User relationship status
enum RelationshipStatus {
  @JsonValue('none')
  none,
  @JsonValue('following')
  following,
  @JsonValue('follower')
  follower,
  @JsonValue('mutual')
  mutual,
  @JsonValue('blocked')
  blocked,
  @JsonValue('pending')
  pending,
}

/// User relationship model
@freezed
class UserRelationship with _$UserRelationship {
  const factory UserRelationship({
    required String userId,
    required String targetUserId,
    required RelationshipStatus status,
    required DateTime createdAt,
    DateTime? updatedAt,
  }) = _UserRelationship;

  factory UserRelationship.fromJson(Map<String, dynamic> json) =>
      _$UserRelationshipFromJson(json);
}

/// User search result
@freezed
class UserSearchResult with _$UserSearchResult {
  const factory UserSearchResult({
    required SocialUserModel user,
    required double matchScore,
    required List<String> matchReasons,
    RelationshipStatus? relationshipStatus,
    @Default([]) List<String> mutualFollowers,
    @Default([]) List<String> commonInterests,
  }) = _UserSearchResult;

  factory UserSearchResult.fromJson(Map<String, dynamic> json) =>
      _$UserSearchResultFromJson(json);
}

/// Extensions for easy access
extension SocialUserModelExtensions on SocialUserModel {
  String get fullName => displayName.isNotEmpty ? displayName : username;
  
  String get profileImageUrl => avatarImage?.url ?? '';
  
  String get coverImageUrl => coverImage?.url ?? '';
  
  bool get hasProfileImage => avatarImage != null;
  
  bool get hasCoverImage => coverImage != null;
  
  bool get isPopular => followersCount > 1000;
  
  bool get isInfluencer => followersCount > 10000;
  
  bool get isActive => stats?.lastActive != null && 
      stats!.lastActive!.isAfter(DateTime.now().subtract(const Duration(days: 7)));
  
  double get engagementRate {
    if (postsCount == 0) return 0.0;
    return (likesCount + (stats?.totalCommentsReceived ?? 0)) / postsCount;
  }
  
  String get formattedFollowersCount => _formatCount(followersCount);
  
  String get formattedFollowingCount => _formatCount(followingCount);
  
  String get formattedPostsCount => _formatCount(postsCount);
  
  String _formatCount(int count) {
    if (count < 1000) return count.toString();
    if (count < 1000000) return '${(count / 1000).toStringAsFixed(1)}K';
    return '${(count / 1000000).toStringAsFixed(1)}M';
  }
}

extension ProfileVisibilityExtensions on ProfileVisibility {
  String get displayName {
    switch (this) {
      case ProfileVisibility.public:
        return 'Public';
      case ProfileVisibility.followers:
        return 'Followers Only';
      case ProfileVisibility.private:
        return 'Private';
    }
  }
  
  String get description {
    switch (this) {
      case ProfileVisibility.public:
        return 'Anyone can see your profile';
      case ProfileVisibility.followers:
        return 'Only followers can see your profile';
      case ProfileVisibility.private:
        return 'Only you can see your profile';
    }
  }
}

extension PostVisibilityExtensions on PostVisibility {
  String get displayName {
    switch (this) {
      case PostVisibility.public:
        return 'Public';
      case PostVisibility.followers:
        return 'Followers';
      case PostVisibility.friends:
        return 'Friends';
      case PostVisibility.private:
        return 'Private';
    }
  }
  
  String get description {
    switch (this) {
      case PostVisibility.public:
        return 'Anyone can see this post';
      case PostVisibility.followers:
        return 'Only followers can see this post';
      case PostVisibility.friends:
        return 'Only friends can see this post';
      case PostVisibility.private:
        return 'Only you can see this post';
    }
  }
}

extension SocialAuthProviderExtensions on SocialAuthProvider {
  String get displayName {
    switch (this) {
      case SocialAuthProvider.google:
        return 'Google';
      case SocialAuthProvider.facebook:
        return 'Facebook';
      case SocialAuthProvider.apple:
        return 'Apple';
      case SocialAuthProvider.instagram:
        return 'Instagram';
      case SocialAuthProvider.twitter:
        return 'Twitter';
    }
  }
  
  String get iconPath {
    switch (this) {
      case SocialAuthProvider.google:
        return 'assets/icons/google.svg';
      case SocialAuthProvider.facebook:
        return 'assets/icons/facebook.svg';
      case SocialAuthProvider.apple:
        return 'assets/icons/apple.svg';
      case SocialAuthProvider.instagram:
        return 'assets/icons/instagram.svg';
      case SocialAuthProvider.twitter:
        return 'assets/icons/twitter.svg';
    }
  }
}

extension RelationshipStatusExtensions on RelationshipStatus {
  String get displayName {
    switch (this) {
      case RelationshipStatus.none:
        return 'None';
      case RelationshipStatus.following:
        return 'Following';
      case RelationshipStatus.follower:
        return 'Follower';
      case RelationshipStatus.mutual:
        return 'Mutual';
      case RelationshipStatus.blocked:
        return 'Blocked';
      case RelationshipStatus.pending:
        return 'Pending';
    }
  }
  
  bool get isFollowing => this == RelationshipStatus.following || this == RelationshipStatus.mutual;
  
  bool get isFollower => this == RelationshipStatus.follower || this == RelationshipStatus.mutual;
  
  bool get canUnfollow => isFollowing;
  
  bool get canFollow => this == RelationshipStatus.none || this == RelationshipStatus.follower;
}