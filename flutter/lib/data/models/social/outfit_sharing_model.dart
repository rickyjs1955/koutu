import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/data/models/image/image_model.dart';

part 'outfit_sharing_model.freezed.dart';
part 'outfit_sharing_model.g.dart';

/// Shared outfit model with social features
@freezed
class SharedOutfitModel with _$SharedOutfitModel {
  const factory SharedOutfitModel({
    required String id,
    required String userId,
    required String outfitId,
    required String title,
    String? description,
    required ShareVisibility visibility,
    required DateTime sharedAt,
    DateTime? updatedAt,
    @Default([]) List<String> tags,
    @Default([]) List<ImageModel> images,
    @Default(0) int likesCount,
    @Default(0) int commentsCount,
    @Default(0) int sharesCount,
    @Default(0) int viewsCount,
    @Default(false) bool allowComments,
    @Default(false) bool allowShares,
    @Default(false) bool allowDownloads,
    @Default(false) bool isPromoted,
    @Default(false) bool isFeatured,
    SocialUserModel? author,
    OutfitModel? outfit,
    ShareMetadata? metadata,
  }) = _SharedOutfitModel;

  factory SharedOutfitModel.fromJson(Map<String, dynamic> json) =>
      _$SharedOutfitModelFromJson(json);
}

/// Share visibility options
enum ShareVisibility {
  @JsonValue('public')
  public,
  @JsonValue('followers')
  followers,
  @JsonValue('friends')
  friends,
  @JsonValue('private')
  private,
  @JsonValue('unlisted')
  unlisted,
}

/// Share metadata for analytics
@freezed
class ShareMetadata with _$ShareMetadata {
  const factory ShareMetadata({
    @Default([]) List<String> sharedOn,
    @Default({}) Map<String, dynamic> analytics,
    String? originalSource,
    DateTime? lastInteraction,
    @Default(0) int totalInteractions,
    @Default(0) int uniqueViews,
    @Default(0) int avgViewDuration,
    @Default([]) List<String> viewerCountries,
    @Default([]) List<String> viewerAgeGroups,
  }) = _ShareMetadata;

  factory ShareMetadata.fromJson(Map<String, dynamic> json) =>
      _$ShareMetadataFromJson(json);
}

/// Outfit interaction model
@freezed
class OutfitInteraction with _$OutfitInteraction {
  const factory OutfitInteraction({
    required String id,
    required String userId,
    required String sharedOutfitId,
    required InteractionType type,
    required DateTime createdAt,
    String? content,
    Map<String, dynamic>? metadata,
  }) = _OutfitInteraction;

  factory OutfitInteraction.fromJson(Map<String, dynamic> json) =>
      _$OutfitInteractionFromJson(json);
}

/// Interaction types
enum InteractionType {
  @JsonValue('like')
  like,
  @JsonValue('comment')
  comment,
  @JsonValue('share')
  share,
  @JsonValue('save')
  save,
  @JsonValue('report')
  report,
  @JsonValue('view')
  view,
  @JsonValue('download')
  download,
}

/// Outfit comment model
@freezed
class OutfitComment with _$OutfitComment {
  const factory OutfitComment({
    required String id,
    required String userId,
    required String sharedOutfitId,
    required String content,
    required DateTime createdAt,
    DateTime? updatedAt,
    String? parentCommentId,
    @Default(0) int likesCount,
    @Default(0) int repliesCount,
    @Default(false) bool isEdited,
    @Default(false) bool isDeleted,
    @Default(false) bool isPinned,
    SocialUserModel? author,
    @Default([]) List<OutfitComment> replies,
  }) = _OutfitComment;

  factory OutfitComment.fromJson(Map<String, dynamic> json) =>
      _$OutfitCommentFromJson(json);
}

/// Outfit sharing settings
@freezed
class OutfitSharingSettings with _$OutfitSharingSettings {
  const factory OutfitSharingSettings({
    @Default(ShareVisibility.public) ShareVisibility defaultVisibility,
    @Default(true) bool allowComments,
    @Default(true) bool allowShares,
    @Default(false) bool allowDownloads,
    @Default(true) bool showAuthorInfo,
    @Default(true) bool enableAnalytics,
    @Default(false) bool requireApproval,
    @Default(false) bool watermarkImages,
    @Default([]) List<String> blockedWords,
    @Default([]) List<String> allowedDomains,
  }) = _OutfitSharingSettings;

  factory OutfitSharingSettings.fromJson(Map<String, dynamic> json) =>
      _$OutfitSharingSettingsFromJson(json);
}

/// Share request model
@freezed
class ShareRequest with _$ShareRequest {
  const factory ShareRequest({
    required String outfitId,
    required String title,
    String? description,
    required ShareVisibility visibility,
    @Default([]) List<String> tags,
    @Default(true) bool allowComments,
    @Default(true) bool allowShares,
    @Default(false) bool allowDownloads,
    @Default([]) List<String> sharedOn,
    Map<String, dynamic>? metadata,
  }) = _ShareRequest;

  factory ShareRequest.fromJson(Map<String, dynamic> json) =>
      _$ShareRequestFromJson(json);
}

/// Share response model
@freezed
class ShareResponse with _$ShareResponse {
  const factory ShareResponse({
    required String sharedOutfitId,
    required String shareUrl,
    required ShareVisibility visibility,
    required DateTime sharedAt,
    @Default([]) List<String> availablePlatforms,
    Map<String, String>? socialUrls,
  }) = _ShareResponse;

  factory ShareResponse.fromJson(Map<String, dynamic> json) =>
      _$ShareResponseFromJson(json);
}

/// Extensions for outfit sharing
extension SharedOutfitModelExtensions on SharedOutfitModel {
  String get shareUrl => 'https://koutu.app/outfit/$id';
  
  String get formattedLikesCount => _formatCount(likesCount);
  String get formattedCommentsCount => _formatCount(commentsCount);
  String get formattedSharesCount => _formatCount(sharesCount);
  String get formattedViewsCount => _formatCount(viewsCount);
  
  double get engagementRate {
    if (viewsCount == 0) return 0.0;
    return (likesCount + commentsCount + sharesCount) / viewsCount;
  }
  
  bool get isPopular => likesCount > 100 || viewsCount > 1000;
  bool get isTrending => engagementRate > 0.1 && viewsCount > 500;
  bool get isViral => viewsCount > 10000 || sharesCount > 50;
  
  String get shareText => 'Check out this amazing outfit: $title $shareUrl';
  
  String _formatCount(int count) {
    if (count < 1000) return count.toString();
    if (count < 1000000) return '${(count / 1000).toStringAsFixed(1)}K';
    return '${(count / 1000000).toStringAsFixed(1)}M';
  }
}

extension ShareVisibilityExtensions on ShareVisibility {
  String get displayName {
    switch (this) {
      case ShareVisibility.public:
        return 'Public';
      case ShareVisibility.followers:
        return 'Followers';
      case ShareVisibility.friends:
        return 'Friends';
      case ShareVisibility.private:
        return 'Private';
      case ShareVisibility.unlisted:
        return 'Unlisted';
    }
  }
  
  String get description {
    switch (this) {
      case ShareVisibility.public:
        return 'Anyone can see this outfit';
      case ShareVisibility.followers:
        return 'Only your followers can see this outfit';
      case ShareVisibility.friends:
        return 'Only your friends can see this outfit';
      case ShareVisibility.private:
        return 'Only you can see this outfit';
      case ShareVisibility.unlisted:
        return 'Only people with the link can see this outfit';
    }
  }
  
  String get iconName {
    switch (this) {
      case ShareVisibility.public:
        return 'public';
      case ShareVisibility.followers:
        return 'people';
      case ShareVisibility.friends:
        return 'person_add';
      case ShareVisibility.private:
        return 'lock';
      case ShareVisibility.unlisted:
        return 'link';
    }
  }
}

extension InteractionTypeExtensions on InteractionType {
  String get displayName {
    switch (this) {
      case InteractionType.like:
        return 'Like';
      case InteractionType.comment:
        return 'Comment';
      case InteractionType.share:
        return 'Share';
      case InteractionType.save:
        return 'Save';
      case InteractionType.report:
        return 'Report';
      case InteractionType.view:
        return 'View';
      case InteractionType.download:
        return 'Download';
    }
  }
  
  String get iconName {
    switch (this) {
      case InteractionType.like:
        return 'favorite';
      case InteractionType.comment:
        return 'comment';
      case InteractionType.share:
        return 'share';
      case InteractionType.save:
        return 'bookmark';
      case InteractionType.report:
        return 'report';
      case InteractionType.view:
        return 'visibility';
      case InteractionType.download:
        return 'download';
    }
  }
}