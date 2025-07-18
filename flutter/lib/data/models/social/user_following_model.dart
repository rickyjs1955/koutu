import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/social/social_user_model.dart';

part 'user_following_model.freezed.dart';
part 'user_following_model.g.dart';

/// User following/follower relationship model
@freezed
class UserFollowingModel with _$UserFollowingModel {
  const factory UserFollowingModel({
    required String id,
    required String followerId,
    required String followingId,
    required FollowStatus status,
    required DateTime createdAt,
    DateTime? updatedAt,
    DateTime? acceptedAt,
    String? note,
    Map<String, dynamic>? metadata,
    SocialUserModel? follower,
    SocialUserModel? following,
  }) = _UserFollowingModel;

  factory UserFollowingModel.fromJson(Map<String, dynamic> json) =>
      _$UserFollowingModelFromJson(json);
}

/// Follow status enum
enum FollowStatus {
  @JsonValue('pending')
  pending,
  @JsonValue('accepted')
  accepted,
  @JsonValue('blocked')
  blocked,
  @JsonValue('declined')
  declined,
}

/// Follow request model
@freezed
class FollowRequest with _$FollowRequest {
  const factory FollowRequest({
    required String id,
    required String fromUserId,
    required String toUserId,
    required DateTime createdAt,
    String? message,
    Map<String, dynamic>? metadata,
    SocialUserModel? fromUser,
    SocialUserModel? toUser,
  }) = _FollowRequest;

  factory FollowRequest.fromJson(Map<String, dynamic> json) =>
      _$FollowRequestFromJson(json);
}

/// Follow suggestion model
@freezed
class FollowSuggestion with _$FollowSuggestion {
  const factory FollowSuggestion({
    required String id,
    required String userId,
    required String suggestedUserId,
    required double relevanceScore,
    required List<String> reasons,
    required DateTime createdAt,
    @Default(false) bool isDismissed,
    @Default(false) bool isFollowed,
    @Default([]) List<String> mutualFollowers,
    @Default([]) List<String> commonInterests,
    SocialUserModel? suggestedUser,
  }) = _FollowSuggestion;

  factory FollowSuggestion.fromJson(Map<String, dynamic> json) =>
      _$FollowSuggestionFromJson(json);
}

/// Follow activity model
@freezed
class FollowActivity with _$FollowActivity {
  const factory FollowActivity({
    required String id,
    required String userId,
    required String targetUserId,
    required FollowActivityType type,
    required DateTime createdAt,
    Map<String, dynamic>? metadata,
    SocialUserModel? user,
    SocialUserModel? targetUser,
  }) = _FollowActivity;

  factory FollowActivity.fromJson(Map<String, dynamic> json) =>
      _$FollowActivityFromJson(json);
}

/// Follow activity types
enum FollowActivityType {
  @JsonValue('followed')
  followed,
  @JsonValue('unfollowed')
  unfollowed,
  @JsonValue('blocked')
  blocked,
  @JsonValue('unblocked')
  unblocked,
  @JsonValue('request_sent')
  requestSent,
  @JsonValue('request_accepted')
  requestAccepted,
  @JsonValue('request_declined')
  requestDeclined,
}

/// Follow statistics model
@freezed
class FollowStatistics with _$FollowStatistics {
  const factory FollowStatistics({
    required String userId,
    required int followersCount,
    required int followingCount,
    required int pendingRequestsCount,
    required int mutualFollowersCount,
    required DateTime lastUpdated,
    @Default(0) int followersGrowthThisWeek,
    @Default(0) int followingGrowthThisWeek,
    @Default(0) int totalFollowRequests,
    @Default(0) int totalFollowsGiven,
    @Default(0.0) double engagementRate,
    Map<String, dynamic>? analytics,
  }) = _FollowStatistics;

  factory FollowStatistics.fromJson(Map<String, dynamic> json) =>
      _$FollowStatisticsFromJson(json);
}

/// Follow list response model
@freezed
class FollowListResponse with _$FollowListResponse {
  const factory FollowListResponse({
    required List<SocialUserModel> users,
    required int totalCount,
    required int page,
    required int limit,
    required bool hasMore,
    Map<String, dynamic>? metadata,
  }) = _FollowListResponse;

  factory FollowListResponse.fromJson(Map<String, dynamic> json) =>
      _$FollowListResponseFromJson(json);
}

/// Extensions for follow models
extension FollowStatusExtensions on FollowStatus {
  String get displayName {
    switch (this) {
      case FollowStatus.pending:
        return 'Pending';
      case FollowStatus.accepted:
        return 'Following';
      case FollowStatus.blocked:
        return 'Blocked';
      case FollowStatus.declined:
        return 'Declined';
    }
  }

  bool get isActive => this == FollowStatus.accepted;
  bool get isPending => this == FollowStatus.pending;
  bool get isBlocked => this == FollowStatus.blocked;
  bool get isDeclined => this == FollowStatus.declined;

  String get iconName {
    switch (this) {
      case FollowStatus.pending:
        return 'schedule';
      case FollowStatus.accepted:
        return 'check_circle';
      case FollowStatus.blocked:
        return 'block';
      case FollowStatus.declined:
        return 'cancel';
    }
  }
}

extension FollowActivityTypeExtensions on FollowActivityType {
  String get displayName {
    switch (this) {
      case FollowActivityType.followed:
        return 'Followed';
      case FollowActivityType.unfollowed:
        return 'Unfollowed';
      case FollowActivityType.blocked:
        return 'Blocked';
      case FollowActivityType.unblocked:
        return 'Unblocked';
      case FollowActivityType.requestSent:
        return 'Request Sent';
      case FollowActivityType.requestAccepted:
        return 'Request Accepted';
      case FollowActivityType.requestDeclined:
        return 'Request Declined';
    }
  }

  String get iconName {
    switch (this) {
      case FollowActivityType.followed:
        return 'person_add';
      case FollowActivityType.unfollowed:
        return 'person_remove';
      case FollowActivityType.blocked:
        return 'block';
      case FollowActivityType.unblocked:
        return 'check_circle';
      case FollowActivityType.requestSent:
        return 'send';
      case FollowActivityType.requestAccepted:
        return 'check_circle';
      case FollowActivityType.requestDeclined:
        return 'cancel';
    }
  }
}

extension FollowSuggestionExtensions on FollowSuggestion {
  String get primaryReason => reasons.isNotEmpty ? reasons.first : 'Suggested for you';
  
  String get reasonsText {
    if (reasons.isEmpty) return 'Suggested for you';
    if (reasons.length == 1) return reasons.first;
    return '${reasons.first} and ${reasons.length - 1} more';
  }
  
  bool get isHighRelevance => relevanceScore >= 0.8;
  bool get isMediumRelevance => relevanceScore >= 0.5 && relevanceScore < 0.8;
  bool get isLowRelevance => relevanceScore < 0.5;
}

extension FollowStatisticsExtensions on FollowStatistics {
  String get formattedFollowersCount => _formatCount(followersCount);
  String get formattedFollowingCount => _formatCount(followingCount);
  String get formattedMutualFollowersCount => _formatCount(mutualFollowersCount);
  
  double get followingRatio {
    if (followersCount == 0) return 0.0;
    return followingCount / followersCount;
  }
  
  bool get isInfluencer => followersCount > 10000;
  bool get isPopular => followersCount > 1000;
  bool get isActive => engagementRate > 0.05;
  
  String get growthStatus {
    if (followersGrowthThisWeek > 0) return 'Growing';
    if (followersGrowthThisWeek < 0) return 'Declining';
    return 'Stable';
  }
  
  String _formatCount(int count) {
    if (count < 1000) return count.toString();
    if (count < 1000000) return '${(count / 1000).toStringAsFixed(1)}K';
    return '${(count / 1000000).toStringAsFixed(1)}M';
  }
}