import 'package:flutter/foundation.dart';
import 'package:koutu/data/models/social/user_following_model.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for managing user following relationships
class UserFollowingService {
  static const String _baseUrl = 'https://api.koutu.app';
  
  /// Follow a user
  static Future<Either<Failure, UserFollowingModel>> followUser(
    String userId,
    String targetUserId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Check if target user requires approval
      final requiresApproval = targetUserId.hashCode % 3 == 0; // Mock logic
      
      final follow = UserFollowingModel(
        id: 'follow_${DateTime.now().millisecondsSinceEpoch}',
        followerId: userId,
        followingId: targetUserId,
        status: requiresApproval ? FollowStatus.pending : FollowStatus.accepted,
        createdAt: DateTime.now(),
        acceptedAt: requiresApproval ? null : DateTime.now(),
        following: _generateMockUser(targetUserId),
      );
      
      return Right(follow);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Unfollow a user
  static Future<Either<Failure, bool>> unfollowUser(
    String userId,
    String targetUserId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Block a user
  static Future<Either<Failure, bool>> blockUser(
    String userId,
    String targetUserId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Unblock a user
  static Future<Either<Failure, bool>> unblockUser(
    String userId,
    String targetUserId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get user's followers
  static Future<Either<Failure, FollowListResponse>> getFollowers(
    String userId, {
    int page = 0,
    int limit = 20,
    String? search,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final followers = List.generate(limit, (index) {
        return _generateMockUser('follower_${userId}_${page * limit + index}');
      });
      
      final response = FollowListResponse(
        users: followers,
        totalCount: 1250 + (userId.hashCode % 5000),
        page: page,
        limit: limit,
        hasMore: page < 10, // Mock pagination
      );
      
      return Right(response);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get user's following
  static Future<Either<Failure, FollowListResponse>> getFollowing(
    String userId, {
    int page = 0,
    int limit = 20,
    String? search,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final following = List.generate(limit, (index) {
        return _generateMockUser('following_${userId}_${page * limit + index}');
      });
      
      final response = FollowListResponse(
        users: following,
        totalCount: 450 + (userId.hashCode % 2000),
        page: page,
        limit: limit,
        hasMore: page < 5, // Mock pagination
      );
      
      return Right(response);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get mutual followers
  static Future<Either<Failure, FollowListResponse>> getMutualFollowers(
    String userId,
    String targetUserId, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final mutualFollowers = List.generate(limit, (index) {
        return _generateMockUser('mutual_${userId}_${targetUserId}_${page * limit + index}');
      });
      
      final response = FollowListResponse(
        users: mutualFollowers,
        totalCount: 25 + (userId.hashCode % 100),
        page: page,
        limit: limit,
        hasMore: page < 2, // Mock pagination
      );
      
      return Right(response);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get follow requests
  static Future<Either<Failure, List<FollowRequest>>> getFollowRequests(
    String userId, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final requests = List.generate(limit, (index) {
        return FollowRequest(
          id: 'request_${DateTime.now().millisecondsSinceEpoch}_$index',
          fromUserId: 'user_request_$index',
          toUserId: userId,
          createdAt: DateTime.now().subtract(Duration(hours: index * 2)),
          message: index % 3 == 0 ? 'Hi! I love your style!' : null,
          fromUser: _generateMockUser('user_request_$index'),
        );
      });
      
      return Right(requests);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Accept follow request
  static Future<Either<Failure, bool>> acceptFollowRequest(
    String requestId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Decline follow request
  static Future<Either<Failure, bool>> declineFollowRequest(
    String requestId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get follow suggestions
  static Future<Either<Failure, List<FollowSuggestion>>> getFollowSuggestions(
    String userId, {
    int limit = 10,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final suggestions = List.generate(limit, (index) {
        final reasons = _generateSuggestionReasons(index);
        return FollowSuggestion(
          id: 'suggestion_${DateTime.now().millisecondsSinceEpoch}_$index',
          userId: userId,
          suggestedUserId: 'suggested_user_$index',
          relevanceScore: 0.9 - (index * 0.08),
          reasons: reasons,
          createdAt: DateTime.now().subtract(Duration(hours: index)),
          mutualFollowers: _generateMutualFollowers(index),
          commonInterests: _generateCommonInterests(index),
          suggestedUser: _generateMockUser('suggested_user_$index'),
        );
      });
      
      return Right(suggestions);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get follow statistics
  static Future<Either<Failure, FollowStatistics>> getFollowStatistics(
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final stats = FollowStatistics(
        userId: userId,
        followersCount: 1250 + (userId.hashCode % 5000),
        followingCount: 450 + (userId.hashCode % 2000),
        pendingRequestsCount: 5 + (userId.hashCode % 20),
        mutualFollowersCount: 25 + (userId.hashCode % 100),
        lastUpdated: DateTime.now(),
        followersGrowthThisWeek: 15 + (userId.hashCode % 50),
        followingGrowthThisWeek: 5 + (userId.hashCode % 20),
        totalFollowRequests: 100 + (userId.hashCode % 500),
        totalFollowsGiven: 500 + (userId.hashCode % 2000),
        engagementRate: 0.05 + (userId.hashCode % 15) / 100,
        analytics: {
          'avg_followers_per_day': 2.5,
          'avg_following_per_day': 1.2,
          'follow_back_rate': 0.65,
          'unfollow_rate': 0.08,
          'block_rate': 0.02,
        },
      );
      
      return Right(stats);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get follow relationship status
  static Future<Either<Failure, RelationshipStatus>> getRelationshipStatus(
    String userId,
    String targetUserId,
  ) async {
    try {
      await Future.delayed(const Duration(milliseconds: 500));
      
      // Mock relationship status
      final statuses = [
        RelationshipStatus.none,
        RelationshipStatus.following,
        RelationshipStatus.follower,
        RelationshipStatus.mutual,
      ];
      
      final status = statuses[targetUserId.hashCode % statuses.length];
      
      return Right(status);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Search users to follow
  static Future<Either<Failure, List<SocialUserModel>>> searchUsersToFollow(
    String query,
    String userId, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final users = List.generate(limit, (index) {
        return _generateMockUser('search_${query}_$index');
      });
      
      return Right(users);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get follow activity
  static Future<Either<Failure, List<FollowActivity>>> getFollowActivity(
    String userId, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final activities = List.generate(limit, (index) {
        final types = FollowActivityType.values;
        return FollowActivity(
          id: 'activity_${DateTime.now().millisecondsSinceEpoch}_$index',
          userId: userId,
          targetUserId: 'target_user_$index',
          type: types[index % types.length],
          createdAt: DateTime.now().subtract(Duration(hours: index * 2)),
          user: _generateMockUser(userId),
          targetUser: _generateMockUser('target_user_$index'),
        );
      });
      
      return Right(activities);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Remove follower
  static Future<Either<Failure, bool>> removeFollower(
    String userId,
    String followerId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Update follow settings
  static Future<Either<Failure, bool>> updateFollowSettings(
    String userId,
    Map<String, dynamic> settings,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Helper methods for generating mock data
  static SocialUserModel _generateMockUser(String userId) {
    final usernames = ['fashionista', 'styleguru', 'trendlover', 'chic_style', 'fashion_forward'];
    final displayNames = ['Fashion Lover', 'Style Guru', 'Trend Setter', 'Chic Style', 'Fashion Forward'];
    final bios = [
      'Sharing my daily outfits and style inspiration',
      'Professional stylist and fashion enthusiast',
      'Always on the lookout for the latest trends',
      'Minimalist style with a touch of elegance',
      'Helping others discover their personal style',
    ];
    
    final index = userId.hashCode % usernames.length;
    
    return SocialUserModel(
      id: userId,
      email: '${usernames[index]}@example.com',
      username: usernames[index],
      displayName: displayNames[index],
      bio: bios[index],
      followersCount: 1000 + (userId.hashCode % 10000),
      followingCount: 500 + (userId.hashCode % 5000),
      postsCount: 50 + (userId.hashCode % 200),
      createdAt: DateTime.now().subtract(Duration(days: 200 + (userId.hashCode % 500))),
      updatedAt: DateTime.now().subtract(Duration(hours: userId.hashCode % 24)),
      interests: _generateInterests(index),
      isVerified: userId.hashCode % 10 == 0,
      settings: const SocialUserSettings(),
      stats: const SocialUserStats(),
    );
  }
  
  static List<String> _generateSuggestionReasons(int index) {
    final reasonSets = [
      ['Followed by friends', 'Similar interests'],
      ['Popular in your area', 'Fashion influencer'],
      ['Mutual connections', 'Active user'],
      ['Similar style', 'Trending creator'],
      ['Recommended for you', 'High engagement'],
    ];
    
    return reasonSets[index % reasonSets.length];
  }
  
  static List<String> _generateMutualFollowers(int index) {
    return List.generate(3 + (index % 5), (i) => 'mutual_user_${index}_$i');
  }
  
  static List<String> _generateCommonInterests(int index) {
    final interestSets = [
      ['fashion', 'style', 'minimalism'],
      ['streetwear', 'sneakers', 'urban'],
      ['vintage', 'thrifting', 'sustainability'],
      ['luxury', 'designer', 'high-end'],
      ['casual', 'comfort', 'everyday'],
    ];
    
    return interestSets[index % interestSets.length];
  }
  
  static List<String> _generateInterests(int index) {
    final interestSets = [
      ['fashion', 'style', 'minimalism', 'sustainable fashion'],
      ['streetwear', 'sneakers', 'urban style', 'hip-hop'],
      ['vintage', 'thrifting', 'sustainability', 'retro'],
      ['luxury', 'designer', 'high-end', 'couture'],
      ['casual', 'comfort', 'everyday', 'athleisure'],
    ];
    
    return interestSets[index % interestSets.length];
  }
}