import 'package:flutter/foundation.dart';
import 'package:koutu/data/models/social/outfit_sharing_model.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for outfit sharing and social interactions
class OutfitSharingService {
  static const String _baseUrl = 'https://api.koutu.app';
  
  /// Share an outfit
  static Future<Either<Failure, ShareResponse>> shareOutfit(
    ShareRequest request,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final response = ShareResponse(
        sharedOutfitId: 'shared_${DateTime.now().millisecondsSinceEpoch}',
        shareUrl: 'https://koutu.app/outfit/shared_${DateTime.now().millisecondsSinceEpoch}',
        visibility: request.visibility,
        sharedAt: DateTime.now(),
        availablePlatforms: ['instagram', 'twitter', 'facebook', 'pinterest', 'tiktok'],
        socialUrls: {
          'instagram': 'https://instagram.com/share?url=...',
          'twitter': 'https://twitter.com/intent/tweet?url=...',
          'facebook': 'https://facebook.com/sharer.php?u=...',
          'pinterest': 'https://pinterest.com/pin/create/button/?url=...',
        },
      );
      
      return Right(response);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get shared outfits feed
  static Future<Either<Failure, List<SharedOutfitModel>>> getSharedOutfitsFeed({
    String? userId,
    int page = 0,
    int limit = 20,
    String? category,
    List<String>? tags,
    ShareVisibility? visibility,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final outfits = List.generate(limit, (index) {
        final authorIndex = index % 5;
        return SharedOutfitModel(
          id: 'shared_outfit_${page * limit + index}',
          userId: 'user_$authorIndex',
          outfitId: 'outfit_${page * limit + index}',
          title: _generateOutfitTitle(index),
          description: _generateOutfitDescription(index),
          visibility: ShareVisibility.values[index % ShareVisibility.values.length],
          sharedAt: DateTime.now().subtract(Duration(hours: index * 2)),
          tags: _generateTags(index),
          likesCount: 50 + (index * 25),
          commentsCount: 5 + (index * 3),
          sharesCount: 2 + index,
          viewsCount: 500 + (index * 100),
          allowComments: true,
          allowShares: true,
          allowDownloads: index % 3 == 0,
          isPromoted: index % 10 == 0,
          isFeatured: index % 15 == 0,
          author: _generateAuthor(authorIndex),
          metadata: ShareMetadata(
            sharedOn: ['app', 'instagram', 'twitter'],
            analytics: {
              'reach': 1000 + (index * 200),
              'engagement': 0.05 + (index * 0.01),
              'clicks': 25 + (index * 5),
            },
            totalInteractions: 57 + (index * 28),
            uniqueViews: 450 + (index * 90),
            avgViewDuration: 15 + (index * 2),
            viewerCountries: ['US', 'UK', 'CA', 'AU'],
            viewerAgeGroups: ['18-24', '25-34', '35-44'],
          ),
        );
      });
      
      return Right(outfits);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get user's shared outfits
  static Future<Either<Failure, List<SharedOutfitModel>>> getUserSharedOutfits(
    String userId, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final outfits = List.generate(limit, (index) {
        return SharedOutfitModel(
          id: 'user_shared_${userId}_$index',
          userId: userId,
          outfitId: 'outfit_${userId}_$index',
          title: 'My Outfit ${index + 1}',
          description: 'Perfect for ${_getRandomOccasion()}',
          visibility: ShareVisibility.values[index % ShareVisibility.values.length],
          sharedAt: DateTime.now().subtract(Duration(days: index)),
          tags: _generateTags(index),
          likesCount: 20 + (index * 15),
          commentsCount: 2 + (index * 2),
          sharesCount: index,
          viewsCount: 200 + (index * 50),
          allowComments: true,
          allowShares: true,
          allowDownloads: index % 4 == 0,
          metadata: ShareMetadata(
            sharedOn: ['app'],
            totalInteractions: 22 + (index * 17),
            uniqueViews: 180 + (index * 45),
            avgViewDuration: 12 + (index * 3),
          ),
        );
      });
      
      return Right(outfits);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get outfit details
  static Future<Either<Failure, SharedOutfitModel>> getSharedOutfitDetails(
    String sharedOutfitId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final outfit = SharedOutfitModel(
        id: sharedOutfitId,
        userId: 'user_123',
        outfitId: 'outfit_456',
        title: 'Summer Casual Look',
        description: 'Perfect for weekend brunch with friends. Comfortable yet stylish.',
        visibility: ShareVisibility.public,
        sharedAt: DateTime.now().subtract(const Duration(hours: 6)),
        tags: ['summer', 'casual', 'brunch', 'weekend'],
        likesCount: 156,
        commentsCount: 23,
        sharesCount: 8,
        viewsCount: 1240,
        allowComments: true,
        allowShares: true,
        allowDownloads: true,
        isPromoted: false,
        isFeatured: true,
        author: SocialUserModel(
          id: 'user_123',
          email: 'fashionista@example.com',
          username: 'fashionista',
          displayName: 'Fashion Lover',
          bio: 'Sharing my daily outfits and style inspiration',
          followersCount: 2500,
          followingCount: 850,
          postsCount: 145,
          createdAt: DateTime.now().subtract(const Duration(days: 200)),
          updatedAt: DateTime.now().subtract(const Duration(hours: 2)),
          settings: const SocialUserSettings(),
          stats: const SocialUserStats(),
        ),
        metadata: ShareMetadata(
          sharedOn: ['app', 'instagram', 'pinterest'],
          analytics: {
            'reach': 2500,
            'engagement': 0.12,
            'clicks': 78,
            'saves': 34,
            'profile_visits': 12,
          },
          totalInteractions: 187,
          uniqueViews: 1150,
          avgViewDuration: 24,
          viewerCountries: ['US', 'UK', 'CA', 'AU', 'DE'],
          viewerAgeGroups: ['18-24', '25-34', '35-44'],
        ),
      );
      
      return Right(outfit);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Like/unlike an outfit
  static Future<Either<Failure, bool>> toggleOutfitLike(
    String sharedOutfitId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(milliseconds: 500));
      
      // Mock toggle like
      final isLiked = DateTime.now().millisecond % 2 == 0;
      
      return Right(isLiked);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Add comment to outfit
  static Future<Either<Failure, OutfitComment>> addComment(
    String sharedOutfitId,
    String userId,
    String content, {
    String? parentCommentId,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final comment = OutfitComment(
        id: 'comment_${DateTime.now().millisecondsSinceEpoch}',
        userId: userId,
        sharedOutfitId: sharedOutfitId,
        content: content,
        createdAt: DateTime.now(),
        parentCommentId: parentCommentId,
        author: SocialUserModel(
          id: userId,
          email: 'user@example.com',
          username: 'user123',
          displayName: 'User',
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
          settings: const SocialUserSettings(),
          stats: const SocialUserStats(),
        ),
      );
      
      return Right(comment);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get outfit comments
  static Future<Either<Failure, List<OutfitComment>>> getOutfitComments(
    String sharedOutfitId, {
    int page = 0,
    int limit = 20,
    String? parentCommentId,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final comments = List.generate(limit, (index) {
        return OutfitComment(
          id: 'comment_${sharedOutfitId}_$index',
          userId: 'user_$index',
          sharedOutfitId: sharedOutfitId,
          content: _generateCommentContent(index),
          createdAt: DateTime.now().subtract(Duration(hours: index * 2)),
          parentCommentId: parentCommentId,
          likesCount: 5 + (index * 2),
          repliesCount: index % 3,
          author: SocialUserModel(
            id: 'user_$index',
            email: 'user$index@example.com',
            username: 'user$index',
            displayName: 'User $index',
            createdAt: DateTime.now().subtract(Duration(days: 30 + index)),
            updatedAt: DateTime.now().subtract(Duration(hours: index)),
            settings: const SocialUserSettings(),
            stats: const SocialUserStats(),
          ),
        );
      });
      
      return Right(comments);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Save outfit for later
  static Future<Either<Failure, bool>> saveOutfit(
    String sharedOutfitId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(milliseconds: 500));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Report outfit
  static Future<Either<Failure, bool>> reportOutfit(
    String sharedOutfitId,
    String userId,
    String reason,
    String? details,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Update outfit sharing settings
  static Future<Either<Failure, SharedOutfitModel>> updateOutfitSharing(
    String sharedOutfitId,
    String userId,
    Map<String, dynamic> updates,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock updated outfit
      final updatedOutfit = SharedOutfitModel(
        id: sharedOutfitId,
        userId: userId,
        outfitId: 'outfit_456',
        title: updates['title'] ?? 'Updated Outfit',
        description: updates['description'],
        visibility: ShareVisibility.values.firstWhere(
          (v) => v.toString() == 'ShareVisibility.${updates['visibility']}',
          orElse: () => ShareVisibility.public,
        ),
        sharedAt: DateTime.now().subtract(const Duration(hours: 6)),
        updatedAt: DateTime.now(),
        tags: List<String>.from(updates['tags'] ?? []),
        likesCount: 156,
        commentsCount: 23,
        sharesCount: 8,
        viewsCount: 1240,
        allowComments: updates['allowComments'] ?? true,
        allowShares: updates['allowShares'] ?? true,
        allowDownloads: updates['allowDownloads'] ?? false,
      );
      
      return Right(updatedOutfit);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Delete shared outfit
  static Future<Either<Failure, bool>> deleteSharedOutfit(
    String sharedOutfitId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get outfit sharing analytics
  static Future<Either<Failure, ShareMetadata>> getOutfitAnalytics(
    String sharedOutfitId,
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final analytics = ShareMetadata(
        sharedOn: ['app', 'instagram', 'twitter', 'pinterest'],
        analytics: {
          'reach': 2500,
          'engagement': 0.12,
          'clicks': 78,
          'saves': 34,
          'profile_visits': 12,
          'link_clicks': 6,
          'shares_from_post': 8,
          'comments_per_view': 0.018,
          'likes_per_view': 0.126,
        },
        totalInteractions: 187,
        uniqueViews: 1150,
        avgViewDuration: 24,
        viewerCountries: ['US', 'UK', 'CA', 'AU', 'DE', 'FR', 'IT'],
        viewerAgeGroups: ['18-24', '25-34', '35-44', '45-54'],
      );
      
      return Right(analytics);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Helper methods for generating mock data
  static String _generateOutfitTitle(int index) {
    final titles = [
      'Summer Casual Look',
      'Business Meeting Style',
      'Weekend Brunch Outfit',
      'Date Night Special',
      'Gym to Coffee Look',
      'Minimalist Chic',
      'Boho Vibes',
      'Street Style',
      'Elegant Evening',
      'Cozy Fall Look',
    ];
    return titles[index % titles.length];
  }
  
  static String _generateOutfitDescription(int index) {
    final descriptions = [
      'Perfect for sunny days and outdoor activities',
      'Professional yet comfortable for long meetings',
      'Casual but put-together for weekend plans',
      'Romantic and stylish for special occasions',
      'Versatile look that transitions from workout to coffee',
      'Clean lines and neutral tones for effortless style',
      'Free-spirited and comfortable with vintage touches',
      'Urban-inspired with trendy pieces',
      'Sophisticated and timeless for formal events',
      'Cozy layers perfect for autumn weather',
    ];
    return descriptions[index % descriptions.length];
  }
  
  static List<String> _generateTags(int index) {
    final tagSets = [
      ['summer', 'casual', 'comfortable'],
      ['business', 'professional', 'meeting'],
      ['weekend', 'brunch', 'relaxed'],
      ['date', 'evening', 'romantic'],
      ['athleisure', 'versatile', 'active'],
      ['minimalist', 'neutral', 'clean'],
      ['boho', 'vintage', 'artistic'],
      ['street', 'urban', 'trendy'],
      ['elegant', 'formal', 'sophisticated'],
      ['fall', 'cozy', 'layers'],
    ];
    return tagSets[index % tagSets.length];
  }
  
  static SocialUserModel _generateAuthor(int index) {
    final usernames = ['fashionista', 'styleguru', 'trendlover', 'chic_style', 'fashion_forward'];
    final displayNames = ['Fashion Lover', 'Style Guru', 'Trend Setter', 'Chic Style', 'Fashion Forward'];
    final bios = [
      'Sharing my daily outfits and style inspiration',
      'Professional stylist and fashion enthusiast',
      'Always on the lookout for the latest trends',
      'Minimalist style with a touch of elegance',
      'Helping others discover their personal style',
    ];
    
    return SocialUserModel(
      id: 'user_$index',
      email: '${usernames[index % usernames.length]}@example.com',
      username: usernames[index % usernames.length],
      displayName: displayNames[index % displayNames.length],
      bio: bios[index % bios.length],
      followersCount: 1000 + (index * 500),
      followingCount: 500 + (index * 200),
      postsCount: 50 + (index * 25),
      createdAt: DateTime.now().subtract(Duration(days: 200 + (index * 30))),
      updatedAt: DateTime.now().subtract(Duration(hours: index * 2)),
      settings: const SocialUserSettings(),
      stats: const SocialUserStats(),
    );
  }
  
  static String _generateCommentContent(int index) {
    final comments = [
      'Love this outfit! 😍',
      'Where did you get that top?',
      'Such a great color combination!',
      'This is giving me major style inspiration',
      'Perfect for the season!',
      'You have such great taste!',
      'I need to recreate this look',
      'The accessories are perfect',
      'This is exactly what I was looking for',
      'Amazing styling as always!',
    ];
    return comments[index % comments.length];
  }
  
  static String _getRandomOccasion() {
    final occasions = ['work', 'weekend', 'date night', 'brunch', 'travel', 'shopping', 'dinner'];
    final random = DateTime.now().millisecond % occasions.length;
    return occasions[random];
  }
}