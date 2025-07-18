import 'package:flutter/foundation.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for social authentication and user management
class SocialAuthService {
  static const String _baseUrl = 'https://api.koutu.app';
  
  /// Sign in with Google
  static Future<Either<Failure, SocialAuthResult>> signInWithGoogle() async {
    try {
      // Mock implementation - in real app, use google_sign_in package
      await Future.delayed(const Duration(seconds: 2));
      
      final result = SocialAuthResult(
        provider: SocialAuthProvider.google,
        providerId: 'google_123456789',
        accessToken: 'google_access_token_12345',
        refreshToken: 'google_refresh_token_12345',
        email: 'user@gmail.com',
        displayName: 'John Doe',
        photoUrl: 'https://lh3.googleusercontent.com/a/default-user=s96-c',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
        additionalData: {
          'locale': 'en_US',
          'verified_email': true,
        },
      );
      
      return Right(result);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Sign in with Facebook
  static Future<Either<Failure, SocialAuthResult>> signInWithFacebook() async {
    try {
      // Mock implementation - in real app, use flutter_facebook_auth package
      await Future.delayed(const Duration(seconds: 2));
      
      final result = SocialAuthResult(
        provider: SocialAuthProvider.facebook,
        providerId: 'facebook_123456789',
        accessToken: 'facebook_access_token_12345',
        email: 'user@facebook.com',
        displayName: 'Jane Smith',
        photoUrl: 'https://graph.facebook.com/123456789/picture',
        expiresAt: DateTime.now().add(const Duration(hours: 2)),
        additionalData: {
          'age_range': {'min': 21},
          'gender': 'female',
        },
      );
      
      return Right(result);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Sign in with Apple
  static Future<Either<Failure, SocialAuthResult>> signInWithApple() async {
    try {
      // Mock implementation - in real app, use sign_in_with_apple package
      await Future.delayed(const Duration(seconds: 2));
      
      final result = SocialAuthResult(
        provider: SocialAuthProvider.apple,
        providerId: 'apple_123456789',
        accessToken: 'apple_access_token_12345',
        email: 'user@privaterelay.appleid.com',
        displayName: 'Apple User',
        expiresAt: DateTime.now().add(const Duration(hours: 24)),
        additionalData: {
          'is_private_email': true,
        },
      );
      
      return Right(result);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Sign in with Instagram
  static Future<Either<Failure, SocialAuthResult>> signInWithInstagram() async {
    try {
      // Mock implementation - in real app, use Instagram Basic Display API
      await Future.delayed(const Duration(seconds: 2));
      
      final result = SocialAuthResult(
        provider: SocialAuthProvider.instagram,
        providerId: 'instagram_123456789',
        accessToken: 'instagram_access_token_12345',
        displayName: 'Fashion Lover',
        photoUrl: 'https://scontent.cdninstagram.com/v/t51.2885-19/s150x150/profile.jpg',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
        additionalData: {
          'account_type': 'PERSONAL',
          'media_count': 150,
        },
      );
      
      return Right(result);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Sign in with Twitter
  static Future<Either<Failure, SocialAuthResult>> signInWithTwitter() async {
    try {
      // Mock implementation - in real app, use Twitter API
      await Future.delayed(const Duration(seconds: 2));
      
      final result = SocialAuthResult(
        provider: SocialAuthProvider.twitter,
        providerId: 'twitter_123456789',
        accessToken: 'twitter_access_token_12345',
        displayName: 'Style Enthusiast',
        photoUrl: 'https://pbs.twimg.com/profile_images/123456789/profile_normal.jpg',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
        additionalData: {
          'followers_count': 500,
          'following_count': 300,
        },
      );
      
      return Right(result);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Create social user account
  static Future<Either<Failure, SocialUserModel>> createSocialUser(
    SocialAuthResult authResult,
    String username,
    String displayName,
    String? bio,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      final user = SocialUserModel(
        id: 'user_${DateTime.now().millisecondsSinceEpoch}',
        email: authResult.email ?? '',
        username: username,
        displayName: displayName,
        bio: bio,
        avatarImage: authResult.photoUrl != null
            ? ImageModel(
                id: 'avatar_${DateTime.now().millisecondsSinceEpoch}',
                url: authResult.photoUrl!,
                thumbnailUrl: authResult.photoUrl!,
                width: 256,
                height: 256,
                fileSize: 50000,
                mimeType: 'image/jpeg',
                createdAt: DateTime.now(),
              )
            : null,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
        settings: const SocialUserSettings(),
        stats: const SocialUserStats(),
      );
      
      return Right(user);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Link social account to existing user
  static Future<Either<Failure, bool>> linkSocialAccount(
    String userId,
    SocialAuthResult authResult,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock success
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Unlink social account
  static Future<Either<Failure, bool>> unlinkSocialAccount(
    String userId,
    SocialAuthProvider provider,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock success
      return const Right(true);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get linked social accounts
  static Future<Either<Failure, List<SocialAuthProvider>>> getLinkedAccounts(
    String userId,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock linked accounts
      final linkedAccounts = [
        SocialAuthProvider.google,
        SocialAuthProvider.instagram,
      ];
      
      return Right(linkedAccounts);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Update user profile
  static Future<Either<Failure, SocialUserModel>> updateProfile(
    String userId,
    Map<String, dynamic> updates,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock updated user
      final updatedUser = SocialUserModel(
        id: userId,
        email: updates['email'] ?? 'user@example.com',
        username: updates['username'] ?? 'user123',
        displayName: updates['displayName'] ?? 'User',
        bio: updates['bio'],
        location: updates['location'],
        website: updates['website'],
        createdAt: DateTime.now().subtract(const Duration(days: 30)),
        updatedAt: DateTime.now(),
        interests: List<String>.from(updates['interests'] ?? []),
        favoriteColors: List<String>.from(updates['favoriteColors'] ?? []),
        favoriteStyles: List<String>.from(updates['favoriteStyles'] ?? []),
        favoriteBrands: List<String>.from(updates['favoriteBrands'] ?? []),
        settings: const SocialUserSettings(),
        stats: const SocialUserStats(),
      );
      
      return Right(updatedUser);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Update user settings
  static Future<Either<Failure, SocialUserSettings>> updateSettings(
    String userId,
    SocialUserSettings settings,
  ) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      return Right(settings);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Search users
  static Future<Either<Failure, List<UserSearchResult>>> searchUsers(
    String query, {
    int page = 0,
    int limit = 20,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock search results
      final results = List.generate(10, (index) {
        final user = SocialUserModel(
          id: 'user_search_$index',
          email: 'user$index@example.com',
          username: 'user$index',
          displayName: 'User $index',
          bio: 'Fashion enthusiast and style blogger',
          followersCount: 1000 + (index * 100),
          followingCount: 500 + (index * 50),
          postsCount: 50 + (index * 10),
          createdAt: DateTime.now().subtract(Duration(days: 365 - (index * 30))),
          updatedAt: DateTime.now().subtract(Duration(days: index)),
          interests: ['fashion', 'style', 'shopping'],
          favoriteColors: ['black', 'white', 'blue'],
          isVerified: index % 3 == 0,
          settings: const SocialUserSettings(),
          stats: const SocialUserStats(),
        );
        
        return UserSearchResult(
          user: user,
          matchScore: 0.9 - (index * 0.05),
          matchReasons: [
            'Username match',
            'Similar interests',
            'Location match',
          ],
          relationshipStatus: RelationshipStatus.none,
          mutualFollowers: [],
          commonInterests: ['fashion', 'style'],
        );
      });
      
      return Right(results);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Get user suggestions
  static Future<Either<Failure, List<UserSearchResult>>> getUserSuggestions(
    String userId, {
    int limit = 10,
  }) async {
    try {
      await Future.delayed(const Duration(seconds: 1));
      
      // Mock suggestions
      final suggestions = List.generate(5, (index) {
        final user = SocialUserModel(
          id: 'suggested_user_$index',
          email: 'suggested$index@example.com',
          username: 'suggested$index',
          displayName: 'Suggested User $index',
          bio: 'Fashion influencer and style inspiration',
          followersCount: 5000 + (index * 1000),
          followingCount: 1000 + (index * 200),
          postsCount: 200 + (index * 50),
          createdAt: DateTime.now().subtract(Duration(days: 200 + (index * 10))),
          updatedAt: DateTime.now().subtract(Duration(hours: index * 2)),
          interests: ['fashion', 'luxury', 'sustainability'],
          favoriteColors: ['gold', 'silver', 'rose'],
          isVerified: true,
          settings: const SocialUserSettings(),
          stats: const SocialUserStats(),
        );
        
        return UserSearchResult(
          user: user,
          matchScore: 0.85 - (index * 0.03),
          matchReasons: [
            'Similar style preferences',
            'Mutual followers',
            'Active user',
          ],
          relationshipStatus: RelationshipStatus.none,
          mutualFollowers: ['mutual_user_1', 'mutual_user_2'],
          commonInterests: ['fashion', 'sustainability'],
        );
      });
      
      return Right(suggestions);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Check username availability
  static Future<Either<Failure, bool>> checkUsernameAvailability(
    String username,
  ) async {
    try {
      await Future.delayed(const Duration(milliseconds: 500));
      
      // Mock availability check
      final unavailableUsernames = [
        'admin', 'user', 'test', 'demo', 'fashion', 'style', 'outfit'
      ];
      
      final isAvailable = !unavailableUsernames.contains(username.toLowerCase());
      
      return Right(isAvailable);
    } catch (e) {
      return Left(ServerFailure(e.toString()));
    }
  }
  
  /// Validate social profile data
  static Either<Failure, bool> validateProfileData({
    required String username,
    required String displayName,
    String? bio,
    String? website,
  }) {
    try {
      // Username validation
      if (username.length < 3 || username.length > 30) {
        return Left(ValidationFailure('Username must be between 3 and 30 characters'));
      }
      
      if (!RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(username)) {
        return Left(ValidationFailure('Username can only contain letters, numbers, and underscores'));
      }
      
      // Display name validation
      if (displayName.length < 1 || displayName.length > 50) {
        return Left(ValidationFailure('Display name must be between 1 and 50 characters'));
      }
      
      // Bio validation
      if (bio != null && bio.length > 160) {
        return Left(ValidationFailure('Bio must be 160 characters or less'));
      }
      
      // Website validation
      if (website != null && website.isNotEmpty) {
        final uri = Uri.tryParse(website);
        if (uri == null || !uri.hasScheme || !uri.hasAuthority) {
          return Left(ValidationFailure('Please enter a valid website URL'));
        }
      }
      
      return const Right(true);
    } catch (e) {
      return Left(ValidationFailure(e.toString()));
    }
  }
}

/// Mock data for development
class MockSocialData {
  static SocialUserModel get currentUser => SocialUserModel(
    id: 'current_user_123',
    email: 'currentuser@example.com',
    username: 'fashionista',
    displayName: 'Fashion Enthusiast',
    bio: 'Sustainable fashion advocate | Style blogger | Vintage lover',
    location: 'New York, NY',
    website: 'https://fashionista.blog',
    followersCount: 2450,
    followingCount: 890,
    postsCount: 156,
    likesCount: 12500,
    createdAt: DateTime.now().subtract(const Duration(days: 365)),
    updatedAt: DateTime.now(),
    interests: ['sustainable fashion', 'vintage', 'minimalism', 'thrifting'],
    favoriteColors: ['black', 'white', 'beige', 'olive'],
    favoriteStyles: ['minimalist', 'vintage', 'casual'],
    favoriteBrands: ['Everlane', 'Reformation', 'Patagonia'],
    isVerified: true,
    settings: const SocialUserSettings(
      allowFollowing: true,
      allowComments: true,
      requireFollowApproval: false,
      notifications: NotificationSettings(
        likes: true,
        comments: true,
        follows: true,
        mentions: true,
      ),
      privacy: PrivacySettings(
        profileVisibility: ProfileVisibility.public,
        defaultPostVisibility: PostVisibility.public,
      ),
    ),
    stats: SocialUserStats(
      totalOutfits: 89,
      totalGarments: 245,
      totalWardrobes: 8,
      totalLikesReceived: 12500,
      totalCommentsReceived: 1850,
      totalShares: 456,
      totalViews: 45000,
      challengesWon: 3,
      challengesParticipated: 12,
      streak: 7,
      lastActive: DateTime.now().subtract(const Duration(minutes: 30)),
    ),
  );
}