import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/services/social/social_auth_service.dart';
import 'package:go_router/go_router.dart';

/// Social profile screen for viewing and editing user profiles
class SocialProfileScreen extends StatefulWidget {
  final String? userId;
  final bool isCurrentUser;
  
  const SocialProfileScreen({
    super.key,
    this.userId,
    this.isCurrentUser = false,
  });

  @override
  State<SocialProfileScreen> createState() => _SocialProfileScreenState();
}

class _SocialProfileScreenState extends State<SocialProfileScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  
  SocialUserModel? _user;
  RelationshipStatus _relationshipStatus = RelationshipStatus.none;
  bool _isLoading = true;
  bool _isFollowing = false;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _loadUserProfile();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }
  
  void _loadUserProfile() async {
    setState(() => _isLoading = true);
    
    try {
      // Mock loading user profile
      await Future.delayed(const Duration(seconds: 1));
      
      if (widget.isCurrentUser) {
        _user = MockSocialData.currentUser;
      } else {
        _user = SocialUserModel(
          id: widget.userId ?? 'user_123',
          email: 'user@example.com',
          username: 'stylish_user',
          displayName: 'Stylish User',
          bio: 'Fashion lover | Style inspiration | Minimalist wardrobe',
          location: 'San Francisco, CA',
          website: 'https://stylishuser.com',
          followersCount: 1250,
          followingCount: 450,
          postsCount: 89,
          likesCount: 5600,
          createdAt: DateTime.now().subtract(const Duration(days: 200)),
          updatedAt: DateTime.now().subtract(const Duration(hours: 2)),
          interests: ['fashion', 'minimalism', 'sustainable living'],
          favoriteColors: ['black', 'white', 'grey', 'navy'],
          favoriteStyles: ['minimalist', 'casual', 'professional'],
          favoriteBrands: ['COS', 'Uniqlo', 'Everlane'],
          isVerified: false,
          settings: const SocialUserSettings(),
          stats: const SocialUserStats(
            totalOutfits: 45,
            totalGarments: 120,
            totalWardrobes: 5,
            totalLikesReceived: 5600,
            totalCommentsReceived: 890,
            totalShares: 234,
            totalViews: 15000,
            challengesWon: 1,
            challengesParticipated: 6,
            streak: 3,
          ),
        );
      }
      
      // Mock relationship status
      _relationshipStatus = widget.isCurrentUser 
          ? RelationshipStatus.none 
          : RelationshipStatus.none;
      _isFollowing = _relationshipStatus.isFollowing;
      
    } catch (e) {
      // Handle error
      debugPrint('Error loading user profile: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onFollowTap() async {
    if (_user == null) return;
    
    setState(() => _isLoading = true);
    
    try {
      // Mock follow/unfollow
      await Future.delayed(const Duration(seconds: 1));
      
      setState(() {
        _isFollowing = !_isFollowing;
        if (_isFollowing) {
          _relationshipStatus = RelationshipStatus.following;
          _user = _user!.copyWith(
            followersCount: _user!.followersCount + 1,
          );
        } else {
          _relationshipStatus = RelationshipStatus.none;
          _user = _user!.copyWith(
            followersCount: _user!.followersCount - 1,
          );
        }
      });
    } catch (e) {
      // Handle error
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onMessageTap() {
    // TODO: Navigate to messages
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Messages coming soon')),
    );
  }
  
  void _onEditProfileTap() {
    context.push('/profile/edit');
  }
  
  void _onSettingsTap() {
    context.push('/profile/settings');
  }
  
  void _onShareProfileTap() {
    // TODO: Implement profile sharing
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Profile shared')),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    if (_isLoading && _user == null) {
      return Scaffold(
        appBar: AppCustomAppBar(
          title: widget.isCurrentUser ? 'My Profile' : 'Profile',
        ),
        body: const Center(
          child: AppLoadingIndicator(),
        ),
      );
    }
    
    if (_user == null) {
      return Scaffold(
        appBar: AppCustomAppBar(
          title: 'Profile',
        ),
        body: const Center(
          child: Text('User not found'),
        ),
      );
    }
    
    return Scaffold(
      body: NestedScrollView(
        headerSliverBuilder: (context, innerBoxIsScrolled) {
          return [
            _buildSliverAppBar(),
            _buildProfileHeader(),
            _buildTabBar(),
          ];
        },
        body: TabBarView(
          controller: _tabController,
          children: [
            _buildOutfitsTab(),
            _buildGarmentsTab(),
            _buildLikesTab(),
            _buildAboutTab(),
          ],
        ),
      ),
    );
  }
  
  Widget _buildSliverAppBar() {
    return SliverAppBar(
      expandedHeight: 200,
      pinned: true,
      backgroundColor: AppColors.surface,
      flexibleSpace: FlexibleSpaceBar(
        background: _user!.hasCoverImage
            ? CachedNetworkImage(
                imageUrl: _user!.coverImageUrl,
                fit: BoxFit.cover,
                placeholder: (context, url) => Container(
                  color: AppColors.backgroundSecondary,
                  child: const Center(
                    child: AppLoadingIndicator(),
                  ),
                ),
              )
            : Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      AppColors.primary.withOpacity(0.8),
                      AppColors.primary.withOpacity(0.4),
                    ],
                  ),
                ),
              ),
      ),
      actions: [
        if (widget.isCurrentUser)
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: _onSettingsTap,
          )
        else
          IconButton(
            icon: const Icon(Icons.share),
            onPressed: _onShareProfileTap,
          ),
        if (widget.isCurrentUser)
          IconButton(
            icon: const Icon(Icons.edit),
            onPressed: _onEditProfileTap,
          ),
      ],
    );
  }
  
  Widget _buildProfileHeader() {
    return SliverToBoxAdapter(
      child: Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          children: [
            // Profile image and basic info
            Row(
              children: [
                // Profile image
                Container(
                  width: 80,
                  height: 80,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: AppColors.surface,
                      width: 4,
                    ),
                  ),
                  child: CircleAvatar(
                    radius: 36,
                    backgroundColor: AppColors.backgroundSecondary,
                    backgroundImage: _user!.hasProfileImage
                        ? CachedNetworkImageProvider(_user!.profileImageUrl)
                        : null,
                    child: !_user!.hasProfileImage
                        ? Text(
                            _user!.displayName.isNotEmpty
                                ? _user!.displayName[0].toUpperCase()
                                : _user!.username[0].toUpperCase(),
                            style: AppTextStyles.h2.copyWith(
                              color: AppColors.textPrimary,
                            ),
                          )
                        : null,
                  ),
                ),
                
                const SizedBox(width: AppDimensions.paddingL),
                
                // Name and verification
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              _user!.displayName,
                              style: AppTextStyles.h2,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (_user!.isVerified)
                            Icon(
                              Icons.verified,
                              color: AppColors.primary,
                              size: 20,
                            ),
                        ],
                      ),
                      Text(
                        '@${_user!.username}',
                        style: AppTextStyles.bodyMedium.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                      if (_user!.location != null) ...[\n                        const SizedBox(height: 4),\n                        Row(\n                          children: [\n                            Icon(\n                              Icons.location_on,\n                              size: 16,\n                              color: AppColors.textSecondary,\n                            ),\n                            const SizedBox(width: 4),\n                            Text(\n                              _user!.location!,\n                              style: AppTextStyles.caption.copyWith(\n                                color: AppColors.textSecondary,\n                              ),\n                            ),\n                          ],\n                        ),\n                      ],
                    ],
                  ),
                ),
              ],
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Bio
            if (_user!.bio != null && _user!.bio!.isNotEmpty)
              Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  _user!.bio!,
                  style: AppTextStyles.bodyMedium,
                ),
              ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Website
            if (_user!.website != null && _user!.website!.isNotEmpty)
              Align(
                alignment: Alignment.centerLeft,
                child: InkWell(
                  onTap: () {
                    // TODO: Launch URL
                  },
                  child: Text(
                    _user!.website!,
                    style: AppTextStyles.bodyMedium.copyWith(
                      color: AppColors.primary,
                      decoration: TextDecoration.underline,
                    ),
                  ),
                ),
              ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Stats
            Row(
              children: [
                _buildStatItem('Posts', _user!.formattedPostsCount),
                _buildStatItem('Followers', _user!.formattedFollowersCount),
                _buildStatItem('Following', _user!.formattedFollowingCount),
                _buildStatItem('Likes', _user!.formattedLikesCount),
              ],
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Action buttons
            if (!widget.isCurrentUser)
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _isLoading ? null : _onFollowTap,
                      icon: Icon(_isFollowing ? Icons.person_remove : Icons.person_add),
                      label: Text(_isFollowing ? 'Unfollow' : 'Follow'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: _isFollowing ? AppColors.backgroundSecondary : AppColors.primary,
                        foregroundColor: _isFollowing ? AppColors.textPrimary : Colors.white,
                      ),
                    ),
                  ),
                  const SizedBox(width: AppDimensions.paddingM),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _onMessageTap,
                      icon: const Icon(Icons.message),
                      label: const Text('Message'),
                    ),
                  ),
                ],
              ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildStatItem(String label, String value) {
    return Expanded(
      child: Column(
        children: [
          Text(
            value,
            style: AppTextStyles.h3,
          ),
          Text(
            label,
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildTabBar() {
    return SliverPersistentHeader(
      pinned: true,
      delegate: _SliverTabBarDelegate(
        TabBar(
          controller: _tabController,
          labelColor: AppColors.primary,
          unselectedLabelColor: AppColors.textSecondary,
          indicatorColor: AppColors.primary,
          tabs: const [
            Tab(text: 'Outfits'),
            Tab(text: 'Garments'),
            Tab(text: 'Likes'),
            Tab(text: 'About'),
          ],
        ),
      ),
    );
  }
  
  Widget _buildOutfitsTab() {
    return GridView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: AppDimensions.paddingS,
        mainAxisSpacing: AppDimensions.paddingS,
        childAspectRatio: 0.8,
      ),
      itemCount: _user!.stats?.totalOutfits ?? 0,
      itemBuilder: (context, index) {
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: Card(
            clipBehavior: Clip.antiAlias,
            child: Stack(
              children: [
                Container(
                  decoration: BoxDecoration(
                    color: AppColors.backgroundSecondary,
                  ),
                  child: Center(
                    child: Icon(
                      Icons.checkroom,
                      size: 48,
                      color: AppColors.textTertiary,
                    ),
                  ),
                ),
                Positioned(
                  bottom: 0,
                  left: 0,
                  right: 0,
                  child: Container(
                    padding: const EdgeInsets.all(AppDimensions.paddingS),
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [
                          Colors.transparent,
                          Colors.black.withOpacity(0.7),
                        ],
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Outfit ${index + 1}',
                          style: AppTextStyles.labelMedium.copyWith(
                            color: Colors.white,
                          ),
                        ),
                        Row(
                          children: [
                            Icon(
                              Icons.favorite,
                              size: 16,
                              color: Colors.white,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              '${15 + index}',
                              style: AppTextStyles.caption.copyWith(
                                color: Colors.white,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
  
  Widget _buildGarmentsTab() {
    return GridView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        crossAxisSpacing: AppDimensions.paddingXS,
        mainAxisSpacing: AppDimensions.paddingXS,
        childAspectRatio: 1,
      ),
      itemCount: _user!.stats?.totalGarments ?? 0,
      itemBuilder: (context, index) {
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 30),
          child: Card(
            clipBehavior: Clip.antiAlias,
            child: Container(
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
              ),
              child: Center(
                child: Icon(
                  Icons.checkroom,
                  size: 32,
                  color: AppColors.textTertiary,
                ),
              ),
            ),
          ),
        );
      },
    );
  }
  
  Widget _buildLikesTab() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.favorite_outline,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Liked Posts',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Posts liked by ${_user!.displayName} will appear here',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Widget _buildAboutTab() {
    return ListView(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      children: [
        if (_user!.interests.isNotEmpty) ...[\n          _buildAboutSection(\n            'Interests',\n            Icons.interests,\n            _user!.interests,\n          ),\n          const SizedBox(height: AppDimensions.paddingL),\n        ],\n        \n        if (_user!.favoriteColors.isNotEmpty) ...[\n          _buildAboutSection(\n            'Favorite Colors',\n            Icons.palette,\n            _user!.favoriteColors,\n          ),\n          const SizedBox(height: AppDimensions.paddingL),\n        ],\n        \n        if (_user!.favoriteStyles.isNotEmpty) ...[\n          _buildAboutSection(\n            'Favorite Styles',\n            Icons.style,\n            _user!.favoriteStyles,\n          ),\n          const SizedBox(height: AppDimensions.paddingL),\n        ],\n        \n        if (_user!.favoriteBrands.isNotEmpty) ...[\n          _buildAboutSection(\n            'Favorite Brands',\n            Icons.business,\n            _user!.favoriteBrands,\n          ),\n          const SizedBox(height: AppDimensions.paddingL),\n        ],
        
        // Join date
        _buildInfoItem(
          'Member since',
          _formatDate(_user!.createdAt),
          Icons.calendar_today,
        ),
        
        // Last active
        if (_user!.stats?.lastActive != null)
          _buildInfoItem(
            'Last active',
            _formatRelativeTime(_user!.stats!.lastActive!),
            Icons.access_time,
          ),
      ],
    );
  }
  
  Widget _buildAboutSection(String title, IconData icon, List<String> items) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, size: 20, color: AppColors.textSecondary),
            const SizedBox(width: AppDimensions.paddingS),
            Text(
              title,
              style: AppTextStyles.labelLarge,
            ),
          ],
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: items.map((item) => Chip(
            label: Text(item),
            backgroundColor: AppColors.primary.withOpacity(0.1),
            labelStyle: AppTextStyles.caption.copyWith(
              color: AppColors.primary,
            ),
          )).toList(),
        ),
      ],
    );
  }
  
  Widget _buildInfoItem(String label, String value, IconData icon) {
    return Padding(
      padding: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: Row(
        children: [
          Icon(icon, size: 20, color: AppColors.textSecondary),
          const SizedBox(width: AppDimensions.paddingS),
          Text(
            label,
            style: AppTextStyles.labelMedium,
          ),
          const Spacer(),
          Text(
            value,
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  String _formatDate(DateTime date) {
    final now = DateTime.now();
    final difference = now.difference(date);
    
    if (difference.inDays > 365) {
      return '${(difference.inDays / 365).floor()} years ago';
    } else if (difference.inDays > 30) {
      return '${(difference.inDays / 30).floor()} months ago';
    } else if (difference.inDays > 0) {
      return '${difference.inDays} days ago';
    } else {
      return 'Today';
    }
  }
  
  String _formatRelativeTime(DateTime date) {
    final now = DateTime.now();
    final difference = now.difference(date);
    
    if (difference.inDays > 0) {
      return '${difference.inDays} days ago';
    } else if (difference.inHours > 0) {
      return '${difference.inHours} hours ago';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes} minutes ago';
    } else {
      return 'Just now';
    }
  }
  
  String get _formattedLikesCount => _user!.formattedLikesCount;
}

class _SliverTabBarDelegate extends SliverPersistentHeaderDelegate {
  final TabBar tabBar;
  
  _SliverTabBarDelegate(this.tabBar);
  
  @override
  double get minExtent => tabBar.preferredSize.height;
  
  @override
  double get maxExtent => tabBar.preferredSize.height;
  
  @override
  Widget build(BuildContext context, double shrinkOffset, bool overlapsContent) {
    return Container(
      color: AppColors.surface,
      child: tabBar,
    );
  }
  
  @override
  bool shouldRebuild(covariant SliverPersistentHeaderDelegate oldDelegate) => false;
}

extension on SocialUserModel {
  String get formattedLikesCount => _formatCount(likesCount);
  
  String _formatCount(int count) {
    if (count < 1000) return count.toString();
    if (count < 1000000) return '${(count / 1000).toStringAsFixed(1)}K';
    return '${(count / 1000000).toStringAsFixed(1)}M';
  }
}