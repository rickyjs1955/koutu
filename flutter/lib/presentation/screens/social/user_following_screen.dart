import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/data/models/social/user_following_model.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/services/social/user_following_service.dart';
import 'package:go_router/go_router.dart';

/// Screen for displaying user's followers or following
class UserFollowingScreen extends StatefulWidget {
  final String userId;
  final String initialTab; // 'followers' or 'following'
  final String? userName;
  
  const UserFollowingScreen({
    super.key,
    required this.userId,
    this.initialTab = 'followers',
    this.userName,
  });

  @override
  State<UserFollowingScreen> createState() => _UserFollowingScreenState();
}

class _UserFollowingScreenState extends State<UserFollowingScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final TextEditingController _searchController = TextEditingController();
  
  List<SocialUserModel> _followers = [];
  List<SocialUserModel> _following = [];
  List<SocialUserModel> _mutualFollowers = [];
  
  bool _isLoadingFollowers = false;
  bool _isLoadingFollowing = false;
  bool _isLoadingMutual = false;
  
  int _followersPage = 0;
  int _followingPage = 0;
  int _mutualPage = 0;
  
  bool _hasMoreFollowers = true;
  bool _hasMoreFollowing = true;
  bool _hasMoreMutual = true;
  
  String _searchQuery = '';
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(
      length: 3,
      vsync: this,
      initialIndex: widget.initialTab == 'following' ? 1 : 0,
    );
    _loadInitialData();
    _searchController.addListener(_onSearchChanged);
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }
  
  void _onSearchChanged() {
    if (_searchController.text != _searchQuery) {
      setState(() {
        _searchQuery = _searchController.text;
      });
      _searchUsers();
    }
  }
  
  void _searchUsers() {
    // Reset and reload data with search query
    setState(() {
      _followers.clear();
      _following.clear();
      _mutualFollowers.clear();
      _followersPage = 0;
      _followingPage = 0;
      _mutualPage = 0;
      _hasMoreFollowers = true;
      _hasMoreFollowing = true;
      _hasMoreMutual = true;
    });
    
    _loadFollowers();
    _loadFollowing();
    _loadMutualFollowers();
  }
  
  void _loadInitialData() {
    _loadFollowers();
    _loadFollowing();
    _loadMutualFollowers();
  }
  
  void _loadFollowers() async {
    if (_isLoadingFollowers || !_hasMoreFollowers) return;
    
    setState(() => _isLoadingFollowers = true);
    
    try {
      final result = await UserFollowingService.getFollowers(
        widget.userId,
        page: _followersPage,
        limit: 20,
        search: _searchQuery.isNotEmpty ? _searchQuery : null,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (response) {
          setState(() {
            if (_followersPage == 0) {
              _followers = response.users;
            } else {
              _followers.addAll(response.users);
            }
            _followersPage++;
            _hasMoreFollowers = response.hasMore;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoadingFollowers = false);
    }
  }
  
  void _loadFollowing() async {
    if (_isLoadingFollowing || !_hasMoreFollowing) return;
    
    setState(() => _isLoadingFollowing = true);
    
    try {
      final result = await UserFollowingService.getFollowing(
        widget.userId,
        page: _followingPage,
        limit: 20,
        search: _searchQuery.isNotEmpty ? _searchQuery : null,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (response) {
          setState(() {
            if (_followingPage == 0) {
              _following = response.users;
            } else {
              _following.addAll(response.users);
            }
            _followingPage++;
            _hasMoreFollowing = response.hasMore;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoadingFollowing = false);
    }
  }
  
  void _loadMutualFollowers() async {
    if (_isLoadingMutual || !_hasMoreMutual) return;
    
    setState(() => _isLoadingMutual = true);
    
    try {
      final result = await UserFollowingService.getMutualFollowers(
        'current_user_id', // In real app, get from auth state
        widget.userId,
        page: _mutualPage,
        limit: 20,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (response) {
          setState(() {
            if (_mutualPage == 0) {
              _mutualFollowers = response.users;
            } else {
              _mutualFollowers.addAll(response.users);
            }
            _mutualPage++;
            _hasMoreMutual = response.hasMore;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoadingMutual = false);
    }
  }
  
  void _onUserTap(SocialUserModel user) {
    context.push('/social/profile/${user.id}');
  }
  
  void _onFollowTap(SocialUserModel user) async {
    try {
      final result = await UserFollowingService.followUser(
        'current_user_id', // In real app, get from auth state
        user.id,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Follow Failed', failure.message);
        },
        (followModel) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                followModel.status == FollowStatus.pending
                    ? 'Follow request sent'
                    : 'Now following ${user.displayName}',
              ),
              backgroundColor: AppColors.success,
            ),
          );
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    }
  }
  
  void _onUnfollowTap(SocialUserModel user) async {
    final confirmed = await AppDialog.confirm(
      context,
      title: 'Unfollow ${user.displayName}',
      message: 'Are you sure you want to unfollow this user?',
      confirmText: 'Unfollow',
      confirmIsDestructive: true,
    );
    
    if (!confirmed) return;
    
    try {
      final result = await UserFollowingService.unfollowUser(
        'current_user_id', // In real app, get from auth state
        user.id,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Unfollow Failed', failure.message);
        },
        (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Unfollowed ${user.displayName}'),
              backgroundColor: AppColors.warning,
            ),
          );
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    }
  }
  
  void _onRemoveFollowerTap(SocialUserModel user) async {
    final confirmed = await AppDialog.confirm(
      context,
      title: 'Remove ${user.displayName}',
      message: 'Are you sure you want to remove this follower?',
      confirmText: 'Remove',
      confirmIsDestructive: true,
    );
    
    if (!confirmed) return;
    
    try {
      final result = await UserFollowingService.removeFollower(
        'current_user_id', // In real app, get from auth state
        user.id,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Remove Failed', failure.message);
        },
        (success) {
          setState(() {
            _followers.removeWhere((u) => u.id == user.id);
          });
          
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Removed ${user.displayName}'),
              backgroundColor: AppColors.warning,
            ),
          );
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    }
  }
  
  void _showErrorDialog(String title, String message) {
    AppDialog.error(
      context,
      title: title,
      message: message,
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: widget.userName != null ? '${widget.userName}' : 'Connections',
        bottom: TabBar(
          controller: _tabController,
          tabs: [
            Tab(text: 'Followers (${_followers.length})'),
            Tab(text: 'Following (${_following.length})'),
            Tab(text: 'Mutual (${_mutualFollowers.length})'),
          ],
        ),
      ),
      body: Column(
        children: [
          // Search bar
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Search users...',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchQuery.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchController.clear();
                        },
                      )
                    : null,
              ),
            ),
          ),
          
          // Tabs content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildFollowersList(),
                _buildFollowingList(),
                _buildMutualFollowersList(),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildFollowersList() {
    if (_isLoadingFollowers && _followers.isEmpty) {
      return const Center(child: AppLoadingIndicator());
    }
    
    if (_followers.isEmpty) {
      return _buildEmptyState(
        icon: Icons.people_outline,
        title: 'No Followers',
        subtitle: 'When people follow you, they\'ll appear here',
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: _followers.length + (_hasMoreFollowers ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= _followers.length) {
          _loadFollowers();
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(AppDimensions.paddingL),
              child: AppLoadingIndicator(),
            ),
          );
        }
        
        final user = _followers[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: _buildUserListItem(
            user,
            isFollower: true,
            onRemove: () => _onRemoveFollowerTap(user),
          ),
        );
      },
    );
  }
  
  Widget _buildFollowingList() {
    if (_isLoadingFollowing && _following.isEmpty) {
      return const Center(child: AppLoadingIndicator());
    }
    
    if (_following.isEmpty) {
      return _buildEmptyState(
        icon: Icons.person_add_outlined,
        title: 'Not Following Anyone',
        subtitle: 'People you follow will appear here',
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: _following.length + (_hasMoreFollowing ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= _following.length) {
          _loadFollowing();
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(AppDimensions.paddingL),
              child: AppLoadingIndicator(),
            ),
          );
        }
        
        final user = _following[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: _buildUserListItem(
            user,
            isFollowing: true,
            onUnfollow: () => _onUnfollowTap(user),
          ),
        );
      },
    );
  }
  
  Widget _buildMutualFollowersList() {
    if (_isLoadingMutual && _mutualFollowers.isEmpty) {
      return const Center(child: AppLoadingIndicator());
    }
    
    if (_mutualFollowers.isEmpty) {
      return _buildEmptyState(
        icon: Icons.people_alt_outlined,
        title: 'No Mutual Followers',
        subtitle: 'People you both follow will appear here',
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: _mutualFollowers.length + (_hasMoreMutual ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= _mutualFollowers.length) {
          _loadMutualFollowers();
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(AppDimensions.paddingL),
              child: AppLoadingIndicator(),
            ),
          );
        }
        
        final user = _mutualFollowers[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: _buildUserListItem(
            user,
            isMutual: true,
          ),
        );
      },
    );
  }
  
  Widget _buildUserListItem(
    SocialUserModel user, {
    bool isFollower = false,
    bool isFollowing = false,
    bool isMutual = false,
    VoidCallback? onRemove,
    VoidCallback? onUnfollow,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingS),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: AppColors.backgroundSecondary,
          backgroundImage: user.hasProfileImage
              ? CachedNetworkImageProvider(user.profileImageUrl)
              : null,
          child: !user.hasProfileImage
              ? Text(
                  user.displayName.isNotEmpty
                      ? user.displayName[0].toUpperCase()
                      : user.username[0].toUpperCase(),
                  style: AppTextStyles.labelMedium,
                )
              : null,
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                user.displayName,
                style: AppTextStyles.labelMedium,
              ),
            ),
            if (user.isVerified)
              Icon(
                Icons.verified,
                color: AppColors.primary,
                size: 16,
              ),
          ],
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '@${user.username}',
              style: AppTextStyles.caption.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
            if (user.bio != null && user.bio!.isNotEmpty)
              Text(
                user.bio!,
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
          ],
        ),
        trailing: _buildUserActions(
          user,
          isFollower: isFollower,
          isFollowing: isFollowing,
          isMutual: isMutual,
          onRemove: onRemove,
          onUnfollow: onUnfollow,
        ),
        onTap: () => _onUserTap(user),
      ),
    );
  }
  
  Widget? _buildUserActions(
    SocialUserModel user, {
    bool isFollower = false,
    bool isFollowing = false,
    bool isMutual = false,
    VoidCallback? onRemove,
    VoidCallback? onUnfollow,
  }) {
    if (isFollower && onRemove != null) {
      return PopupMenuButton<String>(
        onSelected: (value) {
          if (value == 'remove') {
            onRemove();
          }
        },
        itemBuilder: (context) => [
          const PopupMenuItem(
            value: 'remove',
            child: Text('Remove Follower'),
          ),
        ],
      );
    }
    
    if (isFollowing && onUnfollow != null) {
      return OutlinedButton(
        onPressed: onUnfollow,
        child: const Text('Unfollow'),
      );
    }
    
    if (isMutual) {
      return const Text(
        'Mutual',
        style: TextStyle(color: AppColors.primary),
      );
    }
    
    return OutlinedButton(
      onPressed: () => _onFollowTap(user),
      child: const Text('Follow'),
    );
  }
  
  Widget _buildEmptyState({
    required IconData icon,
    required String title,
    required String subtitle,
  }) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            icon,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            title,
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            subtitle,
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}