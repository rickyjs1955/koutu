import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/data/models/social/outfit_sharing_model.dart';
import 'package:koutu/services/social/outfit_sharing_service.dart';
import 'package:go_router/go_router.dart';

/// Screen showing shared outfits feed
class SharedOutfitFeedScreen extends StatefulWidget {
  final String? category;
  final List<String>? tags;
  
  const SharedOutfitFeedScreen({
    super.key,
    this.category,
    this.tags,
  });

  @override
  State<SharedOutfitFeedScreen> createState() => _SharedOutfitFeedScreenState();
}

class _SharedOutfitFeedScreenState extends State<SharedOutfitFeedScreen> {
  final ScrollController _scrollController = ScrollController();
  
  List<SharedOutfitModel> _outfits = [];
  bool _isLoading = false;
  bool _hasMore = true;
  int _currentPage = 0;
  
  final List<String> _categories = [
    'All',
    'Casual',
    'Business',
    'Evening',
    'Sports',
    'Seasonal',
  ];
  
  String _selectedCategory = 'All';
  ShareVisibility? _selectedVisibility;
  
  @override
  void initState() {
    super.initState();
    _selectedCategory = widget.category ?? 'All';
    _loadOutfits();
    _scrollController.addListener(_onScroll);
  }
  
  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }
  
  void _onScroll() {
    if (_scrollController.position.pixels >= _scrollController.position.maxScrollExtent - 200) {
      _loadMoreOutfits();
    }
  }
  
  void _loadOutfits() async {
    if (_isLoading) return;
    
    setState(() {
      _isLoading = true;
      _currentPage = 0;
    });
    
    try {
      final result = await OutfitSharingService.getSharedOutfitsFeed(
        page: _currentPage,
        limit: 20,
        category: _selectedCategory == 'All' ? null : _selectedCategory.toLowerCase(),
        tags: widget.tags,
        visibility: _selectedVisibility,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (outfits) {
          setState(() {
            _outfits = outfits;
            _hasMore = outfits.length >= 20;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _loadMoreOutfits() async {
    if (_isLoading || !_hasMore) return;
    
    setState(() => _isLoading = true);
    
    try {
      final result = await OutfitSharingService.getSharedOutfitsFeed(
        page: _currentPage + 1,
        limit: 20,
        category: _selectedCategory == 'All' ? null : _selectedCategory.toLowerCase(),
        tags: widget.tags,
        visibility: _selectedVisibility,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (outfits) {
          setState(() {
            _outfits.addAll(outfits);
            _currentPage++;
            _hasMore = outfits.length >= 20;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onCategoryChanged(String category) {
    setState(() {
      _selectedCategory = category;
    });
    _loadOutfits();
  }
  
  void _onOutfitTap(SharedOutfitModel outfit) {
    context.push('/social/outfit/${outfit.id}');
  }
  
  void _onUserTap(SharedOutfitModel outfit) {
    context.push('/social/profile/${outfit.userId}');
  }
  
  void _onLikeTap(SharedOutfitModel outfit) async {
    try {
      final result = await OutfitSharingService.toggleOutfitLike(
        outfit.id,
        'current_user_id', // In real app, get from auth state
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Like Failed', failure.message);
        },
        (isLiked) {
          setState(() {
            final index = _outfits.indexWhere((o) => o.id == outfit.id);
            if (index != -1) {
              _outfits[index] = _outfits[index].copyWith(
                likesCount: isLiked 
                    ? _outfits[index].likesCount + 1 
                    : _outfits[index].likesCount - 1,
              );
            }
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    }
  }
  
  void _onCommentTap(SharedOutfitModel outfit) {
    context.push('/social/outfit/${outfit.id}/comments');
  }
  
  void _onShareTap(SharedOutfitModel outfit) {
    _showShareDialog(outfit);
  }
  
  void _onSaveTap(SharedOutfitModel outfit) async {
    try {
      final result = await OutfitSharingService.saveOutfit(
        outfit.id,
        'current_user_id', // In real app, get from auth state
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Save Failed', failure.message);
        },
        (saved) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(saved ? 'Outfit saved!' : 'Outfit removed from saved'),
              backgroundColor: AppColors.success,
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
  
  void _showShareDialog(SharedOutfitModel outfit) {
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Share Outfit',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            ListTile(
              leading: const Icon(Icons.copy),
              title: const Text('Copy Link'),
              onTap: () {
                Navigator.pop(context);
                // Copy share link logic
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Link copied to clipboard')),
                );
              },
            ),
            ListTile(
              leading: const Icon(Icons.camera_alt),
              title: const Text('Share to Instagram'),
              onTap: () {
                Navigator.pop(context);
                // Instagram share logic
              },
            ),
            ListTile(
              leading: const Icon(Icons.alternate_email),
              title: const Text('Share to Twitter'),
              onTap: () {
                Navigator.pop(context);
                // Twitter share logic
              },
            ),
            ListTile(
              leading: const Icon(Icons.facebook),
              title: const Text('Share to Facebook'),
              onTap: () {
                Navigator.pop(context);
                // Facebook share logic
              },
            ),
          ],
        ),
      ),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Style Feed',
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: () {
              // TODO: Navigate to search
            },
          ),
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: () {
              // TODO: Show filter options
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Categories
          _buildCategories(),
          
          // Outfits feed
          Expanded(
            child: _isLoading && _outfits.isEmpty
                ? const Center(child: AppLoadingIndicator())
                : _outfits.isEmpty
                    ? _buildEmptyState()
                    : _buildOutfitsList(),
          ),
        ],
      ),
    );
  }
  
  Widget _buildCategories() {
    return Container(
      height: 60,
      padding: const EdgeInsets.symmetric(vertical: AppDimensions.paddingS),
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
        itemCount: _categories.length,
        itemBuilder: (context, index) {
          final category = _categories[index];
          final isSelected = category == _selectedCategory;
          
          return Padding(
            padding: const EdgeInsets.only(right: AppDimensions.paddingS),
            child: FilterChip(
              selected: isSelected,
              label: Text(category),
              onSelected: (selected) {
                if (selected) {
                  _onCategoryChanged(category);
                }
              },
            ),
          );
        },
      ),
    );
  }
  
  Widget _buildOutfitsList() {
    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: _outfits.length + (_hasMore ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= _outfits.length) {
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(AppDimensions.paddingL),
              child: AppLoadingIndicator(),
            ),
          );
        }
        
        final outfit = _outfits[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _buildOutfitCard(outfit),
        );
      },
    );
  }
  
  Widget _buildOutfitCard(SharedOutfitModel outfit) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author header
          ListTile(
            leading: CircleAvatar(
              backgroundColor: AppColors.backgroundSecondary,
              backgroundImage: outfit.author?.hasProfileImage == true
                  ? CachedNetworkImageProvider(outfit.author!.profileImageUrl)
                  : null,
              child: outfit.author?.hasProfileImage != true
                  ? Text(
                      outfit.author?.displayName.isNotEmpty == true
                          ? outfit.author!.displayName[0].toUpperCase()
                          : 'U',
                      style: AppTextStyles.labelMedium,
                    )
                  : null,
            ),
            title: Text(
              outfit.author?.displayName ?? 'Unknown User',
              style: AppTextStyles.labelMedium,
            ),
            subtitle: Text(
              _formatTimeAgo(outfit.sharedAt),
              style: AppTextStyles.caption.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
            trailing: outfit.author != null
                ? IconButton(
                    icon: const Icon(Icons.more_vert),
                    onPressed: () {
                      // TODO: Show outfit options
                    },
                  )
                : null,
            onTap: () => _onUserTap(outfit),
          ),
          
          // Outfit image
          GestureDetector(
            onTap: () => _onOutfitTap(outfit),
            child: Container(
              width: double.infinity,
              height: 300,
              color: AppColors.backgroundSecondary,
              child: const Center(
                child: Icon(
                  Icons.checkroom,
                  size: 64,
                  color: AppColors.textTertiary,
                ),
              ),
            ),
          ),
          
          // Outfit details
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Title
                Text(
                  outfit.title,
                  style: AppTextStyles.labelLarge,
                ),
                
                // Description
                if (outfit.description != null && outfit.description!.isNotEmpty) ...[
                  const SizedBox(height: AppDimensions.paddingS),
                  Text(
                    outfit.description!,
                    style: AppTextStyles.bodyMedium,
                  ),
                ],
                
                // Tags
                if (outfit.tags.isNotEmpty) ...[
                  const SizedBox(height: AppDimensions.paddingS),
                  Wrap(
                    spacing: AppDimensions.paddingXS,
                    children: outfit.tags.map((tag) => Text(
                      '#$tag',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.primary,
                      ),
                    )).toList(),
                  ),
                ],
                
                const SizedBox(height: AppDimensions.paddingS),
                
                // Actions
                Row(
                  children: [
                    IconButton(
                      icon: const Icon(Icons.favorite_border),
                      onPressed: () => _onLikeTap(outfit),
                    ),
                    Text(outfit.formattedLikesCount),
                    
                    const SizedBox(width: AppDimensions.paddingM),
                    
                    IconButton(
                      icon: const Icon(Icons.comment_outlined),
                      onPressed: () => _onCommentTap(outfit),
                    ),
                    Text(outfit.formattedCommentsCount),
                    
                    const SizedBox(width: AppDimensions.paddingM),
                    
                    IconButton(
                      icon: const Icon(Icons.share_outlined),
                      onPressed: () => _onShareTap(outfit),
                    ),
                    
                    const Spacer(),
                    
                    IconButton(
                      icon: const Icon(Icons.bookmark_border),
                      onPressed: () => _onSaveTap(outfit),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.checkroom_outlined,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Outfits Yet',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Be the first to share your style!',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          ElevatedButton(
            onPressed: () {
              context.push('/outfit/create');
            },
            child: const Text('Create Outfit'),
          ),
        ],
      ),
    );
  }
  
  String _formatTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h ago';
    } else if (difference.inDays < 7) {
      return '${difference.inDays}d ago';
    } else {
      return '${(difference.inDays / 7).floor()}w ago';
    }
  }
}