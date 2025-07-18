import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/data/models/social/outfit_sharing_model.dart';
import 'package:koutu/services/social/outfit_sharing_service.dart';
import 'package:go_router/go_router.dart';

/// Style inspiration feed with curated content
class StyleInspirationScreen extends StatefulWidget {
  const StyleInspirationScreen({super.key});

  @override
  State<StyleInspirationScreen> createState() => _StyleInspirationScreenState();
}

class _StyleInspirationScreenState extends State<StyleInspirationScreen> {
  final ScrollController _scrollController = ScrollController();
  
  List<SharedOutfitModel> _inspirations = [];
  bool _isLoading = false;
  bool _hasMore = true;
  int _currentPage = 0;
  
  final List<String> _categories = [
    'For You',
    'Trending',
    'Seasonal',
    'Minimalist',
    'Streetwear',
    'Vintage',
    'Formal',
    'Casual',
  ];
  
  String _selectedCategory = 'For You';
  
  @override
  void initState() {
    super.initState();
    _loadInspirations();
    _scrollController.addListener(_onScroll);
  }
  
  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }
  
  void _onScroll() {
    if (_scrollController.position.pixels >= _scrollController.position.maxScrollExtent - 200) {
      _loadMoreInspirations();
    }
  }
  
  void _loadInspirations() async {
    if (_isLoading) return;
    
    setState(() {
      _isLoading = true;
      _currentPage = 0;
    });
    
    try {
      final result = await OutfitSharingService.getSharedOutfitsFeed(
        page: _currentPage,
        limit: 20,
        category: _selectedCategory.toLowerCase().replaceAll(' ', '_'),
      );
      
      result.fold(
        (failure) {
          // Handle error silently for inspiration feed
          debugPrint('Failed to load inspirations: ${failure.message}');
        },
        (outfits) {
          setState(() {
            _inspirations = _getCuratedInspirations(outfits);
            _hasMore = outfits.length >= 20;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading inspirations: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _loadMoreInspirations() async {
    if (_isLoading || !_hasMore) return;
    
    setState(() => _isLoading = true);
    
    try {
      final result = await OutfitSharingService.getSharedOutfitsFeed(
        page: _currentPage + 1,
        limit: 20,
        category: _selectedCategory.toLowerCase().replaceAll(' ', '_'),
      );
      
      result.fold(
        (failure) {
          // Handle error silently
          debugPrint('Failed to load more inspirations: ${failure.message}');
        },
        (outfits) {
          setState(() {
            _inspirations.addAll(_getCuratedInspirations(outfits));
            _currentPage++;
            _hasMore = outfits.length >= 20;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading more inspirations: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  List<SharedOutfitModel> _getCuratedInspirations(List<SharedOutfitModel> outfits) {
    // Filter and sort outfits for inspiration feed
    return outfits.where((outfit) {
      // Only show high-quality, popular outfits
      return outfit.likesCount > 50 && outfit.viewsCount > 500;
    }).toList()
      ..sort((a, b) {
        // Sort by engagement rate and popularity
        final aScore = a.engagementRate * 0.7 + (a.isPopular ? 0.3 : 0);
        final bScore = b.engagementRate * 0.7 + (b.isPopular ? 0.3 : 0);
        return bScore.compareTo(aScore);
      });
  }
  
  void _onCategoryChanged(String category) {
    setState(() {
      _selectedCategory = category;
    });
    _loadInspirations();
  }
  
  void _onOutfitTap(SharedOutfitModel outfit) {
    context.push('/social/outfit/${outfit.id}');
  }
  
  void _onSaveTap(SharedOutfitModel outfit) async {
    try {
      final result = await OutfitSharingService.saveOutfit(
        outfit.id,
        'current_user_id', // In real app, get from auth state
      );
      
      result.fold(
        (failure) {
          // Handle error silently
          debugPrint('Save failed: ${failure.message}');
        },
        (saved) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(saved ? 'Outfit saved to your inspiration!' : 'Outfit removed from inspiration'),
              backgroundColor: AppColors.success,
              duration: const Duration(seconds: 2),
            ),
          );
        },
      );
    } catch (e) {
      debugPrint('Error saving outfit: $e');
    }
  }
  
  void _onShareTap(SharedOutfitModel outfit) {
    showModalBottomSheet(
      context: context,
      builder: (context) => _buildShareBottomSheet(outfit),
    );
  }
  
  void _onUserTap(SharedOutfitModel outfit) {
    context.push('/social/profile/${outfit.userId}');
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Style Inspiration',
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: () {
              context.push('/social/search');
            },
          ),
          IconButton(
            icon: const Icon(Icons.bookmark_outline),
            onPressed: () {
              context.push('/social/saved');
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Categories
          _buildCategories(),
          
          // Inspiration grid
          Expanded(
            child: _isLoading && _inspirations.isEmpty
                ? const Center(child: AppLoadingIndicator())
                : _inspirations.isEmpty
                    ? _buildEmptyState()
                    : _buildInspirationsGrid(),
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
  
  Widget _buildInspirationsGrid() {
    return GridView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.all(AppDimensions.paddingS),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: AppDimensions.paddingS,
        mainAxisSpacing: AppDimensions.paddingS,
        childAspectRatio: 0.75,
      ),
      itemCount: _inspirations.length + (_hasMore ? 2 : 0),
      itemBuilder: (context, index) {
        if (index >= _inspirations.length) {
          return const Center(
            child: AppLoadingIndicator(),
          );
        }
        
        final outfit = _inspirations[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: (index % 10) * 100),
          child: _buildInspirationCard(outfit),
        );
      },
    );
  }
  
  Widget _buildInspirationCard(SharedOutfitModel outfit) {
    return Card(
      clipBehavior: Clip.antiAlias,
      child: Stack(
        children: [
          // Outfit image
          Positioned.fill(
            child: GestureDetector(
              onTap: () => _onOutfitTap(outfit),
              child: Container(
                decoration: BoxDecoration(
                  color: AppColors.backgroundSecondary,
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [
                      AppColors.backgroundSecondary,
                      AppColors.backgroundSecondary.withOpacity(0.8),
                    ],
                  ),
                ),
                child: const Center(
                  child: Icon(
                    Icons.checkroom,
                    size: 48,
                    color: AppColors.textTertiary,
                  ),
                ),
              ),
            ),
          ),
          
          // Quality indicators
          Positioned(
            top: AppDimensions.paddingS,
            left: AppDimensions.paddingS,
            child: Row(
              children: [
                if (outfit.isTrending)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingXS,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.error,
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Text(
                      'TRENDING',
                      style: AppTextStyles.caption.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                if (outfit.isFeatured)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingXS,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.primary,
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Text(
                      'FEATURED',
                      style: AppTextStyles.caption.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          
          // Save button
          Positioned(
            top: AppDimensions.paddingS,
            right: AppDimensions.paddingS,
            child: IconButton(
              icon: const Icon(Icons.bookmark_border),
              onPressed: () => _onSaveTap(outfit),
              style: IconButton.styleFrom(
                backgroundColor: Colors.white.withOpacity(0.9),
                foregroundColor: AppColors.textPrimary,
                padding: const EdgeInsets.all(AppDimensions.paddingXS),
              ),
            ),
          ),
          
          // Outfit info overlay
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
                    Colors.black.withOpacity(0.8),
                  ],
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Title
                  Text(
                    outfit.title,
                    style: AppTextStyles.labelMedium.copyWith(
                      color: Colors.white,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  
                  const SizedBox(height: 4),
                  
                  // Author and stats
                  Row(
                    children: [
                      // Author
                      Expanded(
                        child: GestureDetector(
                          onTap: () => _onUserTap(outfit),
                          child: Row(
                            children: [
                              CircleAvatar(
                                radius: 8,
                                backgroundColor: Colors.white.withOpacity(0.3),
                                backgroundImage: outfit.author?.hasProfileImage == true
                                    ? CachedNetworkImageProvider(outfit.author!.profileImageUrl)
                                    : null,
                                child: outfit.author?.hasProfileImage != true
                                    ? Text(
                                        outfit.author?.displayName.isNotEmpty == true
                                            ? outfit.author!.displayName[0].toUpperCase()
                                            : 'U',
                                        style: AppTextStyles.caption.copyWith(
                                          color: Colors.white,
                                          fontSize: 8,
                                        ),
                                      )
                                    : null,
                              ),
                              const SizedBox(width: 4),
                              Expanded(
                                child: Text(
                                  outfit.author?.displayName ?? 'Unknown',
                                  style: AppTextStyles.caption.copyWith(
                                    color: Colors.white70,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                      
                      // Stats
                      Row(
                        children: [
                          Icon(
                            Icons.favorite,
                            size: 12,
                            color: Colors.white70,
                          ),
                          const SizedBox(width: 2),
                          Text(
                            outfit.formattedLikesCount,
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white70,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildShareBottomSheet(SharedOutfitModel outfit) {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            'Share Inspiration',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          
          // Share options
          GridView.count(
            crossAxisCount: 4,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            children: [
              _buildShareOption(
                icon: Icons.copy,
                label: 'Copy Link',
                onTap: () {
                  Navigator.pop(context);
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Link copied to clipboard')),
                  );
                },
              ),
              _buildShareOption(
                icon: Icons.camera_alt,
                label: 'Instagram',
                onTap: () {
                  Navigator.pop(context);
                  // Instagram share logic
                },
              ),
              _buildShareOption(
                icon: Icons.alternate_email,
                label: 'Twitter',
                onTap: () {
                  Navigator.pop(context);
                  // Twitter share logic
                },
              ),
              _buildShareOption(
                icon: Icons.push_pin,
                label: 'Pinterest',
                onTap: () {
                  Navigator.pop(context);
                  // Pinterest share logic
                },
              ),
            ],
          ),
        ],
      ),
    );
  }
  
  Widget _buildShareOption({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            decoration: BoxDecoration(
              color: AppColors.backgroundSecondary,
              shape: BoxShape.circle,
            ),
            child: Icon(
              icon,
              size: 24,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            label,
            style: AppTextStyles.caption,
            textAlign: TextAlign.center,
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
            Icons.lightbulb_outline,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Inspiration Yet',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Follow some users to see their style inspiration',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          ElevatedButton(
            onPressed: () {
              context.push('/social/discover');
            },
            child: const Text('Discover Users'),
          ),
        ],
      ),
    );
  }
}