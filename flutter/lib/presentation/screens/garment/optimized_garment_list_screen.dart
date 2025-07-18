import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/lists/lazy_loading_list.dart';
import 'package:koutu/presentation/widgets/image/cached_network_image_widget.dart';
import 'package:koutu/presentation/widgets/garment/garment_card.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/blocs/garment/garment_bloc.dart';
import 'package:koutu/services/performance/lazy_loading_service.dart';
import 'package:koutu/services/cache/image_cache_service.dart';
import 'package:go_router/go_router.dart';

/// Optimized garment list screen with lazy loading
class OptimizedGarmentListScreen extends StatefulWidget {
  final String wardrobeId;
  
  const OptimizedGarmentListScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<OptimizedGarmentListScreen> createState() => _OptimizedGarmentListScreenState();
}

class _OptimizedGarmentListScreenState extends State<OptimizedGarmentListScreen> {
  final ScrollController _scrollController = ScrollController();
  bool _isGridView = true;
  String _sortBy = 'recent';
  String? _filterCategory;
  final Set<String> _selectedGarmentIds = {};
  bool _isSelectionMode = false;
  
  @override
  void initState() {
    super.initState();
    _preloadImagesForViewport();
  }
  
  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }
  
  Future<List<GarmentModel>> _loadGarments(int page, int pageSize) async {
    // Simulate API call with filtering and sorting
    await Future.delayed(const Duration(milliseconds: 500));
    
    // Mock data generation
    final garments = List.generate(
      page < 5 ? pageSize : pageSize ~/ 2, // Simulate end of data
      (index) => GarmentModel(
        id: 'garment_${page * pageSize + index}',
        wardrobeId: widget.wardrobeId,
        name: 'Garment ${page * pageSize + index}',
        category: _getRandomCategory(),
        color: _getRandomColor(),
        brand: 'Brand ${index % 5}',
        size: _getRandomSize(),
        material: 'Cotton',
        careInstructions: ['Machine wash cold', 'Tumble dry low'],
        tags: ['casual', 'summer'],
        images: [
          ImageModel(
            id: 'img_${page * pageSize + index}',
            url: 'https://example.com/garment_${page * pageSize + index}.jpg',
            thumbnailUrl: 'https://example.com/garment_${page * pageSize + index}_thumb.jpg',
            width: 1000,
            height: 1000,
            size: 500000,
            createdAt: DateTime.now(),
          ),
        ],
        createdAt: DateTime.now().subtract(Duration(days: index)),
        updatedAt: DateTime.now(),
      ),
    );
    
    // Apply filtering
    if (_filterCategory != null) {
      return garments.where((g) => g.category == _filterCategory).toList();
    }
    
    // Apply sorting
    switch (_sortBy) {
      case 'name':
        garments.sort((a, b) => a.name.compareTo(b.name));
        break;
      case 'category':
        garments.sort((a, b) => a.category.compareTo(b.category));
        break;
      case 'color':
        garments.sort((a, b) => a.color.compareTo(b.color));
        break;
      case 'recent':
      default:
        // Already sorted by creation date
        break;
    }
    
    return garments;
  }
  
  void _preloadImagesForViewport() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final imageService = ImageCacheService();
      
      // Calculate visible item count
      final screenHeight = MediaQuery.of(context).size.height;
      final itemHeight = _isGridView ? 200.0 : 100.0;
      final visibleCount = (screenHeight / itemHeight).ceil() * (_isGridView ? 2 : 1);
      
      // Preload images for first visible items
      final preloadUrls = <String>[];
      for (var i = 0; i < visibleCount; i++) {
        preloadUrls.add('https://example.com/garment_$i.jpg');
      }
      
      imageService.preloadImages(
        preloadUrls,
        strategy: ImageCacheStrategy.aggressive,
        targetSize: Size(_isGridView ? 200 : 100, _isGridView ? 200 : 100),
      );
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'My Garments',
        actions: [
          if (_isSelectionMode)
            TextButton(
              onPressed: _selectedGarmentIds.isEmpty ? null : _performBulkAction,
              child: Text('${_selectedGarmentIds.length} selected'),
            ),
          IconButton(
            icon: Icon(_isGridView ? Icons.list : Icons.grid_view),
            onPressed: () {
              setState(() {
                _isGridView = !_isGridView;
              });
              _preloadImagesForViewport();
            },
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.sort),
            onSelected: (value) {
              setState(() {
                _sortBy = value;
              });
              LazyLoadingService.clearCache('garments_${widget.wardrobeId}');
            },
            itemBuilder: (context) => [
              const PopupMenuItem(value: 'recent', child: Text('Recent')),
              const PopupMenuItem(value: 'name', child: Text('Name')),
              const PopupMenuItem(value: 'category', child: Text('Category')),
              const PopupMenuItem(value: 'color', child: Text('Color')),
            ],
          ),
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: _showFilterDialog,
          ),
        ],
      ),
      body: Column(
        children: [
          // Category filter chips
          if (_filterCategory != null)
            Container(
              height: 50,
              padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
              child: Row(
                children: [
                  Chip(
                    label: Text(_filterCategory!),
                    onDeleted: () {
                      setState(() {
                        _filterCategory = null;
                      });
                      LazyLoadingService.clearCache('garments_${widget.wardrobeId}');
                    },
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Filtered results',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
          
          // Garment list/grid
          Expanded(
            child: _isGridView ? _buildGridView() : _buildListView(),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          context.push('/garments/add', extra: {'wardrobeId': widget.wardrobeId});
        },
        child: const Icon(Icons.add),
      ),
    );
  }
  
  Widget _buildGridView() {
    return LazyLoadingGrid<GarmentModel>(
      scrollController: _scrollController,
      onLoadMore: _loadGarments,
      pageSize: 20,
      crossAxisCount: 2,
      mainAxisSpacing: AppDimensions.paddingM,
      crossAxisSpacing: AppDimensions.paddingM,
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      childAspectRatio: 0.75,
      itemBuilder: (context, garment, index) {
        return _buildGarmentGridItem(garment);
      },
      emptyWidget: _buildEmptyState(),
    );
  }
  
  Widget _buildListView() {
    return LazyLoadingList<GarmentModel>(
      scrollController: _scrollController,
      onLoadMore: _loadGarments,
      pageSize: 30, // More items for list view
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      separatorBuilder: (context, index) => const Divider(),
      itemBuilder: (context, garment, index) {
        return _buildGarmentListItem(garment);
      },
      emptyWidget: _buildEmptyState(),
    );
  }
  
  Widget _buildGarmentGridItem(GarmentModel garment) {
    final isSelected = _selectedGarmentIds.contains(garment.id);
    
    return GestureDetector(
      onTap: () {
        if (_isSelectionMode) {
          setState(() {
            if (isSelected) {
              _selectedGarmentIds.remove(garment.id);
            } else {
              _selectedGarmentIds.add(garment.id);
            }
          });
        } else {
          context.push('/garments/${garment.id}', extra: garment);
        }
      },
      onLongPress: () {
        setState(() {
          _isSelectionMode = true;
          _selectedGarmentIds.add(garment.id);
        });
      },
      child: Stack(
        children: [
          Container(
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
              border: Border.all(
                color: isSelected ? AppColors.primary : AppColors.backgroundSecondary,
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: ClipRRect(
                    borderRadius: const BorderRadius.vertical(
                      top: Radius.circular(AppDimensions.radiusM),
                    ),
                    child: CachedNetworkImageWidget(
                      imageUrl: garment.images.first.url,
                      width: double.infinity,
                      height: double.infinity,
                      fit: BoxFit.cover,
                      cacheStrategy: ImageCacheStrategy.balanced,
                      showProgressIndicator: false,
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(AppDimensions.paddingS),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        garment.name,
                        style: AppTextStyles.labelMedium,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${garment.brand} • ${garment.category}',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          if (isSelected)
            Positioned(
              top: AppDimensions.paddingS,
              right: AppDimensions.paddingS,
              child: Container(
                padding: const EdgeInsets.all(4),
                decoration: const BoxDecoration(
                  color: AppColors.primary,
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.check,
                  color: Colors.white,
                  size: 16,
                ),
              ),
            ),
        ],
      ),
    );
  }
  
  Widget _buildGarmentListItem(GarmentModel garment) {
    final isSelected = _selectedGarmentIds.contains(garment.id);
    
    return ListTile(
      leading: ClipRRect(
        borderRadius: BorderRadius.circular(AppDimensions.radiusS),
        child: CachedNetworkImageWidget(
          imageUrl: garment.images.first.thumbnailUrl ?? garment.images.first.url,
          width: 60,
          height: 60,
          fit: BoxFit.cover,
          cacheStrategy: ImageCacheStrategy.aggressive,
          showProgressIndicator: false,
        ),
      ),
      title: Text(garment.name),
      subtitle: Text('${garment.brand} • ${garment.category}'),
      trailing: _isSelectionMode
          ? Checkbox(
              value: isSelected,
              onChanged: (value) {
                setState(() {
                  if (value ?? false) {
                    _selectedGarmentIds.add(garment.id);
                  } else {
                    _selectedGarmentIds.remove(garment.id);
                  }
                });
              },
            )
          : Text(
              garment.size,
              style: AppTextStyles.caption,
            ),
      onTap: () {
        if (_isSelectionMode) {
          setState(() {
            if (isSelected) {
              _selectedGarmentIds.remove(garment.id);
            } else {
              _selectedGarmentIds.add(garment.id);
            }
          });
        } else {
          context.push('/garments/${garment.id}', extra: garment);
        }
      },
      onLongPress: () {
        setState(() {
          _isSelectionMode = true;
          _selectedGarmentIds.add(garment.id);
        });
      },
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.checkroom_outlined,
            size: 80,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No garments yet',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Add your first garment to get started',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingXL),
          ElevatedButton.icon(
            onPressed: () {
              context.push('/garments/add', extra: {'wardrobeId': widget.wardrobeId});
            },
            icon: const Icon(Icons.add),
            label: const Text('Add Garment'),
          ),
        ],
      ),
    );
  }
  
  void _showFilterDialog() {
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Filter by Category',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Wrap(
              spacing: AppDimensions.paddingS,
              children: [
                'All',
                'Tops',
                'Bottoms',
                'Dresses',
                'Outerwear',
                'Shoes',
                'Accessories',
              ].map((category) => FilterChip(
                label: Text(category),
                selected: category == 'All' 
                    ? _filterCategory == null 
                    : _filterCategory == category,
                onSelected: (selected) {
                  setState(() {
                    if (category == 'All') {
                      _filterCategory = null;
                    } else {
                      _filterCategory = selected ? category : null;
                    }
                  });
                  LazyLoadingService.clearCache('garments_${widget.wardrobeId}');
                  Navigator.pop(context);
                },
              )).toList(),
            ),
          ],
        ),
      ),
    );
  }
  
  void _performBulkAction() {
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.delete_outline),
              title: const Text('Delete selected'),
              onTap: () {
                // Perform delete
                Navigator.pop(context);
                setState(() {
                  _selectedGarmentIds.clear();
                  _isSelectionMode = false;
                });
                LazyLoadingService.clearCache('garments_${widget.wardrobeId}');
              },
            ),
            ListTile(
              leading: const Icon(Icons.folder_outlined),
              title: const Text('Move to wardrobe'),
              onTap: () {
                // Show wardrobe selection
                Navigator.pop(context);
              },
            ),
            ListTile(
              leading: const Icon(Icons.label_outline),
              title: const Text('Add tags'),
              onTap: () {
                // Show tag dialog
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
    );
  }
  
  // Helper methods
  String _getRandomCategory() {
    final categories = ['Tops', 'Bottoms', 'Dresses', 'Outerwear', 'Shoes', 'Accessories'];
    return categories[DateTime.now().millisecond % categories.length];
  }
  
  String _getRandomColor() {
    final colors = ['Black', 'White', 'Blue', 'Red', 'Green', 'Yellow'];
    return colors[DateTime.now().millisecond % colors.length];
  }
  
  String _getRandomSize() {
    final sizes = ['XS', 'S', 'M', 'L', 'XL', 'XXL'];
    return sizes[DateTime.now().millisecond % sizes.length];
  }
}