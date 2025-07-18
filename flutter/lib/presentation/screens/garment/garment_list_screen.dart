import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/loading/app_skeleton_loader.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/animations/app_animated_list_item.dart';
import 'package:koutu/presentation/widgets/common/app_badge.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/router/route_paths.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:cached_network_image/cached_network_image.dart';

enum GarmentSortOption { name, date, brand, category, wearCount }

class GarmentListScreen extends StatefulWidget {
  const GarmentListScreen({super.key});

  @override
  State<GarmentListScreen> createState() => _GarmentListScreenState();
}

class _GarmentListScreenState extends State<GarmentListScreen> {
  final _searchController = TextEditingController();
  String _searchQuery = '';
  GarmentSortOption _sortOption = GarmentSortOption.date;
  bool _isAscending = false;
  
  // Filter options
  String? _selectedCategory;
  String? _selectedBrand;
  String? _selectedColor;
  String? _selectedSize;
  final List<String> _selectedTags = [];

  // Selected items for bulk operations
  final Set<String> _selectedGarmentIds = {};
  bool _isSelectionMode = false;

  @override
  void initState() {
    super.initState();
    _loadGarments();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _loadGarments() {
    context.read<GarmentBloc>().add(const LoadGarments());
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        if (_isSelectionMode) {
          _exitSelectionMode();
          return false;
        }
        return true;
      },
      child: Scaffold(
        appBar: _isSelectionMode ? _buildSelectionAppBar() : _buildNormalAppBar(),
        body: Column(
          children: [
            // Search bar
            _buildSearchBar(),
            // Content
            Expanded(
              child: BlocBuilder<GarmentBloc, GarmentState>(
                builder: (context, state) {
                  if (state is GarmentLoading && state.garments.isEmpty) {
                    return _buildLoadingState();
                  }

                  if (state is GarmentError && state.garments.isEmpty) {
                    return AppErrorWidget(
                      errorType: ErrorType.generic,
                      message: state.message,
                      onRetry: _loadGarments,
                    );
                  }

                  final garments = _filterAndSortGarments(state.garments);

                  if (garments.isEmpty) {
                    return _buildEmptyState();
                  }

                  return RefreshIndicator(
                    onRefresh: () async {
                      _loadGarments();
                      await Future.delayed(const Duration(seconds: 1));
                    },
                    child: _buildGarmentGrid(garments),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  PreferredSizeWidget _buildNormalAppBar() {
    return AppCustomAppBar(
      title: 'All Garments',
      actions: [
        IconButton(
          icon: const Icon(Icons.filter_list),
          onPressed: _showFilterOptions,
        ),
        IconButton(
          icon: const Icon(Icons.sort),
          onPressed: _showSortOptions,
        ),
      ],
    );
  }

  PreferredSizeWidget _buildSelectionAppBar() {
    return AppCustomAppBar(
      leading: IconButton(
        icon: const Icon(Icons.close),
        onPressed: _exitSelectionMode,
      ),
      title: '${_selectedGarmentIds.length} selected',
      actions: [
        IconButton(
          icon: const Icon(Icons.select_all),
          onPressed: _selectAll,
        ),
        PopupMenuButton<String>(
          onSelected: _handleBulkAction,
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'favorite',
              child: Row(
                children: [
                  Icon(Icons.favorite),
                  SizedBox(width: 8),
                  Text('Add to Favorites'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'move',
              child: Row(
                children: [
                  Icon(Icons.drive_file_move),
                  SizedBox(width: 8),
                  Text('Move to Wardrobe'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'tags',
              child: Row(
                children: [
                  Icon(Icons.label),
                  SizedBox(width: 8),
                  Text('Add Tags'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'delete',
              child: Row(
                children: [
                  Icon(Icons.delete, color: AppColors.error),
                  SizedBox(width: 8),
                  Text('Delete', style: TextStyle(color: AppColors.error)),
                ],
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildSearchBar() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      child: TextField(
        controller: _searchController,
        decoration: InputDecoration(
          hintText: 'Search garments...',
          prefixIcon: const Icon(Icons.search),
          suffixIcon: _searchQuery.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.clear),
                  onPressed: () {
                    setState(() {
                      _searchController.clear();
                      _searchQuery = '';
                    });
                  },
                )
              : null,
          border: OutlineInputBorder(
            borderRadius: AppDimensions.radiusL,
            borderSide: BorderSide.none,
          ),
          filled: true,
          fillColor: AppColors.backgroundSecondary,
        ),
        onChanged: (value) {
          setState(() {
            _searchQuery = value;
          });
        },
      ),
    );
  }

  Widget _buildLoadingState() {
    return AppGridSkeleton(
      itemCount: 6,
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemBuilder: (context, index) => const AppCardSkeleton(),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: AppFadeAnimation(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.checkroom,
              size: 64,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Text(
              _searchQuery.isNotEmpty || _hasActiveFilters()
                  ? 'No garments found'
                  : 'No garments yet',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              _searchQuery.isNotEmpty || _hasActiveFilters()
                  ? 'Try adjusting your search or filters'
                  : 'Add garments to your wardrobes to see them here',
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
            if (_searchQuery.isNotEmpty || _hasActiveFilters()) ...[
              const SizedBox(height: AppDimensions.paddingXL),
              TextButton(
                onPressed: _clearFilters,
                child: const Text('Clear filters'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildGarmentGrid(List<GarmentModel> garments) {
    return GridView.builder(
      padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: AppDimensions.paddingM,
        mainAxisSpacing: AppDimensions.paddingM,
        childAspectRatio: 0.7,
      ),
      itemCount: garments.length,
      itemBuilder: (context, index) {
        final garment = garments[index];
        final isSelected = _selectedGarmentIds.contains(garment.id);
        
        return AppAnimatedListItem(
          index: index,
          child: GestureDetector(
            onLongPress: () {
              if (!_isSelectionMode) {
                _enterSelectionMode(garment.id);
              }
            },
            child: _GarmentGridItem(
              garment: garment,
              isSelected: isSelected,
              isSelectionMode: _isSelectionMode,
              onTap: () {
                if (_isSelectionMode) {
                  _toggleSelection(garment.id);
                } else {
                  _navigateToGarmentDetail(garment);
                }
              },
            ),
          ),
        );
      },
    );
  }

  List<GarmentModel> _filterAndSortGarments(List<GarmentModel> garments) {
    // Apply search
    var filtered = garments.where((garment) {
      if (_searchQuery.isNotEmpty) {
        final query = _searchQuery.toLowerCase();
        if (!garment.name.toLowerCase().contains(query) &&
            !(garment.brand?.toLowerCase().contains(query) ?? false) &&
            !garment.tags.any((tag) => tag.toLowerCase().contains(query))) {
          return false;
        }
      }

      // Apply filters
      if (_selectedCategory != null && garment.category != _selectedCategory) {
        return false;
      }
      if (_selectedBrand != null && garment.brand != _selectedBrand) {
        return false;
      }
      if (_selectedColor != null && !garment.colors.contains(_selectedColor)) {
        return false;
      }
      if (_selectedSize != null && garment.size != _selectedSize) {
        return false;
      }
      if (_selectedTags.isNotEmpty && 
          !_selectedTags.any((tag) => garment.tags.contains(tag))) {
        return false;
      }

      return true;
    }).toList();

    // Apply sort
    switch (_sortOption) {
      case GarmentSortOption.name:
        filtered.sort((a, b) => _isAscending
            ? a.name.compareTo(b.name)
            : b.name.compareTo(a.name));
        break;
      case GarmentSortOption.date:
        filtered.sort((a, b) => _isAscending
            ? a.createdAt.compareTo(b.createdAt)
            : b.createdAt.compareTo(a.createdAt));
        break;
      case GarmentSortOption.brand:
        filtered.sort((a, b) {
          final aBrand = a.brand ?? '';
          final bBrand = b.brand ?? '';
          return _isAscending
              ? aBrand.compareTo(bBrand)
              : bBrand.compareTo(aBrand);
        });
        break;
      case GarmentSortOption.category:
        filtered.sort((a, b) => _isAscending
            ? a.category.compareTo(b.category)
            : b.category.compareTo(a.category));
        break;
      case GarmentSortOption.wearCount:
        filtered.sort((a, b) => _isAscending
            ? a.wearCount.compareTo(b.wearCount)
            : b.wearCount.compareTo(a.wearCount));
        break;
    }

    return filtered;
  }

  bool _hasActiveFilters() {
    return _selectedCategory != null ||
        _selectedBrand != null ||
        _selectedColor != null ||
        _selectedSize != null ||
        _selectedTags.isNotEmpty;
  }

  void _clearFilters() {
    setState(() {
      _searchController.clear();
      _searchQuery = '';
      _selectedCategory = null;
      _selectedBrand = null;
      _selectedColor = null;
      _selectedSize = null;
      _selectedTags.clear();
    });
  }

  void _showFilterOptions() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => _GarmentFilterSheet(
        selectedCategory: _selectedCategory,
        selectedBrand: _selectedBrand,
        selectedColor: _selectedColor,
        selectedSize: _selectedSize,
        selectedTags: _selectedTags,
        onFiltersChanged: (category, brand, color, size, tags) {
          setState(() {
            _selectedCategory = category;
            _selectedBrand = brand;
            _selectedColor = color;
            _selectedSize = size;
            _selectedTags.clear();
            _selectedTags.addAll(tags);
          });
        },
        garments: context.read<GarmentBloc>().state.garments,
      ),
    );
  }

  void _showSortOptions() {
    showModalBottomSheet(
      context: context,
      builder: (context) => Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Sort by',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            RadioListTile<GarmentSortOption>(
              title: const Text('Date Added'),
              subtitle: Text(_isAscending ? 'Oldest first' : 'Newest first'),
              value: GarmentSortOption.date,
              groupValue: _sortOption,
              onChanged: (value) => _updateSort(value!),
            ),
            RadioListTile<GarmentSortOption>(
              title: const Text('Name'),
              subtitle: Text(_isAscending ? 'A to Z' : 'Z to A'),
              value: GarmentSortOption.name,
              groupValue: _sortOption,
              onChanged: (value) => _updateSort(value!),
            ),
            RadioListTile<GarmentSortOption>(
              title: const Text('Brand'),
              subtitle: Text(_isAscending ? 'A to Z' : 'Z to A'),
              value: GarmentSortOption.brand,
              groupValue: _sortOption,
              onChanged: (value) => _updateSort(value!),
            ),
            RadioListTile<GarmentSortOption>(
              title: const Text('Category'),
              subtitle: Text(_isAscending ? 'A to Z' : 'Z to A'),
              value: GarmentSortOption.category,
              groupValue: _sortOption,
              onChanged: (value) => _updateSort(value!),
            ),
            RadioListTile<GarmentSortOption>(
              title: const Text('Wear Count'),
              subtitle: Text(_isAscending ? 'Least worn' : 'Most worn'),
              value: GarmentSortOption.wearCount,
              groupValue: _sortOption,
              onChanged: (value) => _updateSort(value!),
            ),
            const Divider(),
            SwitchListTile(
              title: const Text('Ascending order'),
              value: _isAscending,
              onChanged: (value) {
                setState(() {
                  _isAscending = value;
                });
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _updateSort(GarmentSortOption option) {
    setState(() {
      if (_sortOption == option) {
        _isAscending = !_isAscending;
      } else {
        _sortOption = option;
        _isAscending = false;
      }
    });
    Navigator.pop(context);
  }

  void _enterSelectionMode(String garmentId) {
    setState(() {
      _isSelectionMode = true;
      _selectedGarmentIds.add(garmentId);
    });
  }

  void _exitSelectionMode() {
    setState(() {
      _isSelectionMode = false;
      _selectedGarmentIds.clear();
    });
  }

  void _toggleSelection(String garmentId) {
    setState(() {
      if (_selectedGarmentIds.contains(garmentId)) {
        _selectedGarmentIds.remove(garmentId);
        if (_selectedGarmentIds.isEmpty) {
          _isSelectionMode = false;
        }
      } else {
        _selectedGarmentIds.add(garmentId);
      }
    });
  }

  void _selectAll() {
    final garments = context.read<GarmentBloc>().state.garments;
    setState(() {
      _selectedGarmentIds.clear();
      _selectedGarmentIds.addAll(garments.map((g) => g.id));
    });
  }

  void _handleBulkAction(String action) {
    switch (action) {
      case 'favorite':
        _addToFavorites();
        break;
      case 'move':
        _moveToWardrobe();
        break;
      case 'tags':
        _addTags();
        break;
      case 'delete':
        _deleteSelected();
        break;
    }
  }

  void _addToFavorites() {
    // TODO: Implement add to favorites
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Added ${_selectedGarmentIds.length} items to favorites'),
        backgroundColor: AppColors.success,
      ),
    );
    _exitSelectionMode();
  }

  void _moveToWardrobe() {
    // TODO: Show wardrobe selection dialog
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Move to wardrobe coming soon'),
      ),
    );
  }

  void _addTags() {
    // TODO: Show tag selection dialog
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Add tags coming soon'),
      ),
    );
  }

  void _deleteSelected() {
    AppDialog.confirm(
      context,
      title: 'Delete Garments',
      message: 'Are you sure you want to delete ${_selectedGarmentIds.length} garments? This action cannot be undone.',
      confirmText: 'Delete',
      confirmIsDestructive: true,
      onConfirm: () {
        for (final id in _selectedGarmentIds) {
          context.read<GarmentBloc>().add(DeleteGarment(id));
        }
        _exitSelectionMode();
      },
    );
  }

  void _navigateToGarmentDetail(GarmentModel garment) {
    context.push(RoutePaths.garmentDetail(garment.id));
  }
}

class _GarmentGridItem extends StatelessWidget {
  final GarmentModel garment;
  final bool isSelected;
  final bool isSelectionMode;
  final VoidCallback onTap;

  const _GarmentGridItem({
    required this.garment,
    required this.isSelected,
    required this.isSelectionMode,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      clipBehavior: Clip.antiAlias,
      elevation: isSelected ? 4 : 1,
      child: InkWell(
        onTap: onTap,
        child: Stack(
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Image
                AspectRatio(
                  aspectRatio: 1,
                  child: garment.images.isNotEmpty
                      ? CachedNetworkImage(
                          imageUrl: garment.images.first.url,
                          fit: BoxFit.cover,
                          placeholder: (context, url) => Container(
                            color: AppColors.backgroundSecondary,
                            child: const Center(
                              child: AppLoadingIndicator(
                                size: LoadingIndicatorSize.small,
                              ),
                            ),
                          ),
                        )
                      : Container(
                          color: AppColors.backgroundSecondary,
                          child: Icon(
                            Icons.checkroom,
                            size: 48,
                            color: AppColors.textTertiary,
                          ),
                        ),
                ),
                // Details
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.all(AppDimensions.paddingS),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          garment.name,
                          style: AppTextStyles.labelLarge,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        if (garment.brand != null) ...[
                          const SizedBox(height: 2),
                          Text(
                            garment.brand!,
                            style: AppTextStyles.caption.copyWith(
                              color: AppColors.textSecondary,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                        const Spacer(),
                        Row(
                          children: [
                            // Colors
                            ...garment.colors.take(3).map((color) => Container(
                                  width: 12,
                                  height: 12,
                                  margin: const EdgeInsets.only(right: 4),
                                  decoration: BoxDecoration(
                                    shape: BoxShape.circle,
                                    color: _getColorFromName(color),
                                    border: Border.all(
                                      color: AppColors.border,
                                      width: 0.5,
                                    ),
                                  ),
                                )),
                            const Spacer(),
                            // Wear count
                            if (garment.wearCount > 0)
                              Text(
                                '${garment.wearCount}x',
                                style: AppTextStyles.caption.copyWith(
                                  color: AppColors.textTertiary,
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
            // Selection overlay
            if (isSelectionMode)
              Positioned(
                top: 8,
                right: 8,
                child: Container(
                  width: 24,
                  height: 24,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: isSelected ? AppColors.primary : Colors.white,
                    border: Border.all(
                      color: isSelected ? AppColors.primary : AppColors.border,
                      width: 2,
                    ),
                  ),
                  child: isSelected
                      ? const Icon(
                          Icons.check,
                          size: 16,
                          color: Colors.white,
                        )
                      : null,
                ),
              ),
            // Favorite indicator
            if (garment.isFavorite && !isSelectionMode)
              Positioned(
                top: 8,
                right: 8,
                child: Container(
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.1),
                        blurRadius: 4,
                      ),
                    ],
                  ),
                  child: Icon(
                    Icons.favorite,
                    size: 16,
                    color: AppColors.error,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Color _getColorFromName(String colorName) {
    // TODO: Map color names to actual colors from AppConstants
    final colors = {
      'black': Colors.black,
      'white': Colors.white,
      'grey': Colors.grey,
      'red': Colors.red,
      'blue': Colors.blue,
      'green': Colors.green,
      'yellow': Colors.yellow,
      'orange': Colors.orange,
      'purple': Colors.purple,
      'pink': Colors.pink,
      'brown': Colors.brown,
    };
    return colors[colorName.toLowerCase()] ?? Colors.grey;
  }
}

// Filter sheet widget would be in a separate file in production
class _GarmentFilterSheet extends StatefulWidget {
  final String? selectedCategory;
  final String? selectedBrand;
  final String? selectedColor;
  final String? selectedSize;
  final List<String> selectedTags;
  final List<GarmentModel> garments;
  final Function(String?, String?, String?, String?, List<String>) onFiltersChanged;

  const _GarmentFilterSheet({
    required this.selectedCategory,
    required this.selectedBrand,
    required this.selectedColor,
    required this.selectedSize,
    required this.selectedTags,
    required this.garments,
    required this.onFiltersChanged,
  });

  @override
  State<_GarmentFilterSheet> createState() => _GarmentFilterSheetState();
}

class _GarmentFilterSheetState extends State<_GarmentFilterSheet> {
  late String? _category = widget.selectedCategory;
  late String? _brand = widget.selectedBrand;
  late String? _color = widget.selectedColor;
  late String? _size = widget.selectedSize;
  late final List<String> _tags = List.from(widget.selectedTags);

  @override
  Widget build(BuildContext context) {
    // Extract unique values from garments
    final categories = widget.garments.map((g) => g.category).toSet().toList()..sort();
    final brands = widget.garments
        .map((g) => g.brand)
        .where((b) => b != null)
        .cast<String>()
        .toSet()
        .toList()
      ..sort();
    final colors = widget.garments
        .expand((g) => g.colors)
        .toSet()
        .toList()
      ..sort();
    final sizes = widget.garments
        .map((g) => g.size)
        .where((s) => s != null)
        .cast<String>()
        .toSet()
        .toList();
    final tags = widget.garments
        .expand((g) => g.tags)
        .toSet()
        .toList()
      ..sort();

    return DraggableScrollableSheet(
      initialChildSize: 0.8,
      minChildSize: 0.5,
      maxChildSize: 0.9,
      builder: (context, scrollController) => Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Filter Garments',
                  style: AppTextStyles.h3,
                ),
                TextButton(
                  onPressed: () {
                    setState(() {
                      _category = null;
                      _brand = null;
                      _color = null;
                      _size = null;
                      _tags.clear();
                    });
                  },
                  child: const Text('Clear all'),
                ),
              ],
            ),
            const SizedBox(height: AppDimensions.paddingL),
            // Filter options
            Expanded(
              child: ListView(
                controller: scrollController,
                children: [
                  // Category
                  _buildFilterSection(
                    'Category',
                    categories,
                    _category,
                    (value) => setState(() => _category = value),
                  ),
                  const SizedBox(height: AppDimensions.paddingL),
                  // Brand
                  if (brands.isNotEmpty) ...[
                    _buildFilterSection(
                      'Brand',
                      brands,
                      _brand,
                      (value) => setState(() => _brand = value),
                    ),
                    const SizedBox(height: AppDimensions.paddingL),
                  ],
                  // Color
                  _buildColorFilter(colors),
                  const SizedBox(height: AppDimensions.paddingL),
                  // Size
                  if (sizes.isNotEmpty) ...[
                    _buildFilterSection(
                      'Size',
                      sizes,
                      _size,
                      (value) => setState(() => _size = value),
                    ),
                    const SizedBox(height: AppDimensions.paddingL),
                  ],
                  // Tags
                  if (tags.isNotEmpty) ...[
                    _buildTagFilter(tags),
                    const SizedBox(height: AppDimensions.paddingL),
                  ],
                ],
              ),
            ),
            // Apply button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: () {
                  widget.onFiltersChanged(_category, _brand, _color, _size, _tags);
                  Navigator.pop(context);
                },
                child: const Text('Apply Filters'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterSection(
    String title,
    List<String> options,
    String? selectedValue,
    ValueChanged<String?> onChanged,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: [
            ChoiceChip(
              label: const Text('All'),
              selected: selectedValue == null,
              onSelected: (selected) {
                if (selected) onChanged(null);
              },
            ),
            ...options.map((option) => ChoiceChip(
                  label: Text(option.capitalize()),
                  selected: selectedValue == option,
                  onSelected: (selected) {
                    onChanged(selected ? option : null);
                  },
                )),
          ],
        ),
      ],
    );
  }

  Widget _buildColorFilter(List<String> colors) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Color',
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: colors.map((color) {
            final isSelected = _color == color;
            return InkWell(
              onTap: () {
                setState(() {
                  _color = isSelected ? null : color;
                });
              },
              borderRadius: BorderRadius.circular(24),
              child: Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: _getColorFromName(color),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected ? AppColors.textPrimary : AppColors.border,
                    width: isSelected ? 3 : 1,
                  ),
                ),
                child: isSelected
                    ? const Icon(
                        Icons.check,
                        color: Colors.white,
                        size: 20,
                      )
                    : null,
              ),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildTagFilter(List<String> tags) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Tags',
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: tags.map((tag) {
            final isSelected = _tags.contains(tag);
            return FilterChip(
              label: Text(tag),
              selected: isSelected,
              onSelected: (selected) {
                setState(() {
                  if (selected) {
                    _tags.add(tag);
                  } else {
                    _tags.remove(tag);
                  }
                });
              },
            );
          }).toList(),
        ),
      ],
    );
  }

  Color _getColorFromName(String colorName) {
    final colors = {
      'black': Colors.black,
      'white': Colors.white,
      'grey': Colors.grey,
      'red': Colors.red,
      'blue': Colors.blue,
      'green': Colors.green,
      'yellow': Colors.yellow,
      'orange': Colors.orange,
      'purple': Colors.purple,
      'pink': Colors.pink,
      'brown': Colors.brown,
    };
    return colors[colorName.toLowerCase()] ?? Colors.grey;
  }
}

extension StringExtension on String {
  String capitalize() {
    return "${this[0].toUpperCase()}${substring(1)}";
  }
}