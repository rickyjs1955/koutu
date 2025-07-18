import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
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
import 'package:koutu/presentation/router/route_paths.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:cached_network_image/cached_network_image.dart';

enum WardrobeViewType { grid, list }

class WardrobeListScreen extends StatefulWidget {
  const WardrobeListScreen({super.key});

  @override
  State<WardrobeListScreen> createState() => _WardrobeListScreenState();
}

class _WardrobeListScreenState extends State<WardrobeListScreen> {
  WardrobeViewType _viewType = WardrobeViewType.grid;
  String _searchQuery = '';
  String _sortBy = 'name';
  bool _showSharedOnly = false;

  @override
  void initState() {
    super.initState();
    _loadWardrobes();
  }

  void _loadWardrobes() {
    context.read<WardrobeBloc>().add(const LoadWardrobes());
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'My Wardrobes',
        actions: [
          IconButton(
            icon: Icon(
              _viewType == WardrobeViewType.grid
                  ? Icons.list
                  : Icons.grid_view,
            ),
            onPressed: _toggleViewType,
          ),
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: _showFilterOptions,
          ),
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: () => context.push(RoutePaths.createWardrobe),
          ),
        ],
      ),
      body: BlocBuilder<WardrobeBloc, WardrobeState>(
        builder: (context, state) {
          if (state is WardrobeLoading && state.wardrobes.isEmpty) {
            return _buildLoadingState();
          }

          if (state is WardrobeError && state.wardrobes.isEmpty) {
            return AppErrorWidget(
              errorType: ErrorType.generic,
              message: state.message,
              onRetry: _loadWardrobes,
            );
          }

          final wardrobes = _filterAndSortWardrobes(state.wardrobes);

          if (wardrobes.isEmpty) {
            return _buildEmptyState();
          }

          return RefreshIndicator(
            onRefresh: () async {
              _loadWardrobes();
              await Future.delayed(const Duration(seconds: 1));
            },
            child: _viewType == WardrobeViewType.grid
                ? _buildGridView(wardrobes)
                : _buildListView(wardrobes),
          );
        },
      ),
    );
  }

  Widget _buildLoadingState() {
    return _viewType == WardrobeViewType.grid
        ? AppGridSkeleton(
            itemCount: 6,
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            itemBuilder: (context, index) => const AppCardSkeleton(),
          )
        : AppSkeletonLoader(
            itemCount: 5,
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            itemBuilder: (context, index) => const AppListItemSkeleton(),
          );
  }

  Widget _buildEmptyState() {
    return Center(
      child: AppFadeAnimation(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              _showSharedOnly ? Icons.people_outline : Icons.checkroom,
              size: 64,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Text(
              _showSharedOnly
                  ? 'No shared wardrobes'
                  : 'No wardrobes yet',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              _showSharedOnly
                  ? 'Wardrobes shared with you will appear here'
                  : 'Create your first wardrobe to get started',
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
            if (!_showSharedOnly) ...[
              const SizedBox(height: AppDimensions.paddingXL),
              ElevatedButton.icon(
                onPressed: () => context.push(RoutePaths.createWardrobe),
                icon: const Icon(Icons.add),
                label: const Text('Create Wardrobe'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildGridView(List<WardrobeModel> wardrobes) {
    return GridView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: AppDimensions.paddingM,
        mainAxisSpacing: AppDimensions.paddingM,
        childAspectRatio: 0.85,
      ),
      itemCount: wardrobes.length,
      itemBuilder: (context, index) {
        return AppAnimatedListItem(
          index: index,
          child: _WardrobeGridItem(
            wardrobe: wardrobes[index],
            onTap: () => _navigateToWardrobe(wardrobes[index]),
          ),
        );
      },
    );
  }

  Widget _buildListView(List<WardrobeModel> wardrobes) {
    return ListView.separated(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: wardrobes.length,
      separatorBuilder: (context, index) => const SizedBox(
        height: AppDimensions.paddingS,
      ),
      itemBuilder: (context, index) {
        return AppAnimatedListItem(
          index: index,
          child: _WardrobeListItem(
            wardrobe: wardrobes[index],
            onTap: () => _navigateToWardrobe(wardrobes[index]),
          ),
        );
      },
    );
  }

  List<WardrobeModel> _filterAndSortWardrobes(List<WardrobeModel> wardrobes) {
    var filtered = wardrobes.where((wardrobe) {
      // Filter by search query
      if (_searchQuery.isNotEmpty) {
        final query = _searchQuery.toLowerCase();
        if (!wardrobe.name.toLowerCase().contains(query) &&
            !(wardrobe.description?.toLowerCase().contains(query) ?? false)) {
          return false;
        }
      }

      // Filter by shared status
      if (_showSharedOnly && !wardrobe.isShared) {
        return false;
      }

      return true;
    }).toList();

    // Sort wardrobes
    switch (_sortBy) {
      case 'name':
        filtered.sort((a, b) => a.name.compareTo(b.name));
        break;
      case 'date':
        filtered.sort((a, b) => b.createdAt.compareTo(a.createdAt));
        break;
      case 'items':
        filtered.sort((a, b) => b.garmentIds.length.compareTo(a.garmentIds.length));
        break;
    }

    return filtered;
  }

  void _toggleViewType() {
    setState(() {
      _viewType = _viewType == WardrobeViewType.grid
          ? WardrobeViewType.list
          : WardrobeViewType.grid;
    });
  }

  void _showFilterOptions() {
    showModalBottomSheet(
      context: context,
      builder: (context) => _FilterOptionsSheet(
        searchQuery: _searchQuery,
        sortBy: _sortBy,
        showSharedOnly: _showSharedOnly,
        onSearchChanged: (value) => setState(() => _searchQuery = value),
        onSortChanged: (value) => setState(() => _sortBy = value),
        onSharedOnlyChanged: (value) => setState(() => _showSharedOnly = value),
      ),
    );
  }

  void _navigateToWardrobe(WardrobeModel wardrobe) {
    context.push(RoutePaths.wardrobeDetail(wardrobe.id));
  }
}

class _WardrobeGridItem extends StatelessWidget {
  final WardrobeModel wardrobe;
  final VoidCallback onTap;

  const _WardrobeGridItem({
    required this.wardrobe,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Card(
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: onTap,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Image
            AspectRatio(
              aspectRatio: 1,
              child: wardrobe.imageUrl != null
                  ? CachedNetworkImage(
                      imageUrl: wardrobe.imageUrl!,
                      fit: BoxFit.cover,
                      placeholder: (context, url) => Container(
                        color: AppColors.backgroundSecondary,
                        child: const Center(
                          child: AppLoadingIndicator(size: LoadingIndicatorSize.small),
                        ),
                      ),
                      errorWidget: (context, url, error) => Container(
                        color: AppColors.backgroundSecondary,
                        child: Icon(
                          Icons.checkroom,
                          size: 48,
                          color: AppColors.textTertiary,
                        ),
                      ),
                    )
                  : Container(
                      color: theme.colorScheme.primary.withOpacity(0.1),
                      child: Icon(
                        Icons.checkroom,
                        size: 48,
                        color: theme.colorScheme.primary,
                      ),
                    ),
            ),
            // Content
            Expanded(
              child: Padding(
                padding: const EdgeInsets.all(AppDimensions.paddingS),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            wardrobe.name,
                            style: AppTextStyles.labelLarge,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (wardrobe.isDefault)
                          Icon(
                            Icons.star,
                            size: 16,
                            color: AppColors.warning,
                          ),
                        if (wardrobe.isShared)
                          Icon(
                            Icons.people,
                            size: 16,
                            color: theme.colorScheme.primary,
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '${wardrobe.garmentIds.length} items',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _WardrobeListItem extends StatelessWidget {
  final WardrobeModel wardrobe;
  final VoidCallback onTap;

  const _WardrobeListItem({
    required this.wardrobe,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Card(
      child: ListTile(
        onTap: onTap,
        leading: Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            borderRadius: AppDimensions.radiusM,
            color: theme.colorScheme.primary.withOpacity(0.1),
          ),
          clipBehavior: Clip.antiAlias,
          child: wardrobe.imageUrl != null
              ? CachedNetworkImage(
                  imageUrl: wardrobe.imageUrl!,
                  fit: BoxFit.cover,
                )
              : Icon(
                  Icons.checkroom,
                  color: theme.colorScheme.primary,
                ),
        ),
        title: Row(
          children: [
            Expanded(
              child: Text(
                wardrobe.name,
                style: AppTextStyles.bodyLarge.copyWith(
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
            if (wardrobe.isDefault)
              Padding(
                padding: const EdgeInsets.only(left: AppDimensions.paddingXS),
                child: Icon(
                  Icons.star,
                  size: 16,
                  color: AppColors.warning,
                ),
              ),
          ],
        ),
        subtitle: Text(
          wardrobe.description ?? '${wardrobe.garmentIds.length} items',
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (wardrobe.isShared)
              AppBadge(
                text: 'Shared',
                type: AppBadgeType.info,
                size: AppBadgeSize.small,
              ),
            const SizedBox(width: AppDimensions.paddingS),
            const Icon(Icons.chevron_right),
          ],
        ),
      ),
    );
  }
}

class _FilterOptionsSheet extends StatelessWidget {
  final String searchQuery;
  final String sortBy;
  final bool showSharedOnly;
  final ValueChanged<String> onSearchChanged;
  final ValueChanged<String> onSortChanged;
  final ValueChanged<bool> onSharedOnlyChanged;

  const _FilterOptionsSheet({
    required this.searchQuery,
    required this.sortBy,
    required this.showSharedOnly,
    required this.onSearchChanged,
    required this.onSortChanged,
    required this.onSharedOnlyChanged,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Filter & Sort',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          // Search
          TextField(
            decoration: const InputDecoration(
              labelText: 'Search',
              hintText: 'Search by name or description',
              prefixIcon: Icon(Icons.search),
            ),
            onChanged: onSearchChanged,
          ),
          const SizedBox(height: AppDimensions.paddingM),
          // Sort by
          Text(
            'Sort by',
            style: AppTextStyles.labelMedium,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Wrap(
            spacing: AppDimensions.paddingS,
            children: [
              ChoiceChip(
                label: const Text('Name'),
                selected: sortBy == 'name',
                onSelected: (selected) {
                  if (selected) onSortChanged('name');
                },
              ),
              ChoiceChip(
                label: const Text('Date'),
                selected: sortBy == 'date',
                onSelected: (selected) {
                  if (selected) onSortChanged('date');
                },
              ),
              ChoiceChip(
                label: const Text('Items'),
                selected: sortBy == 'items',
                onSelected: (selected) {
                  if (selected) onSortChanged('items');
                },
              ),
            ],
          ),
          const SizedBox(height: AppDimensions.paddingM),
          // Filters
          SwitchListTile(
            title: const Text('Show shared wardrobes only'),
            value: showSharedOnly,
            onChanged: onSharedOnlyChanged,
          ),
          const SizedBox(height: AppDimensions.paddingM),
          // Apply button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Apply'),
            ),
          ),
        ],
      ),
    );
  }
}