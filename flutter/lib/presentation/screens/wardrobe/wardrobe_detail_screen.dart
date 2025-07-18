import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/animations/app_animated_list_item.dart';
import 'package:koutu/presentation/widgets/common/app_badge.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/router/route_paths.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:share_plus/share_plus.dart';

class WardrobeDetailScreen extends StatefulWidget {
  final String wardrobeId;

  const WardrobeDetailScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<WardrobeDetailScreen> createState() => _WardrobeDetailScreenState();
}

class _WardrobeDetailScreenState extends State<WardrobeDetailScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  String _selectedCategory = 'all';
  String _sortBy = 'date';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadWardrobeDetails();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  void _loadWardrobeDetails() {
    context.read<WardrobeBloc>().add(LoadWardrobeDetail(widget.wardrobeId));
    context.read<GarmentBloc>().add(LoadGarmentsByWardrobe(widget.wardrobeId));
  }

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<WardrobeBloc, WardrobeState>(
      builder: (context, wardrobeState) {
        final wardrobe = _findWardrobe(wardrobeState);

        if (wardrobe == null && wardrobeState is! WardrobeLoading) {
          return Scaffold(
            appBar: AppCustomAppBar(title: 'Wardrobe'),
            body: AppErrorWidget(
              errorType: ErrorType.notFound,
              message: 'Wardrobe not found',
              onRetry: _loadWardrobeDetails,
            ),
          );
        }

        return Scaffold(
          body: CustomScrollView(
            slivers: [
              // Custom App Bar with Image
              SliverAppBar(
                expandedHeight: 250,
                pinned: true,
                flexibleSpace: FlexibleSpaceBar(
                  title: Text(
                    wardrobe?.name ?? 'Loading...',
                    style: AppTextStyles.h3.copyWith(color: Colors.white),
                  ),
                  background: Stack(
                    fit: StackFit.expand,
                    children: [
                      if (wardrobe?.imageUrl != null)
                        CachedNetworkImage(
                          imageUrl: wardrobe!.imageUrl!,
                          fit: BoxFit.cover,
                        )
                      else
                        Container(
                          color: Theme.of(context).colorScheme.primary,
                          child: const Icon(
                            Icons.checkroom,
                            size: 80,
                            color: Colors.white24,
                          ),
                        ),
                      Container(
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
                      ),
                    ],
                  ),
                ),
                actions: [
                  if (wardrobe != null) ...[
                    IconButton(
                      icon: const Icon(Icons.share),
                      onPressed: () => _shareWardrobe(wardrobe),
                    ),
                    PopupMenuButton<String>(
                      onSelected: (value) => _handleMenuAction(value, wardrobe),
                      itemBuilder: (context) => [
                        const PopupMenuItem(
                          value: 'edit',
                          child: Row(
                            children: [
                              Icon(Icons.edit),
                              SizedBox(width: 8),
                              Text('Edit'),
                            ],
                          ),
                        ),
                        const PopupMenuItem(
                          value: 'stats',
                          child: Row(
                            children: [
                              Icon(Icons.analytics),
                              SizedBox(width: 8),
                              Text('Statistics'),
                            ],
                          ),
                        ),
                        if (!wardrobe.isDefault)
                          const PopupMenuItem(
                            value: 'set_default',
                            child: Row(
                              children: [
                                Icon(Icons.star),
                                SizedBox(width: 8),
                                Text('Set as Default'),
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
                ],
              ),

              // Wardrobe Info
              if (wardrobe != null)
                SliverToBoxAdapter(
                  child: _buildWardrobeInfo(wardrobe),
                ),

              // Tab Bar
              SliverPersistentHeader(
                pinned: true,
                delegate: _SliverTabBarDelegate(
                  TabBar(
                    controller: _tabController,
                    tabs: const [
                      Tab(text: 'Garments'),
                      Tab(text: 'Outfits'),
                      Tab(text: 'Statistics'),
                    ],
                  ),
                ),
              ),

              // Tab Content
              SliverFillRemaining(
                child: TabBarView(
                  controller: _tabController,
                  children: [
                    _buildGarmentsTab(),
                    _buildOutfitsTab(),
                    _buildStatisticsTab(wardrobe),
                  ],
                ),
              ),
            ],
          ),
          floatingActionButton: wardrobe != null
              ? FloatingActionButton.extended(
                  onPressed: () => _addGarment(wardrobe),
                  icon: const Icon(Icons.add),
                  label: const Text('Add Garment'),
                )
              : null,
        );
      },
    );
  }

  Widget _buildWardrobeInfo(WardrobeModel wardrobe) {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Description
          if (wardrobe.description != null) ...[
            Text(
              wardrobe.description!,
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
            const SizedBox(height: AppDimensions.paddingM),
          ],

          // Badges
          Wrap(
            spacing: AppDimensions.paddingS,
            children: [
              if (wardrobe.isDefault)
                const AppBadge(
                  text: 'Default',
                  icon: Icons.star,
                  type: AppBadgeType.warning,
                ),
              if (wardrobe.isShared)
                const AppBadge(
                  text: 'Shared',
                  icon: Icons.people,
                  type: AppBadgeType.info,
                ),
              AppBadge(
                text: '${wardrobe.garmentIds.length} items',
                type: AppBadgeType.neutral,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildGarmentsTab() {
    return BlocBuilder<GarmentBloc, GarmentState>(
      builder: (context, state) {
        if (state is GarmentLoading) {
          return const Center(child: AppLoadingIndicator());
        }

        if (state is GarmentError) {
          return AppErrorWidget(
            errorType: ErrorType.generic,
            message: state.message,
            onRetry: () => context.read<GarmentBloc>().add(
              LoadGarmentsByWardrobe(widget.wardrobeId),
            ),
          );
        }

        final garments = _filterAndSortGarments(state.garments);

        if (garments.isEmpty) {
          return _buildEmptyGarmentsState();
        }

        return Column(
          children: [
            // Filter Bar
            _buildFilterBar(),
            // Garment Grid
            Expanded(
              child: GridView.builder(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 2,
                  crossAxisSpacing: AppDimensions.paddingM,
                  mainAxisSpacing: AppDimensions.paddingM,
                  childAspectRatio: 0.75,
                ),
                itemCount: garments.length,
                itemBuilder: (context, index) {
                  return AppAnimatedListItem(
                    index: index,
                    child: _GarmentGridItem(
                      garment: garments[index],
                      onTap: () => _navigateToGarment(garments[index]),
                    ),
                  );
                },
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _buildOutfitsTab() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.style,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Outfits coming soon!',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Create and save outfit combinations',
            style: AppTextStyles.bodyLarge.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatisticsTab(WardrobeModel? wardrobe) {
    if (wardrobe == null) {
      return const Center(child: AppLoadingIndicator());
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _WardrobeStatisticsWidget(wardrobe: wardrobe),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    final categories = ['all', 'tops', 'bottoms', 'dresses', 'outerwear', 'shoes', 'accessories'];

    return Container(
      height: 50,
      padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
      child: Row(
        children: [
          // Category Filter
          Expanded(
            child: ListView.separated(
              scrollDirection: Axis.horizontal,
              itemCount: categories.length,
              separatorBuilder: (context, index) => const SizedBox(width: 8),
              itemBuilder: (context, index) {
                final category = categories[index];
                final isSelected = _selectedCategory == category;
                return FilterChip(
                  label: Text(category.capitalize()),
                  selected: isSelected,
                  onSelected: (selected) {
                    setState(() {
                      _selectedCategory = selected ? category : 'all';
                    });
                  },
                );
              },
            ),
          ),
          // Sort Button
          IconButton(
            icon: const Icon(Icons.sort),
            onPressed: _showSortOptions,
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyGarmentsState() {
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
            const Text(
              'No garments yet',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              'Add your first garment to this wardrobe',
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
            const SizedBox(height: AppDimensions.paddingXL),
            ElevatedButton.icon(
              onPressed: () => _addGarment(_findWardrobe(
                context.read<WardrobeBloc>().state,
              )!),
              icon: const Icon(Icons.add),
              label: const Text('Add Garment'),
            ),
          ],
        ),
      ),
    );
  }

  List<GarmentModel> _filterAndSortGarments(List<GarmentModel> garments) {
    var filtered = garments.where((garment) {
      if (_selectedCategory != 'all' && garment.category != _selectedCategory) {
        return false;
      }
      return true;
    }).toList();

    switch (_sortBy) {
      case 'name':
        filtered.sort((a, b) => a.name.compareTo(b.name));
        break;
      case 'date':
        filtered.sort((a, b) => b.createdAt.compareTo(a.createdAt));
        break;
      case 'brand':
        filtered.sort((a, b) => (a.brand ?? '').compareTo(b.brand ?? ''));
        break;
    }

    return filtered;
  }

  WardrobeModel? _findWardrobe(WardrobeState state) {
    return state.wardrobes.firstWhere(
      (w) => w.id == widget.wardrobeId,
      orElse: () => state is WardrobeSuccess && state.selectedWardrobe?.id == widget.wardrobeId
          ? state.selectedWardrobe!
          : null as WardrobeModel,
    );
  }

  void _shareWardrobe(WardrobeModel wardrobe) {
    final text = 'Check out my ${wardrobe.name} wardrobe on Koutu!';
    Share.share(text);
  }

  void _handleMenuAction(String action, WardrobeModel wardrobe) {
    switch (action) {
      case 'edit':
        context.push(RoutePaths.editWardrobe(wardrobe.id));
        break;
      case 'stats':
        _tabController.animateTo(2);
        break;
      case 'set_default':
        context.read<WardrobeBloc>().add(SetDefaultWardrobe(wardrobe.id));
        break;
      case 'delete':
        AppDialog.confirm(
          context,
          title: 'Delete Wardrobe',
          message: 'Are you sure you want to delete "${wardrobe.name}"? This action cannot be undone.',
          confirmText: 'Delete',
          confirmIsDestructive: true,
          onConfirm: () {
            context.read<WardrobeBloc>().add(DeleteWardrobe(wardrobe.id));
            context.pop();
          },
        );
        break;
    }
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
            const Text(
              'Sort by',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            RadioListTile<String>(
              title: const Text('Date Added'),
              value: 'date',
              groupValue: _sortBy,
              onChanged: (value) {
                setState(() => _sortBy = value!);
                Navigator.pop(context);
              },
            ),
            RadioListTile<String>(
              title: const Text('Name'),
              value: 'name',
              groupValue: _sortBy,
              onChanged: (value) {
                setState(() => _sortBy = value!);
                Navigator.pop(context);
              },
            ),
            RadioListTile<String>(
              title: const Text('Brand'),
              value: 'brand',
              groupValue: _sortBy,
              onChanged: (value) {
                setState(() => _sortBy = value!);
                Navigator.pop(context);
              },
            ),
          ],
        ),
      ),
    );
  }

  void _addGarment(WardrobeModel wardrobe) {
    context.push(RoutePaths.addGarment(wardrobe.id));
  }

  void _navigateToGarment(GarmentModel garment) {
    context.push(RoutePaths.garmentDetail(garment.id));
  }
}

class _GarmentGridItem extends StatelessWidget {
  final GarmentModel garment;
  final VoidCallback onTap;

  const _GarmentGridItem({
    required this.garment,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
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
              child: garment.images.isNotEmpty
                  ? CachedNetworkImage(
                      imageUrl: garment.images.first.url,
                      fit: BoxFit.cover,
                      placeholder: (context, url) => Container(
                        color: AppColors.backgroundSecondary,
                        child: const Center(
                          child: AppLoadingIndicator(size: LoadingIndicatorSize.small),
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

class _WardrobeStatisticsWidget extends StatelessWidget {
  final WardrobeModel wardrobe;

  const _WardrobeStatisticsWidget({required this.wardrobe});

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<GarmentBloc, GarmentState>(
      builder: (context, state) {
        final garments = state.garments.where((g) => g.wardrobeId == wardrobe.id).toList();

        // Calculate statistics
        final categoryCount = _calculateCategoryDistribution(garments);
        final colorCount = _calculateColorDistribution(garments);
        final brandCount = _calculateBrandDistribution(garments);
        final totalValue = _calculateTotalValue(garments);

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Overview Card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(AppDimensions.paddingL),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Overview',
                      style: AppTextStyles.h3,
                    ),
                    const SizedBox(height: AppDimensions.paddingM),
                    _StatRow(
                      icon: Icons.checkroom,
                      label: 'Total Items',
                      value: garments.length.toString(),
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    _StatRow(
                      icon: Icons.category,
                      label: 'Categories',
                      value: categoryCount.keys.length.toString(),
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    _StatRow(
                      icon: Icons.palette,
                      label: 'Colors',
                      value: colorCount.keys.length.toString(),
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    _StatRow(
                      icon: Icons.business,
                      label: 'Brands',
                      value: brandCount.keys.length.toString(),
                    ),
                    if (totalValue > 0) ...[
                      const SizedBox(height: AppDimensions.paddingS),
                      _StatRow(
                        icon: Icons.attach_money,
                        label: 'Total Value',
                        value: '\$${totalValue.toStringAsFixed(2)}',
                      ),
                    ],
                  ],
                ),
              ),
            ),

            const SizedBox(height: AppDimensions.paddingL),

            // Category Distribution
            if (categoryCount.isNotEmpty) ...[
              const Text(
                'Categories',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              ...categoryCount.entries.map((entry) => Padding(
                    padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
                    child: _DistributionBar(
                      label: entry.key.capitalize(),
                      value: entry.value,
                      total: garments.length,
                      color: _getCategoryColor(entry.key),
                    ),
                  )),
            ],

            const SizedBox(height: AppDimensions.paddingL),

            // Top Brands
            if (brandCount.isNotEmpty) ...[
              const Text(
                'Top Brands',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              ...brandCount.entries.take(5).map((entry) => Padding(
                    padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          entry.key,
                          style: AppTextStyles.bodyMedium,
                        ),
                        AppBadge(
                          text: entry.value.toString(),
                          type: AppBadgeType.neutral,
                          size: AppBadgeSize.small,
                        ),
                      ],
                    ),
                  )),
            ],
          ],
        );
      },
    );
  }

  Map<String, int> _calculateCategoryDistribution(List<GarmentModel> garments) {
    final distribution = <String, int>{};
    for (final garment in garments) {
      distribution[garment.category] = (distribution[garment.category] ?? 0) + 1;
    }
    return distribution;
  }

  Map<String, int> _calculateColorDistribution(List<GarmentModel> garments) {
    final distribution = <String, int>{};
    for (final garment in garments) {
      for (final color in garment.colors) {
        distribution[color] = (distribution[color] ?? 0) + 1;
      }
    }
    return distribution;
  }

  Map<String, int> _calculateBrandDistribution(List<GarmentModel> garments) {
    final distribution = <String, int>{};
    for (final garment in garments) {
      if (garment.brand != null) {
        distribution[garment.brand!] = (distribution[garment.brand!] ?? 0) + 1;
      }
    }
    // Sort by count
    final sorted = distribution.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    return Map.fromEntries(sorted);
  }

  double _calculateTotalValue(List<GarmentModel> garments) {
    return garments.fold(0.0, (sum, garment) => sum + (garment.price ?? 0));
  }

  Color _getCategoryColor(String category) {
    final colors = {
      'tops': Colors.blue,
      'bottoms': Colors.green,
      'dresses': Colors.pink,
      'outerwear': Colors.orange,
      'shoes': Colors.brown,
      'accessories': Colors.purple,
    };
    return colors[category] ?? Colors.grey;
  }
}

class _StatRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;

  const _StatRow({
    required this.icon,
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 20, color: AppColors.textSecondary),
        const SizedBox(width: AppDimensions.paddingS),
        Expanded(
          child: Text(
            label,
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ),
        Text(
          value,
          style: AppTextStyles.bodyLarge.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }
}

class _DistributionBar extends StatelessWidget {
  final String label;
  final int value;
  final int total;
  final Color color;

  const _DistributionBar({
    required this.label,
    required this.value,
    required this.total,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    final percentage = (value / total * 100).toStringAsFixed(0);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label, style: AppTextStyles.bodyMedium),
            Text('$value ($percentage%)', style: AppTextStyles.caption),
          ],
        ),
        const SizedBox(height: 4),
        LinearProgressIndicator(
          value: value / total,
          backgroundColor: color.withOpacity(0.2),
          valueColor: AlwaysStoppedAnimation<Color>(color),
        ),
      ],
    );
  }
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
      color: Theme.of(context).scaffoldBackgroundColor,
      child: tabBar,
    );
  }

  @override
  bool shouldRebuild(_SliverTabBarDelegate oldDelegate) {
    return false;
  }
}

extension StringExtension on String {
  String capitalize() {
    return "${this[0].toUpperCase()}${substring(1)}";
  }
}