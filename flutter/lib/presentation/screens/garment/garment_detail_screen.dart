import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/common/app_badge.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/router/route_paths.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:smooth_page_indicator/smooth_page_indicator.dart';
import 'package:share_plus/share_plus.dart';

class GarmentDetailScreen extends StatefulWidget {
  final String garmentId;

  const GarmentDetailScreen({
    super.key,
    required this.garmentId,
  });

  @override
  State<GarmentDetailScreen> createState() => _GarmentDetailScreenState();
}

class _GarmentDetailScreenState extends State<GarmentDetailScreen> {
  final PageController _pageController = PageController();
  bool _isFavorite = false;

  @override
  void initState() {
    super.initState();
    _loadGarmentDetail();
  }

  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }

  void _loadGarmentDetail() {
    context.read<GarmentBloc>().add(LoadGarmentDetail(widget.garmentId));
  }

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<GarmentBloc, GarmentState>(
      builder: (context, state) {
        final garment = state.selectedGarment ?? 
            state.garments.firstWhere(
              (g) => g.id == widget.garmentId,
              orElse: () => null as GarmentModel,
            );

        if (garment == null && state is! GarmentLoading) {
          return Scaffold(
            appBar: AppCustomAppBar(title: 'Garment'),
            body: AppErrorWidget(
              errorType: ErrorType.notFound,
              message: 'Garment not found',
              onRetry: _loadGarmentDetail,
            ),
          );
        }

        _isFavorite = garment?.isFavorite ?? false;

        return Scaffold(
          body: garment == null
              ? const Center(child: AppLoadingIndicator())
              : CustomScrollView(
                  slivers: [
                    // Image carousel
                    SliverToBoxAdapter(
                      child: _buildImageCarousel(garment),
                    ),
                    // Content
                    SliverToBoxAdapter(
                      child: Padding(
                        padding: const EdgeInsets.all(AppDimensions.paddingL),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Header
                            _buildHeader(garment),
                            const SizedBox(height: AppDimensions.paddingL),
                            // Quick info
                            _buildQuickInfo(garment),
                            const SizedBox(height: AppDimensions.paddingL),
                            // Details
                            _buildDetails(garment),
                            const SizedBox(height: AppDimensions.paddingL),
                            // Tags
                            if (garment.tags.isNotEmpty) ...[
                              _buildTags(garment),
                              const SizedBox(height: AppDimensions.paddingL),
                            ],
                            // Notes
                            if (garment.notes != null) ...[
                              _buildNotes(garment),
                              const SizedBox(height: AppDimensions.paddingL),
                            ],
                            // Actions
                            _buildActions(garment),
                            const SizedBox(height: AppDimensions.paddingXL),
                            // Wear history
                            _buildWearHistory(garment),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
          floatingActionButton: garment != null
              ? FloatingActionButton(
                  onPressed: () => _recordWear(garment),
                  child: const Icon(Icons.checkroom),
                )
              : null,
        );
      },
    );
  }

  Widget _buildImageCarousel(GarmentModel garment) {
    return Stack(
      children: [
        Container(
          height: 400,
          child: garment.images.isEmpty
              ? Container(
                  color: AppColors.backgroundSecondary,
                  child: Center(
                    child: Icon(
                      Icons.checkroom,
                      size: 80,
                      color: AppColors.textTertiary,
                    ),
                  ),
                )
              : PageView.builder(
                  controller: _pageController,
                  itemCount: garment.images.length,
                  itemBuilder: (context, index) {
                    return CachedNetworkImage(
                      imageUrl: garment.images[index].url,
                      fit: BoxFit.cover,
                      placeholder: (context, url) => Container(
                        color: AppColors.backgroundSecondary,
                        child: const Center(
                          child: AppLoadingIndicator(),
                        ),
                      ),
                    );
                  },
                ),
        ),
        // Back button
        Positioned(
          top: MediaQuery.of(context).padding.top + 8,
          left: 8,
          child: CircleAvatar(
            backgroundColor: Colors.black54,
            child: IconButton(
              icon: const Icon(Icons.arrow_back, color: Colors.white),
              onPressed: () => context.pop(),
            ),
          ),
        ),
        // Actions
        Positioned(
          top: MediaQuery.of(context).padding.top + 8,
          right: 8,
          child: Row(
            children: [
              CircleAvatar(
                backgroundColor: Colors.black54,
                child: IconButton(
                  icon: Icon(
                    _isFavorite ? Icons.favorite : Icons.favorite_border,
                    color: _isFavorite ? AppColors.error : Colors.white,
                  ),
                  onPressed: () => _toggleFavorite(garment),
                ),
              ),
              const SizedBox(width: 8),
              CircleAvatar(
                backgroundColor: Colors.black54,
                child: IconButton(
                  icon: const Icon(Icons.share, color: Colors.white),
                  onPressed: () => _shareGarment(garment),
                ),
              ),
              const SizedBox(width: 8),
              CircleAvatar(
                backgroundColor: Colors.black54,
                child: PopupMenuButton<String>(
                  icon: const Icon(Icons.more_vert, color: Colors.white),
                  onSelected: (value) => _handleMenuAction(value, garment),
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
                      value: 'duplicate',
                      child: Row(
                        children: [
                          Icon(Icons.copy),
                          SizedBox(width: 8),
                          Text('Duplicate'),
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
              ),
            ],
          ),
        ),
        // Page indicator
        if (garment.images.length > 1)
          Positioned(
            bottom: 16,
            left: 0,
            right: 0,
            child: Center(
              child: SmoothPageIndicator(
                controller: _pageController,
                count: garment.images.length,
                effect: WormEffect(
                  dotHeight: 8,
                  dotWidth: 8,
                  activeDotColor: Theme.of(context).colorScheme.primary,
                  dotColor: Colors.white.withOpacity(0.5),
                ),
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildHeader(GarmentModel garment) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    garment.name,
                    style: AppTextStyles.h2,
                  ),
                  if (garment.brand != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      garment.brand!,
                      style: AppTextStyles.bodyLarge.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            if (garment.price != null)
              Text(
                '\$${garment.price!.toStringAsFixed(2)}',
                style: AppTextStyles.h3.copyWith(
                  color: AppColors.primary,
                ),
              ),
          ],
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Wardrobe info
        BlocBuilder<WardrobeBloc, WardrobeState>(
          builder: (context, state) {
            final wardrobe = state.wardrobes.firstWhere(
              (w) => w.id == garment.wardrobeId,
              orElse: () => WardrobeModel(
                id: '',
                userId: '',
                name: 'Unknown Wardrobe',
                isDefault: false,
                isShared: false,
                garmentIds: [],
                createdAt: DateTime.now(),
                updatedAt: DateTime.now(),
              ),
            );
            return InkWell(
              onTap: () => context.push(RoutePaths.wardrobeDetail(wardrobe.id)),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.checkroom,
                    size: 16,
                    color: AppColors.textSecondary,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    wardrobe.name,
                    style: AppTextStyles.bodyMedium.copyWith(
                      color: AppColors.textSecondary,
                      decoration: TextDecoration.underline,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildQuickInfo(GarmentModel garment) {
    return Row(
      children: [
        // Category
        _buildInfoChip(
          Icons.category,
          garment.category.capitalize(),
        ),
        const SizedBox(width: AppDimensions.paddingS),
        // Size
        if (garment.size != null) ...[
          _buildInfoChip(
            Icons.straighten,
            garment.size!,
          ),
          const SizedBox(width: AppDimensions.paddingS),
        ],
        // Wear count
        _buildInfoChip(
          Icons.history,
          '${garment.wearCount}x worn',
        ),
      ],
    );
  }

  Widget _buildInfoChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppDimensions.paddingM,
        vertical: AppDimensions.paddingS,
      ),
      decoration: BoxDecoration(
        color: AppColors.backgroundSecondary,
        borderRadius: AppDimensions.radiusL,
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: AppColors.textSecondary),
          const SizedBox(width: 4),
          Text(
            label,
            style: AppTextStyles.bodyMedium,
          ),
        ],
      ),
    );
  }

  Widget _buildDetails(GarmentModel garment) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Details',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Colors
        _buildDetailRow(
          'Colors',
          Row(
            children: garment.colors.map((color) => Container(
              width: 24,
              height: 24,
              margin: const EdgeInsets.only(right: 8),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: _getColorFromName(color),
                border: Border.all(
                  color: AppColors.border,
                  width: 1,
                ),
              ),
            )).toList(),
          ),
        ),
        if (garment.subcategory != null)
          _buildDetailRow('Subcategory', Text(garment.subcategory!)),
        if (garment.material != null)
          _buildDetailRow('Material', Text(garment.material!)),
        if (garment.purchaseDate != null)
          _buildDetailRow(
            'Purchase Date',
            Text(
              '${garment.purchaseDate!.day}/${garment.purchaseDate!.month}/${garment.purchaseDate!.year}',
            ),
          ),
        if (garment.lastWornDate != null)
          _buildDetailRow(
            'Last Worn',
            Text(
              '${garment.lastWornDate!.day}/${garment.lastWornDate!.month}/${garment.lastWornDate!.year}',
            ),
          ),
      ],
    );
  }

  Widget _buildDetailRow(String label, Widget value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
          ),
          Expanded(child: value),
        ],
      ),
    );
  }

  Widget _buildTags(GarmentModel garment) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Tags',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: garment.tags.map((tag) => AppBadge(
            text: tag,
            type: AppBadgeType.neutral,
            size: AppBadgeSize.medium,
          )).toList(),
        ),
      ],
    );
  }

  Widget _buildNotes(GarmentModel garment) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Notes',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        Container(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          decoration: BoxDecoration(
            color: AppColors.backgroundSecondary,
            borderRadius: AppDimensions.radiusM,
          ),
          child: Text(
            garment.notes!,
            style: AppTextStyles.bodyMedium,
          ),
        ),
      ],
    );
  }

  Widget _buildActions(GarmentModel garment) {
    return Row(
      children: [
        Expanded(
          child: AppButton(
            text: 'Create Outfit',
            onPressed: () => _createOutfit(garment),
            type: AppButtonType.secondary,
            icon: Icons.style,
          ),
        ),
        const SizedBox(width: AppDimensions.paddingM),
        Expanded(
          child: AppButton(
            text: 'Similar Items',
            onPressed: () => _findSimilar(garment),
            type: AppButtonType.secondary,
            icon: Icons.search,
          ),
        ),
      ],
    );
  }

  Widget _buildWearHistory(GarmentModel garment) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'Wear History',
              style: AppTextStyles.h3,
            ),
            Text(
              '${garment.wearCount} times',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
        const SizedBox(height: AppDimensions.paddingM),
        if (garment.wearCount == 0)
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingL),
            decoration: BoxDecoration(
              color: AppColors.backgroundSecondary,
              borderRadius: AppDimensions.radiusM,
            ),
            child: Center(
              child: Column(
                children: [
                  Icon(
                    Icons.history,
                    size: 48,
                    color: AppColors.textTertiary,
                  ),
                  const SizedBox(height: AppDimensions.paddingM),
                  Text(
                    'Not worn yet',
                    style: AppTextStyles.bodyLarge.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                  Text(
                    'Tap the button below to record a wear',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textTertiary,
                    ),
                  ),
                ],
              ),
            ),
          )
        else
          // TODO: Show actual wear history
          ListView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: 3, // Mock data
            itemBuilder: (context, index) {
              return ListTile(
                leading: CircleAvatar(
                  backgroundColor: AppColors.backgroundSecondary,
                  child: Icon(
                    Icons.calendar_today,
                    color: AppColors.textSecondary,
                  ),
                ),
                title: Text('${DateTime.now().subtract(Duration(days: index * 7)).day}/${DateTime.now().month}/${DateTime.now().year}'),
                subtitle: const Text('Casual day out'),
                contentPadding: EdgeInsets.zero,
              );
            },
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

  void _toggleFavorite(GarmentModel garment) {
    setState(() {
      _isFavorite = !_isFavorite;
    });
    
    final updatedGarment = garment.copyWith(isFavorite: _isFavorite);
    context.read<GarmentBloc>().add(UpdateGarment(updatedGarment));
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(_isFavorite ? 'Added to favorites' : 'Removed from favorites'),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  void _shareGarment(GarmentModel garment) {
    final text = 'Check out my ${garment.name} on Koutu!';
    Share.share(text);
  }

  void _handleMenuAction(String action, GarmentModel garment) {
    switch (action) {
      case 'edit':
        context.push(RoutePaths.editGarment(garment.id));
        break;
      case 'move':
        // TODO: Show wardrobe selection dialog
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Move to wardrobe coming soon'),
          ),
        );
        break;
      case 'duplicate':
        // TODO: Implement duplicate
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Duplicate garment coming soon'),
          ),
        );
        break;
      case 'delete':
        AppDialog.confirm(
          context,
          title: 'Delete Garment',
          message: 'Are you sure you want to delete "${garment.name}"? This action cannot be undone.',
          confirmText: 'Delete',
          confirmIsDestructive: true,
          onConfirm: () {
            context.read<GarmentBloc>().add(DeleteGarment(garment.id));
            context.pop();
          },
        );
        break;
    }
  }

  void _recordWear(GarmentModel garment) {
    // TODO: Show wear recording dialog with outfit context
    final updatedGarment = garment.copyWith(
      wearCount: garment.wearCount + 1,
      lastWornDate: DateTime.now(),
    );
    context.read<GarmentBloc>().add(UpdateGarment(updatedGarment));
    
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Wear recorded!'),
        backgroundColor: AppColors.success,
      ),
    );
  }

  void _createOutfit(GarmentModel garment) {
    // TODO: Navigate to outfit builder with this garment pre-selected
    context.push(RoutePaths.createOutfit);
  }

  void _findSimilar(GarmentModel garment) {
    // Navigate to garment list with filters pre-applied
    context.push(RoutePaths.garments);
    // TODO: Apply filters based on garment properties
  }
}

extension StringExtension on String {
  String capitalize() {
    return "${this[0].toUpperCase()}${substring(1)}";
  }
}