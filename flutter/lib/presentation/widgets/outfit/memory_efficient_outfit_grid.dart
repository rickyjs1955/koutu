import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/widgets/performance/widget_recycler.dart';
import 'package:koutu/presentation/widgets/image/cached_network_image_widget.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/services/cache/image_cache_service.dart';

/// Memory-efficient outfit grid that recycles widgets and manages memory
class MemoryEfficientOutfitGrid extends StatefulWidget {
  final List<OutfitModel> outfits;
  final Function(OutfitModel) onOutfitTap;
  final ScrollController? scrollController;
  final int crossAxisCount;
  final double spacing;
  final double childAspectRatio;
  
  const MemoryEfficientOutfitGrid({
    super.key,
    required this.outfits,
    required this.onOutfitTap,
    this.scrollController,
    this.crossAxisCount = 2,
    this.spacing = AppDimensions.paddingM,
    this.childAspectRatio = 0.75,
  });

  @override
  State<MemoryEfficientOutfitGrid> createState() => _MemoryEfficientOutfitGridState();
}

class _MemoryEfficientOutfitGridState extends State<MemoryEfficientOutfitGrid> {
  late ScrollController _scrollController;
  final Map<String, GlobalKey> _itemKeys = {};
  final Set<int> _visibleIndices = {};
  
  @override
  void initState() {
    super.initState();
    _scrollController = widget.scrollController ?? ScrollController();
    _scrollController.addListener(_onScroll);
  }
  
  @override
  void dispose() {
    if (widget.scrollController == null) {
      _scrollController.dispose();
    }
    super.dispose();
  }
  
  void _onScroll() {
    _updateVisibleIndices();
  }
  
  void _updateVisibleIndices() {
    if (!_scrollController.hasClients) return;
    
    final screenHeight = MediaQuery.of(context).size.height;
    final scrollOffset = _scrollController.position.pixels;
    final itemHeight = (MediaQuery.of(context).size.width - 
        (widget.spacing * (widget.crossAxisCount - 1))) / 
        widget.crossAxisCount / widget.childAspectRatio;
    
    final firstVisibleRow = (scrollOffset / (itemHeight + widget.spacing)).floor();
    final lastVisibleRow = ((scrollOffset + screenHeight) / (itemHeight + widget.spacing)).ceil();
    
    final newVisibleIndices = <int>{};
    
    for (var row = firstVisibleRow; row <= lastVisibleRow; row++) {
      for (var col = 0; col < widget.crossAxisCount; col++) {
        final index = row * widget.crossAxisCount + col;
        if (index < widget.outfits.length) {
          newVisibleIndices.add(index);
        }
      }
    }
    
    // Preload adjacent items
    for (var row = firstVisibleRow - 1; row <= lastVisibleRow + 1; row++) {
      if (row < 0) continue;
      for (var col = 0; col < widget.crossAxisCount; col++) {
        final index = row * widget.crossAxisCount + col;
        if (index < widget.outfits.length) {
          newVisibleIndices.add(index);
        }
      }
    }
    
    if (newVisibleIndices != _visibleIndices) {
      setState(() {
        _visibleIndices.clear();
        _visibleIndices.addAll(newVisibleIndices);
      });
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      controller: _scrollController,
      padding: EdgeInsets.all(widget.spacing),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: widget.crossAxisCount,
        crossAxisSpacing: widget.spacing,
        mainAxisSpacing: widget.spacing,
        childAspectRatio: widget.childAspectRatio,
      ),
      itemCount: widget.outfits.length,
      itemBuilder: (context, index) {
        final outfit = widget.outfits[index];
        final isVisible = _visibleIndices.contains(index);
        
        return MemoryEfficientOutfitCard(
          key: ValueKey(outfit.id),
          outfit: outfit,
          isVisible: isVisible,
          onTap: () => widget.onOutfitTap(outfit),
        );
      },
    );
  }
}

/// Memory-efficient outfit card that manages its own lifecycle
class MemoryEfficientOutfitCard extends StatefulWidget {
  final OutfitModel outfit;
  final bool isVisible;
  final VoidCallback onTap;
  
  const MemoryEfficientOutfitCard({
    super.key,
    required this.outfit,
    required this.isVisible,
    required this.onTap,
  });

  @override
  State<MemoryEfficientOutfitCard> createState() => _MemoryEfficientOutfitCardState();
}

class _MemoryEfficientOutfitCardState extends State<MemoryEfficientOutfitCard>
    with AutomaticKeepAliveClientMixin {
  bool _isLoaded = false;
  bool _isDisposed = false;
  
  @override
  bool get wantKeepAlive => widget.isVisible && _isLoaded;
  
  @override
  void initState() {
    super.initState();
    if (widget.isVisible) {
      _loadContent();
    }
  }
  
  @override
  void didUpdateWidget(MemoryEfficientOutfitCard oldWidget) {
    super.didUpdateWidget(oldWidget);
    
    if (widget.isVisible && !oldWidget.isVisible) {
      _loadContent();
    } else if (!widget.isVisible && oldWidget.isVisible) {
      _disposeContent();
    }
  }
  
  @override
  void dispose() {
    _isDisposed = true;
    super.dispose();
  }
  
  void _loadContent() {
    if (_isLoaded || _isDisposed) return;
    
    setState(() {
      _isLoaded = true;
    });
  }
  
  void _disposeContent() {
    if (!_isLoaded || _isDisposed) return;
    
    // Clear image cache for this outfit
    if (widget.outfit.imageUrl != null) {
      final imageProvider = NetworkImage(widget.outfit.imageUrl!);
      imageProvider.evict();
    }
    
    setState(() {
      _isLoaded = false;
    });
  }
  
  @override
  Widget build(BuildContext context) {
    super.build(context);
    
    if (!widget.isVisible || !_isLoaded) {
      return _buildPlaceholder();
    }
    
    return GestureDetector(
      onTap: widget.onTap,
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(AppDimensions.radiusM),
          color: AppColors.surface,
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.05),
              blurRadius: 10,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: _buildOutfitImage(),
            ),
            _buildOutfitInfo(),
          ],
        ),
      ),
    );
  }
  
  Widget _buildPlaceholder() {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
        color: AppColors.backgroundSecondary,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: Container(
              decoration: BoxDecoration(
                color: AppColors.backgroundTertiary,
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(AppDimensions.radiusM),
                ),
              ),
            ),
          ),
          Container(
            height: 60,
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  height: 14,
                  width: 100,
                  decoration: BoxDecoration(
                    color: AppColors.backgroundTertiary,
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                ),
                const SizedBox(height: 4),
                Container(
                  height: 12,
                  width: 60,
                  decoration: BoxDecoration(
                    color: AppColors.backgroundTertiary,
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildOutfitImage() {
    if (widget.outfit.garments.isEmpty) {
      return Container(
        decoration: BoxDecoration(
          color: AppColors.backgroundSecondary,
          borderRadius: const BorderRadius.vertical(
            top: Radius.circular(AppDimensions.radiusM),
          ),
        ),
        child: Center(
          child: Icon(
            Icons.checkroom,
            size: 48,
            color: AppColors.textTertiary,
          ),
        ),
      );
    }
    
    if (widget.outfit.imageUrl != null) {
      // Single outfit image
      return ClipRRect(
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(AppDimensions.radiusM),
        ),
        child: MemoryEfficientImage(
          imageUrl: widget.outfit.imageUrl!,
          fit: BoxFit.cover,
          maxCacheWidth: 400,
          maxCacheHeight: 400,
        ),
      );
    }
    
    // Grid of garment images
    return ClipRRect(
      borderRadius: const BorderRadius.vertical(
        top: Radius.circular(AppDimensions.radiusM),
      ),
      child: _buildGarmentGrid(),
    );
  }
  
  Widget _buildGarmentGrid() {
    final garmentImages = widget.outfit.garments
        .take(4)
        .map((g) => g.images.first.url)
        .toList();
    
    return GridView.builder(
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 1,
        mainAxisSpacing: 1,
      ),
      itemCount: garmentImages.length,
      itemBuilder: (context, index) {
        return MemoryEfficientImage(
          imageUrl: garmentImages[index],
          fit: BoxFit.cover,
          maxCacheWidth: 200,
          maxCacheHeight: 200,
        );
      },
    );
  }
  
  Widget _buildOutfitInfo() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            widget.outfit.name,
            style: AppTextStyles.labelMedium,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 2),
          Text(
            '${widget.outfit.garments.length} items • ${widget.outfit.occasion}',
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}

/// Optimized outfit carousel with memory management
class MemoryEfficientOutfitCarousel extends StatefulWidget {
  final List<OutfitModel> outfits;
  final Function(OutfitModel) onOutfitTap;
  final double height;
  final double viewportFraction;
  
  const MemoryEfficientOutfitCarousel({
    super.key,
    required this.outfits,
    required this.onOutfitTap,
    this.height = 200,
    this.viewportFraction = 0.8,
  });

  @override
  State<MemoryEfficientOutfitCarousel> createState() => _MemoryEfficientOutfitCarouselState();
}

class _MemoryEfficientOutfitCarouselState extends State<MemoryEfficientOutfitCarousel> {
  late PageController _pageController;
  int _currentPage = 0;
  final Map<int, bool> _loadedPages = {};
  
  @override
  void initState() {
    super.initState();
    _pageController = PageController(
      viewportFraction: widget.viewportFraction,
    );
    _pageController.addListener(_onPageChanged);
    
    // Preload first few pages
    for (var i = 0; i < 3 && i < widget.outfits.length; i++) {
      _loadedPages[i] = true;
    }
  }
  
  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }
  
  void _onPageChanged() {
    final page = _pageController.page?.round() ?? 0;
    if (page != _currentPage) {
      setState(() {
        _currentPage = page;
        
        // Load current and adjacent pages
        for (var i = page - 1; i <= page + 1; i++) {
          if (i >= 0 && i < widget.outfits.length) {
            _loadedPages[i] = true;
          }
        }
        
        // Unload distant pages
        _loadedPages.removeWhere((key, value) {
          return (key - page).abs() > 2;
        });
      });
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: widget.height,
      child: PageView.builder(
        controller: _pageController,
        itemCount: widget.outfits.length,
        itemBuilder: (context, index) {
          final outfit = widget.outfits[index];
          final isLoaded = _loadedPages[index] ?? false;
          
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingS),
            child: MemoryEfficientOutfitCard(
              outfit: outfit,
              isVisible: isLoaded,
              onTap: () => widget.onOutfitTap(outfit),
            ),
          );
        },
      ),
    );
  }
}