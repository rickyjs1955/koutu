import 'package:flutter/material.dart';
import 'package:koutu/services/cache/image_cache_service.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/widgets/loading/app_shimmer.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';

/// Advanced cached network image widget with progressive loading
class CachedNetworkImageWidget extends StatefulWidget {
  final String imageUrl;
  final double? width;
  final double? height;
  final BoxFit fit;
  final ImageCacheStrategy cacheStrategy;
  final Widget? placeholder;
  final Widget? errorWidget;
  final bool showProgressIndicator;
  final Duration fadeInDuration;
  final int? cacheWidth;
  final int? cacheHeight;
  final int? quality;
  final bool enableBlur;
  final VoidCallback? onTap;
  final BorderRadius? borderRadius;
  
  const CachedNetworkImageWidget({
    super.key,
    required this.imageUrl,
    this.width,
    this.height,
    this.fit = BoxFit.cover,
    this.cacheStrategy = ImageCacheStrategy.balanced,
    this.placeholder,
    this.errorWidget,
    this.showProgressIndicator = true,
    this.fadeInDuration = const Duration(milliseconds: 300),
    this.cacheWidth,
    this.cacheHeight,
    this.quality,
    this.enableBlur = true,
    this.onTap,
    this.borderRadius,
  });

  @override
  State<CachedNetworkImageWidget> createState() => _CachedNetworkImageWidgetState();
}

class _CachedNetworkImageWidgetState extends State<CachedNetworkImageWidget>
    with SingleTickerProviderStateMixin {
  final ImageCacheService _cacheService = ImageCacheService();
  late AnimationController _animationController;
  late Animation<double> _fadeAnimation;
  
  ImageState _state = ImageState.loading;
  Image? _image;
  Image? _thumbnailImage;
  double _loadingProgress = 0.0;
  
  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: widget.fadeInDuration,
      vsync: this,
    );
    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
    
    _loadImage();
  }
  
  @override
  void didUpdateWidget(CachedNetworkImageWidget oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.imageUrl != widget.imageUrl) {
      _loadImage();
    }
  }
  
  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }
  
  Future<void> _loadImage() async {
    setState(() {
      _state = ImageState.loading;
      _loadingProgress = 0.0;
    });
    
    // Load thumbnail first for progressive loading
    if (widget.enableBlur && widget.width != null && widget.height != null) {
      final thumbnailData = await _cacheService.getCachedImage(
        widget.imageUrl,
        strategy: ImageCacheStrategy.aggressive,
        targetSize: Size(
          widget.width! / 10,
          widget.height! / 10,
        ),
        quality: 30,
      );
      
      if (thumbnailData != null && mounted) {
        setState(() {
          _thumbnailImage = Image.memory(
            thumbnailData,
            fit: widget.fit,
          );
          _loadingProgress = 0.3;
        });
      }
    }
    
    // Load full resolution image
    final imageData = await _cacheService.getCachedImage(
      widget.imageUrl,
      strategy: widget.cacheStrategy,
      targetSize: widget.cacheWidth != null || widget.cacheHeight != null
          ? Size(
              widget.cacheWidth?.toDouble() ?? double.infinity,
              widget.cacheHeight?.toDouble() ?? double.infinity,
            )
          : null,
      quality: widget.quality,
    );
    
    if (imageData != null && mounted) {
      final image = Image.memory(
        imageData,
        fit: widget.fit,
        frameBuilder: (context, child, frame, wasSynchronouslyLoaded) {
          if (wasSynchronouslyLoaded) {
            return child;
          }
          
          if (frame != null) {
            _animationController.forward();
          }
          
          return FadeTransition(
            opacity: _fadeAnimation,
            child: child,
          );
        },
      );
      
      setState(() {
        _image = image;
        _state = ImageState.loaded;
        _loadingProgress = 1.0;
      });
    } else if (mounted) {
      setState(() {
        _state = ImageState.error;
      });
    }
  }
  
  @override
  Widget build(BuildContext context) {
    Widget child;
    
    switch (_state) {
      case ImageState.loading:
        child = _buildLoadingWidget();
        break;
      case ImageState.loaded:
        child = _buildImageWidget();
        break;
      case ImageState.error:
        child = _buildErrorWidget();
        break;
    }
    
    if (widget.borderRadius != null) {
      child = ClipRRect(
        borderRadius: widget.borderRadius!,
        child: child,
      );
    }
    
    if (widget.onTap != null) {
      child = GestureDetector(
        onTap: widget.onTap,
        child: child,
      );
    }
    
    return SizedBox(
      width: widget.width,
      height: widget.height,
      child: child,
    );
  }
  
  Widget _buildLoadingWidget() {
    if (widget.placeholder != null) {
      return widget.placeholder!;
    }
    
    return Stack(
      fit: StackFit.expand,
      children: [
        // Blurred thumbnail background
        if (_thumbnailImage != null && widget.enableBlur)
          Positioned.fill(
            child: ImageFiltered(
              imageFilter: ColorFilter.mode(
                Colors.black.withOpacity(0.3),
                BlendMode.darken,
              ),
              child: Transform.scale(
                scale: 1.1,
                child: _thumbnailImage!,
              ),
            ),
          ),
        
        // Loading indicator
        if (widget.showProgressIndicator)
          Center(
            child: AppFadeAnimation(
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.9),
                  shape: BoxShape.circle,
                ),
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    CircularProgressIndicator(
                      value: _loadingProgress,
                      backgroundColor: AppColors.backgroundSecondary,
                      valueColor: AlwaysStoppedAnimation<Color>(AppColors.primary),
                    ),
                    if (_loadingProgress > 0)
                      Text(
                        '${(_loadingProgress * 100).toInt()}%',
                        style: TextStyle(
                          fontSize: 10,
                          color: AppColors.primary,
                        ),
                      ),
                  ],
                ),
              ),
            ),
          )
        else
          AppShimmer(
            width: widget.width ?? double.infinity,
            height: widget.height ?? double.infinity,
          ),
      ],
    );
  }
  
  Widget _buildImageWidget() {
    return Stack(
      fit: StackFit.expand,
      children: [
        // Blurred background for portrait images
        if (_thumbnailImage != null && 
            widget.enableBlur && 
            widget.fit == BoxFit.contain)
          Positioned.fill(
            child: ImageFiltered(
              imageFilter: ColorFilter.mode(
                Colors.black.withOpacity(0.5),
                BlendMode.darken,
              ),
              child: Transform.scale(
                scale: 1.2,
                child: _thumbnailImage!,
              ),
            ),
          ),
        
        // Main image
        _image!,
      ],
    );
  }
  
  Widget _buildErrorWidget() {
    if (widget.errorWidget != null) {
      return widget.errorWidget!;
    }
    
    return Container(
      color: AppColors.backgroundSecondary,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.image_not_supported_outlined,
            size: 48,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: 8),
          Text(
            'Failed to load image',
            style: TextStyle(
              color: AppColors.textTertiary,
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: _loadImage,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }
}

enum ImageState {
  loading,
  loaded,
  error,
}

/// Optimized image list widget with recycling
class OptimizedImageGrid extends StatelessWidget {
  final List<String> imageUrls;
  final int crossAxisCount;
  final double spacing;
  final double childAspectRatio;
  final ImageCacheStrategy cacheStrategy;
  final Function(int index)? onImageTap;
  
  const OptimizedImageGrid({
    super.key,
    required this.imageUrls,
    this.crossAxisCount = 3,
    this.spacing = 4.0,
    this.childAspectRatio = 1.0,
    this.cacheStrategy = ImageCacheStrategy.conservative,
    this.onImageTap,
  });

  @override
  Widget build(BuildContext context) {
    // Preload visible images
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _preloadVisibleImages(context);
    });
    
    return GridView.builder(
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        crossAxisSpacing: spacing,
        mainAxisSpacing: spacing,
        childAspectRatio: childAspectRatio,
      ),
      itemCount: imageUrls.length,
      itemBuilder: (context, index) {
        return CachedNetworkImageWidget(
          imageUrl: imageUrls[index],
          fit: BoxFit.cover,
          cacheStrategy: cacheStrategy,
          enableBlur: false,
          showProgressIndicator: false,
          onTap: onImageTap != null ? () => onImageTap!(index) : null,
          cacheWidth: _calculateCacheSize(context),
          quality: 85,
        );
      },
    );
  }
  
  void _preloadVisibleImages(BuildContext context) {
    final screenHeight = MediaQuery.of(context).size.height;
    final itemHeight = MediaQuery.of(context).size.width / crossAxisCount;
    final visibleRows = (screenHeight / itemHeight).ceil() + 1;
    final visibleItems = visibleRows * crossAxisCount;
    
    final service = ImageCacheService();
    final preloadCount = visibleItems.clamp(0, imageUrls.length);
    
    service.preloadImages(
      imageUrls.take(preloadCount).toList(),
      strategy: ImageCacheStrategy.aggressive,
      targetSize: Size(_calculateCacheSize(context).toDouble(), 
                      _calculateCacheSize(context).toDouble()),
    );
  }
  
  int _calculateCacheSize(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final devicePixelRatio = MediaQuery.of(context).devicePixelRatio;
    final itemWidth = (screenWidth - (spacing * (crossAxisCount - 1))) / crossAxisCount;
    return (itemWidth * devicePixelRatio).toInt();
  }
}