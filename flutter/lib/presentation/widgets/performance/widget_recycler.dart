import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

/// Memory-efficient widget recycler for large lists
class WidgetRecycler extends StatefulWidget {
  final IndexedWidgetBuilder itemBuilder;
  final int itemCount;
  final double itemExtent;
  final int cacheExtent;
  final ScrollController? controller;
  final Axis scrollDirection;
  
  const WidgetRecycler({
    super.key,
    required this.itemBuilder,
    required this.itemCount,
    required this.itemExtent,
    this.cacheExtent = 3,
    this.controller,
    this.scrollDirection = Axis.vertical,
  });

  @override
  State<WidgetRecycler> createState() => _WidgetRecyclerState();
}

class _WidgetRecyclerState extends State<WidgetRecycler> {
  late ScrollController _scrollController;
  final Map<int, Widget> _widgetCache = {};
  final Set<int> _visibleIndices = {};
  late int _maxCacheSize;
  
  @override
  void initState() {
    super.initState();
    _scrollController = widget.controller ?? ScrollController();
    _scrollController.addListener(_onScroll);
    _maxCacheSize = widget.cacheExtent * 2 + 10; // Cache visible + buffer items
    
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _updateVisibleIndices();
    });
  }
  
  @override
  void dispose() {
    if (widget.controller == null) {
      _scrollController.dispose();
    }
    super.dispose();
  }
  
  void _onScroll() {
    _updateVisibleIndices();
    _cleanupCache();
  }
  
  void _updateVisibleIndices() {
    if (!_scrollController.hasClients) return;
    
    final viewport = _scrollController.position.viewportDimension;
    final scrollOffset = _scrollController.position.pixels;
    
    final firstVisibleIndex = (scrollOffset / widget.itemExtent).floor();
    final lastVisibleIndex = ((scrollOffset + viewport) / widget.itemExtent).ceil();
    
    _visibleIndices.clear();
    
    // Add buffer items before and after visible range
    for (var i = (firstVisibleIndex - widget.cacheExtent).clamp(0, widget.itemCount - 1);
         i <= (lastVisibleIndex + widget.cacheExtent).clamp(0, widget.itemCount - 1);
         i++) {
      _visibleIndices.add(i);
    }
    
    setState(() {});
  }
  
  void _cleanupCache() {
    if (_widgetCache.length <= _maxCacheSize) return;
    
    // Remove widgets that are far from visible range
    final keysToRemove = <int>[];
    
    for (final key in _widgetCache.keys) {
      if (!_visibleIndices.contains(key)) {
        bool isNearVisible = false;
        for (final visibleIndex in _visibleIndices) {
          if ((key - visibleIndex).abs() <= widget.cacheExtent * 2) {
            isNearVisible = true;
            break;
          }
        }
        
        if (!isNearVisible) {
          keysToRemove.add(key);
        }
      }
    }
    
    // Remove least recently used items if still over limit
    if (_widgetCache.length - keysToRemove.length > _maxCacheSize) {
      final sortedKeys = _widgetCache.keys.toList()
        ..sort((a, b) {
          final aDistance = _visibleIndices.isEmpty ? double.infinity 
              : _visibleIndices.map((v) => (v - a).abs()).reduce((a, b) => a < b ? a : b).toDouble();
          final bDistance = _visibleIndices.isEmpty ? double.infinity
              : _visibleIndices.map((v) => (v - b).abs()).reduce((a, b) => a < b ? a : b).toDouble();
          return aDistance.compareTo(bDistance);
        });
      
      final additionalToRemove = _widgetCache.length - keysToRemove.length - _maxCacheSize;
      keysToRemove.addAll(sortedKeys.reversed.take(additionalToRemove));
    }
    
    for (final key in keysToRemove) {
      _widgetCache.remove(key);
    }
  }
  
  Widget _buildItem(int index) {
    if (!_widgetCache.containsKey(index)) {
      _widgetCache[index] = KeyedSubtree(
        key: ValueKey(index),
        child: widget.itemBuilder(context, index),
      );
    }
    return _widgetCache[index]!;
  }
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      controller: _scrollController,
      scrollDirection: widget.scrollDirection,
      itemCount: widget.itemCount,
      itemExtent: widget.itemExtent,
      itemBuilder: (context, index) {
        if (_visibleIndices.contains(index)) {
          return _buildItem(index);
        }
        // Return placeholder for non-visible items
        return SizedBox(
          width: widget.scrollDirection == Axis.horizontal ? widget.itemExtent : null,
          height: widget.scrollDirection == Axis.vertical ? widget.itemExtent : null,
        );
      },
    );
  }
}

/// Sliver version for more complex layouts
class SliverWidgetRecycler extends StatefulWidget {
  final IndexedWidgetBuilder itemBuilder;
  final int itemCount;
  final double itemExtent;
  final int cacheExtent;
  
  const SliverWidgetRecycler({
    super.key,
    required this.itemBuilder,
    required this.itemCount,
    required this.itemExtent,
    this.cacheExtent = 3,
  });

  @override
  State<SliverWidgetRecycler> createState() => _SliverWidgetRecyclerState();
}

class _SliverWidgetRecyclerState extends State<SliverWidgetRecycler> {
  final Map<int, Widget> _widgetCache = {};
  final Set<int> _visibleIndices = {};
  
  @override
  Widget build(BuildContext context) {
    return SliverFixedExtentList(
      itemExtent: widget.itemExtent,
      delegate: SliverChildBuilderDelegate(
        (context, index) {
          if (!_widgetCache.containsKey(index)) {
            _widgetCache[index] = KeyedSubtree(
              key: ValueKey(index),
              child: widget.itemBuilder(context, index),
            );
          }
          
          // Cleanup cache periodically
          if (_widgetCache.length > widget.cacheExtent * 3) {
            _cleanupCache(index);
          }
          
          return _widgetCache[index]!;
        },
        childCount: widget.itemCount,
      ),
    );
  }
  
  void _cleanupCache(int currentIndex) {
    final keysToRemove = <int>[];
    
    for (final key in _widgetCache.keys) {
      if ((key - currentIndex).abs() > widget.cacheExtent * 2) {
        keysToRemove.add(key);
      }
    }
    
    for (final key in keysToRemove) {
      _widgetCache.remove(key);
    }
  }
}

/// Memory-efficient image widget with automatic disposal
class MemoryEfficientImage extends StatefulWidget {
  final String imageUrl;
  final double? width;
  final double? height;
  final BoxFit fit;
  final int maxCacheWidth;
  final int maxCacheHeight;
  
  const MemoryEfficientImage({
    super.key,
    required this.imageUrl,
    this.width,
    this.height,
    this.fit = BoxFit.cover,
    this.maxCacheWidth = 500,
    this.maxCacheHeight = 500,
  });

  @override
  State<MemoryEfficientImage> createState() => _MemoryEfficientImageState();
}

class _MemoryEfficientImageState extends State<MemoryEfficientImage> 
    with AutomaticKeepAliveClientMixin {
  ImageProvider? _imageProvider;
  bool _isVisible = true;
  
  @override
  bool get wantKeepAlive => _isVisible;
  
  @override
  void initState() {
    super.initState();
    _loadImage();
  }
  
  @override
  void dispose() {
    _disposeImage();
    super.dispose();
  }
  
  void _loadImage() {
    _imageProvider = ResizeImage(
      NetworkImage(widget.imageUrl),
      width: widget.maxCacheWidth,
      height: widget.maxCacheHeight,
    );
  }
  
  void _disposeImage() {
    if (_imageProvider != null) {
      _imageProvider!.evict();
      _imageProvider = null;
    }
  }
  
  @override
  Widget build(BuildContext context) {
    super.build(context);
    
    return VisibilityDetector(
      key: Key(widget.imageUrl),
      onVisibilityChanged: (info) {
        if (info.visibleFraction == 0 && _isVisible) {
          setState(() {
            _isVisible = false;
            _disposeImage();
          });
        } else if (info.visibleFraction > 0 && !_isVisible) {
          setState(() {
            _isVisible = true;
            _loadImage();
          });
        }
      },
      child: SizedBox(
        width: widget.width,
        height: widget.height,
        child: _imageProvider != null
            ? Image(
                image: _imageProvider!,
                width: widget.width,
                height: widget.height,
                fit: widget.fit,
                frameBuilder: (context, child, frame, wasSynchronouslyLoaded) {
                  if (wasSynchronouslyLoaded) {
                    return child;
                  }
                  return AnimatedOpacity(
                    opacity: frame == null ? 0 : 1,
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeOut,
                    child: child,
                  );
                },
              )
            : Container(
                color: Colors.grey[300],
              ),
      ),
    );
  }
}

/// Visibility detector for efficient widget lifecycle management
class VisibilityDetector extends StatefulWidget {
  final Widget child;
  final Key key;
  final void Function(VisibilityInfo) onVisibilityChanged;
  
  const VisibilityDetector({
    required this.key,
    required this.child,
    required this.onVisibilityChanged,
  }) : super(key: key);

  @override
  State<VisibilityDetector> createState() => _VisibilityDetectorState();
}

class _VisibilityDetectorState extends State<VisibilityDetector> {
  final _key = GlobalKey();
  double _lastVisibleFraction = 0;
  
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkVisibility();
    });
  }
  
  void _checkVisibility() {
    if (!mounted) return;
    
    final RenderObject? renderObject = _key.currentContext?.findRenderObject();
    if (renderObject == null || !renderObject.attached) return;
    
    final RenderAbstractViewport? viewport = RenderAbstractViewport.of(renderObject);
    if (viewport == null) return;
    
    final RevealedOffset offsetToReveal = viewport.getOffsetToReveal(
      renderObject,
      0.0,
    );
    
    final Size size = renderObject.semanticBounds.size;
    final double visibleFraction = _calculateVisibleFraction(
      offsetToReveal.offset,
      size,
      viewport,
    );
    
    if (visibleFraction != _lastVisibleFraction) {
      _lastVisibleFraction = visibleFraction;
      widget.onVisibilityChanged(VisibilityInfo(
        key: widget.key,
        size: size,
        visibleFraction: visibleFraction,
      ));
    }
    
    // Schedule next check
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _checkVisibility();
    });
  }
  
  double _calculateVisibleFraction(
    double offset,
    Size size,
    RenderAbstractViewport viewport,
  ) {
    final viewportDimension = viewport.axis == Axis.horizontal
        ? viewport.paintBounds.width
        : viewport.paintBounds.height;
    
    final itemDimension = viewport.axis == Axis.horizontal
        ? size.width
        : size.height;
    
    if (offset < 0) {
      // Item is partially visible at the start
      final visiblePortion = itemDimension + offset;
      return (visiblePortion / itemDimension).clamp(0.0, 1.0);
    } else if (offset + itemDimension > viewportDimension) {
      // Item is partially visible at the end
      final visiblePortion = viewportDimension - offset;
      return (visiblePortion / itemDimension).clamp(0.0, 1.0);
    } else {
      // Item is fully visible
      return 1.0;
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Container(
      key: _key,
      child: widget.child,
    );
  }
}

class VisibilityInfo {
  final Key key;
  final Size size;
  final double visibleFraction;
  
  const VisibilityInfo({
    required this.key,
    required this.size,
    required this.visibleFraction,
  });
}