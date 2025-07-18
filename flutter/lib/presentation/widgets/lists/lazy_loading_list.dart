import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/loading/app_shimmer.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';

/// Generic lazy loading list widget with pagination
class LazyLoadingList<T> extends StatefulWidget {
  final Future<List<T>> Function(int page, int pageSize) onLoadMore;
  final Widget Function(BuildContext context, T item, int index) itemBuilder;
  final Widget Function(BuildContext context, int index)? separatorBuilder;
  final Widget? emptyWidget;
  final Widget? loadingWidget;
  final Widget? errorWidget;
  final int pageSize;
  final double loadMoreThreshold;
  final ScrollController? scrollController;
  final bool shrinkWrap;
  final ScrollPhysics? physics;
  final EdgeInsetsGeometry? padding;
  final Axis scrollDirection;
  final bool reverse;
  final bool enableRefresh;
  final Future<void> Function()? onRefresh;
  final int? shimmerItemCount;
  
  const LazyLoadingList({
    super.key,
    required this.onLoadMore,
    required this.itemBuilder,
    this.separatorBuilder,
    this.emptyWidget,
    this.loadingWidget,
    this.errorWidget,
    this.pageSize = 20,
    this.loadMoreThreshold = 0.8,
    this.scrollController,
    this.shrinkWrap = false,
    this.physics,
    this.padding,
    this.scrollDirection = Axis.vertical,
    this.reverse = false,
    this.enableRefresh = true,
    this.onRefresh,
    this.shimmerItemCount = 5,
  });

  @override
  State<LazyLoadingList<T>> createState() => _LazyLoadingListState<T>();
}

class _LazyLoadingListState<T> extends State<LazyLoadingList<T>> {
  late ScrollController _scrollController;
  final List<T> _items = [];
  bool _isLoading = false;
  bool _hasMore = true;
  bool _isInitialLoad = true;
  String? _errorMessage;
  int _currentPage = 0;
  
  @override
  void initState() {
    super.initState();
    _scrollController = widget.scrollController ?? ScrollController();
    _scrollController.addListener(_onScroll);
    _loadInitialData();
  }
  
  @override
  void dispose() {
    if (widget.scrollController == null) {
      _scrollController.dispose();
    }
    super.dispose();
  }
  
  void _onScroll() {
    if (_isLoading || !_hasMore) return;
    
    final maxScroll = _scrollController.position.maxScrollExtent;
    final currentScroll = _scrollController.position.pixels;
    final threshold = maxScroll * widget.loadMoreThreshold;
    
    if (currentScroll >= threshold) {
      _loadMore();
    }
  }
  
  Future<void> _loadInitialData() async {
    setState(() {
      _isInitialLoad = true;
      _errorMessage = null;
    });
    
    await _loadMore();
    
    setState(() {
      _isInitialLoad = false;
    });
  }
  
  Future<void> _loadMore() async {
    if (_isLoading || !_hasMore) return;
    
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    
    try {
      final newItems = await widget.onLoadMore(_currentPage, widget.pageSize);
      
      setState(() {
        _items.addAll(newItems);
        _currentPage++;
        _hasMore = newItems.length >= widget.pageSize;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }
  
  Future<void> _refresh() async {
    setState(() {
      _items.clear();
      _currentPage = 0;
      _hasMore = true;
      _errorMessage = null;
    });
    
    if (widget.onRefresh != null) {
      await widget.onRefresh!();
    }
    
    await _loadInitialData();
  }
  
  @override
  Widget build(BuildContext context) {
    if (_isInitialLoad) {
      return _buildLoadingState();
    }
    
    if (_errorMessage != null && _items.isEmpty) {
      return _buildErrorState();
    }
    
    if (_items.isEmpty) {
      return _buildEmptyState();
    }
    
    final listView = ListView.separated(
      controller: _scrollController,
      shrinkWrap: widget.shrinkWrap,
      physics: widget.physics,
      padding: widget.padding,
      scrollDirection: widget.scrollDirection,
      reverse: widget.reverse,
      itemCount: _items.length + (_hasMore ? 1 : 0),
      separatorBuilder: (context, index) {
        if (widget.separatorBuilder != null) {
          return widget.separatorBuilder!(context, index);
        }
        return const SizedBox.shrink();
      },
      itemBuilder: (context, index) {
        if (index >= _items.length) {
          return _buildLoadMoreIndicator();
        }
        
        return widget.itemBuilder(context, _items[index], index);
      },
    );
    
    if (widget.enableRefresh) {
      return RefreshIndicator(
        onRefresh: _refresh,
        child: listView,
      );
    }
    
    return listView;
  }
  
  Widget _buildLoadingState() {
    if (widget.loadingWidget != null) {
      return widget.loadingWidget!;
    }
    
    return ListView.separated(
      shrinkWrap: widget.shrinkWrap,
      physics: const NeverScrollableScrollPhysics(),
      padding: widget.padding,
      itemCount: widget.shimmerItemCount ?? 5,
      separatorBuilder: (context, index) {
        if (widget.separatorBuilder != null) {
          return widget.separatorBuilder!(context, index);
        }
        return const SizedBox(height: AppDimensions.paddingM);
      },
      itemBuilder: (context, index) {
        return AppShimmer(
          width: double.infinity,
          height: widget.scrollDirection == Axis.vertical ? 80 : 150,
        );
      },
    );
  }
  
  Widget _buildEmptyState() {
    if (widget.emptyWidget != null) {
      return widget.emptyWidget!;
    }
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.inbox_outlined,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No items found',
            style: TextStyle(
              fontSize: 16,
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildErrorState() {
    if (widget.errorWidget != null) {
      return widget.errorWidget!;
    }
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 64,
            color: AppColors.error,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Error loading items',
            style: TextStyle(
              fontSize: 16,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            _errorMessage ?? 'Unknown error',
            style: TextStyle(
              fontSize: 14,
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          ElevatedButton(
            onPressed: _loadInitialData,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }
  
  Widget _buildLoadMoreIndicator() {
    if (_isLoading) {
      return Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        alignment: Alignment.center,
        child: const AppLoadingIndicator(size: 24),
      );
    }
    
    if (_errorMessage != null) {
      return Container(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          children: [
            Text(
              'Failed to load more items',
              style: TextStyle(
                color: AppColors.error,
                fontSize: 14,
              ),
            ),
            const SizedBox(height: AppDimensions.paddingS),
            TextButton(
              onPressed: _loadMore,
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }
    
    return const SizedBox.shrink();
  }
}

/// Lazy loading grid widget with pagination
class LazyLoadingGrid<T> extends StatefulWidget {
  final Future<List<T>> Function(int page, int pageSize) onLoadMore;
  final Widget Function(BuildContext context, T item, int index) itemBuilder;
  final Widget? emptyWidget;
  final Widget? loadingWidget;
  final Widget? errorWidget;
  final int pageSize;
  final double loadMoreThreshold;
  final ScrollController? scrollController;
  final bool shrinkWrap;
  final ScrollPhysics? physics;
  final EdgeInsetsGeometry? padding;
  final int crossAxisCount;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final double childAspectRatio;
  final bool enableRefresh;
  final Future<void> Function()? onRefresh;
  
  const LazyLoadingGrid({
    super.key,
    required this.onLoadMore,
    required this.itemBuilder,
    this.emptyWidget,
    this.loadingWidget,
    this.errorWidget,
    this.pageSize = 20,
    this.loadMoreThreshold = 0.8,
    this.scrollController,
    this.shrinkWrap = false,
    this.physics,
    this.padding,
    this.crossAxisCount = 2,
    this.mainAxisSpacing = AppDimensions.paddingM,
    this.crossAxisSpacing = AppDimensions.paddingM,
    this.childAspectRatio = 1.0,
    this.enableRefresh = true,
    this.onRefresh,
  });

  @override
  State<LazyLoadingGrid<T>> createState() => _LazyLoadingGridState<T>();
}

class _LazyLoadingGridState<T> extends State<LazyLoadingGrid<T>> {
  late ScrollController _scrollController;
  final List<T> _items = [];
  bool _isLoading = false;
  bool _hasMore = true;
  bool _isInitialLoad = true;
  String? _errorMessage;
  int _currentPage = 0;
  
  @override
  void initState() {
    super.initState();
    _scrollController = widget.scrollController ?? ScrollController();
    _scrollController.addListener(_onScroll);
    _loadInitialData();
  }
  
  @override
  void dispose() {
    if (widget.scrollController == null) {
      _scrollController.dispose();
    }
    super.dispose();
  }
  
  void _onScroll() {
    if (_isLoading || !_hasMore) return;
    
    final maxScroll = _scrollController.position.maxScrollExtent;
    final currentScroll = _scrollController.position.pixels;
    final threshold = maxScroll * widget.loadMoreThreshold;
    
    if (currentScroll >= threshold) {
      _loadMore();
    }
  }
  
  Future<void> _loadInitialData() async {
    setState(() {
      _isInitialLoad = true;
      _errorMessage = null;
    });
    
    await _loadMore();
    
    setState(() {
      _isInitialLoad = false;
    });
  }
  
  Future<void> _loadMore() async {
    if (_isLoading || !_hasMore) return;
    
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });
    
    try {
      final newItems = await widget.onLoadMore(_currentPage, widget.pageSize);
      
      setState(() {
        _items.addAll(newItems);
        _currentPage++;
        _hasMore = newItems.length >= widget.pageSize;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }
  
  Future<void> _refresh() async {
    setState(() {
      _items.clear();
      _currentPage = 0;
      _hasMore = true;
      _errorMessage = null;
    });
    
    if (widget.onRefresh != null) {
      await widget.onRefresh!();
    }
    
    await _loadInitialData();
  }
  
  @override
  Widget build(BuildContext context) {
    if (_isInitialLoad) {
      return _buildLoadingState();
    }
    
    if (_errorMessage != null && _items.isEmpty) {
      return _buildErrorState();
    }
    
    if (_items.isEmpty) {
      return _buildEmptyState();
    }
    
    final gridView = GridView.builder(
      controller: _scrollController,
      shrinkWrap: widget.shrinkWrap,
      physics: widget.physics,
      padding: widget.padding,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: widget.crossAxisCount,
        mainAxisSpacing: widget.mainAxisSpacing,
        crossAxisSpacing: widget.crossAxisSpacing,
        childAspectRatio: widget.childAspectRatio,
      ),
      itemCount: _items.length + (_hasMore && _isLoading ? widget.crossAxisCount : 0),
      itemBuilder: (context, index) {
        if (index >= _items.length) {
          return _buildLoadMoreIndicator();
        }
        
        return widget.itemBuilder(context, _items[index], index);
      },
    );
    
    if (widget.enableRefresh) {
      return RefreshIndicator(
        onRefresh: _refresh,
        child: gridView,
      );
    }
    
    return gridView;
  }
  
  Widget _buildLoadingState() {
    if (widget.loadingWidget != null) {
      return widget.loadingWidget!;
    }
    
    return GridView.builder(
      shrinkWrap: widget.shrinkWrap,
      physics: const NeverScrollableScrollPhysics(),
      padding: widget.padding,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: widget.crossAxisCount,
        mainAxisSpacing: widget.mainAxisSpacing,
        crossAxisSpacing: widget.crossAxisSpacing,
        childAspectRatio: widget.childAspectRatio,
      ),
      itemCount: widget.crossAxisCount * 3,
      itemBuilder: (context, index) {
        return AppShimmer(
          width: double.infinity,
          height: double.infinity,
        );
      },
    );
  }
  
  Widget _buildEmptyState() {
    if (widget.emptyWidget != null) {
      return widget.emptyWidget!;
    }
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.grid_off_outlined,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No items found',
            style: TextStyle(
              fontSize: 16,
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildErrorState() {
    if (widget.errorWidget != null) {
      return widget.errorWidget!;
    }
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 64,
            color: AppColors.error,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Error loading items',
            style: TextStyle(
              fontSize: 16,
              color: AppColors.textPrimary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            _errorMessage ?? 'Unknown error',
            style: TextStyle(
              fontSize: 14,
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          ElevatedButton(
            onPressed: _loadInitialData,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }
  
  Widget _buildLoadMoreIndicator() {
    return Container(
      alignment: Alignment.center,
      child: AppShimmer(
        width: double.infinity,
        height: double.infinity,
      ),
    );
  }
}