import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for managing lazy loading and pagination
class LazyLoadingService {
  static const int defaultPageSize = 20;
  static const int maxConcurrentRequests = 3;
  
  // Track ongoing requests to prevent duplicate calls
  static final Map<String, Future<dynamic>> _ongoingRequests = {};
  
  // Cache for paginated results
  static final Map<String, PaginationCache> _paginationCache = {};
  
  /// Load paginated data with caching and deduplication
  static Future<Either<Failure, PaginatedResult<T>>> loadPage<T>({
    required String cacheKey,
    required int page,
    required int pageSize,
    required Future<List<T>> Function(int page, int pageSize) loader,
    Duration? cacheDuration,
    bool forceRefresh = false,
  }) async {
    final requestKey = '$cacheKey-$page-$pageSize';
    
    // Check if we should use cached data
    if (!forceRefresh && _paginationCache.containsKey(requestKey)) {
      final cache = _paginationCache[requestKey]!;
      if (!cache.isExpired) {
        return Right(PaginatedResult<T>(
          items: cache.items as List<T>,
          page: page,
          pageSize: pageSize,
          hasMore: cache.hasMore,
          totalCount: cache.totalCount,
        ));
      }
    }
    
    // Check if request is already in progress
    if (_ongoingRequests.containsKey(requestKey)) {
      try {
        final result = await _ongoingRequests[requestKey];
        return Right(result as PaginatedResult<T>);
      } catch (e) {
        return Left(ServerFailure(e.toString()));
      }
    }
    
    // Create new request
    final future = _performLoad<T>(
      cacheKey: cacheKey,
      page: page,
      pageSize: pageSize,
      loader: loader,
      cacheDuration: cacheDuration,
    );
    
    _ongoingRequests[requestKey] = future;
    
    try {
      final result = await future;
      _ongoingRequests.remove(requestKey);
      return Right(result);
    } catch (e) {
      _ongoingRequests.remove(requestKey);
      return Left(ServerFailure(e.toString()));
    }
  }
  
  static Future<PaginatedResult<T>> _performLoad<T>({
    required String cacheKey,
    required int page,
    required int pageSize,
    required Future<List<T>> Function(int page, int pageSize) loader,
    Duration? cacheDuration,
  }) async {
    final items = await loader(page, pageSize);
    final hasMore = items.length >= pageSize;
    
    // Cache the result
    final requestKey = '$cacheKey-$page-$pageSize';
    _paginationCache[requestKey] = PaginationCache(
      items: items,
      page: page,
      pageSize: pageSize,
      hasMore: hasMore,
      totalCount: null, // Can be provided by loader if available
      cachedAt: DateTime.now(),
      cacheDuration: cacheDuration ?? const Duration(minutes: 5),
    );
    
    return PaginatedResult<T>(
      items: items,
      page: page,
      pageSize: pageSize,
      hasMore: hasMore,
      totalCount: null,
    );
  }
  
  /// Clear cache for specific key or all cache
  static void clearCache([String? cacheKey]) {
    if (cacheKey != null) {
      _paginationCache.removeWhere((key, value) => key.startsWith(cacheKey));
    } else {
      _paginationCache.clear();
    }
  }
  
  /// Preload multiple pages in background
  static Future<void> preloadPages<T>({
    required String cacheKey,
    required List<int> pages,
    required int pageSize,
    required Future<List<T>> Function(int page, int pageSize) loader,
    Duration? cacheDuration,
  }) async {
    // Limit concurrent requests
    final chunks = _chunkList(pages, maxConcurrentRequests);
    
    for (final chunk in chunks) {
      await Future.wait(
        chunk.map((page) => loadPage<T>(
          cacheKey: cacheKey,
          page: page,
          pageSize: pageSize,
          loader: loader,
          cacheDuration: cacheDuration,
        )),
      );
    }
  }
  
  /// Infinite scroll helper
  static Stream<PaginatedResult<T>> infiniteScroll<T>({
    required String cacheKey,
    required int pageSize,
    required Future<List<T>> Function(int page, int pageSize) loader,
    Duration? cacheDuration,
  }) async* {
    int currentPage = 0;
    bool hasMore = true;
    
    while (hasMore) {
      final result = await loadPage<T>(
        cacheKey: cacheKey,
        page: currentPage,
        pageSize: pageSize,
        loader: loader,
        cacheDuration: cacheDuration,
      );
      
      yield* result.fold(
        (failure) => throw failure,
        (paginatedResult) async* {
          yield paginatedResult;
          hasMore = paginatedResult.hasMore;
          currentPage++;
        },
      );
    }
  }
  
  /// Virtual scrolling support for very large lists
  static Widget buildVirtualList<T>({
    required String cacheKey,
    required int itemCount,
    required int itemsPerPage,
    required Widget Function(BuildContext context, int index) itemBuilder,
    required Future<List<T>> Function(int page, int pageSize) loader,
    ScrollController? controller,
    double? itemExtent,
  }) {
    return VirtualScrollView<T>(
      cacheKey: cacheKey,
      itemCount: itemCount,
      itemsPerPage: itemsPerPage,
      itemBuilder: itemBuilder,
      loader: loader,
      controller: controller,
      itemExtent: itemExtent,
    );
  }
  
  // Helper methods
  
  static List<List<T>> _chunkList<T>(List<T> list, int chunkSize) {
    final chunks = <List<T>>[];
    for (var i = 0; i < list.length; i += chunkSize) {
      final end = (i + chunkSize < list.length) ? i + chunkSize : list.length;
      chunks.add(list.sublist(i, end));
    }
    return chunks;
  }
}

/// Result model for paginated data
class PaginatedResult<T> {
  final List<T> items;
  final int page;
  final int pageSize;
  final bool hasMore;
  final int? totalCount;
  
  const PaginatedResult({
    required this.items,
    required this.page,
    required this.pageSize,
    required this.hasMore,
    this.totalCount,
  });
  
  int get loadedCount => (page + 1) * pageSize;
  double get loadProgress => totalCount != null ? loadedCount / totalCount! : 0.0;
}

/// Cache model for pagination
class PaginationCache {
  final List<dynamic> items;
  final int page;
  final int pageSize;
  final bool hasMore;
  final int? totalCount;
  final DateTime cachedAt;
  final Duration cacheDuration;
  
  PaginationCache({
    required this.items,
    required this.page,
    required this.pageSize,
    required this.hasMore,
    this.totalCount,
    required this.cachedAt,
    required this.cacheDuration,
  });
  
  bool get isExpired => DateTime.now().difference(cachedAt) > cacheDuration;
}

/// Virtual scroll view for extremely large lists
class VirtualScrollView<T> extends StatefulWidget {
  final String cacheKey;
  final int itemCount;
  final int itemsPerPage;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final Future<List<T>> Function(int page, int pageSize) loader;
  final ScrollController? controller;
  final double? itemExtent;
  
  const VirtualScrollView({
    super.key,
    required this.cacheKey,
    required this.itemCount,
    required this.itemsPerPage,
    required this.itemBuilder,
    required this.loader,
    this.controller,
    this.itemExtent,
  });

  @override
  State<VirtualScrollView<T>> createState() => _VirtualScrollViewState<T>();
}

class _VirtualScrollViewState<T> extends State<VirtualScrollView<T>> {
  late ScrollController _scrollController;
  final Map<int, List<T>> _pageCache = {};
  final Set<int> _loadingPages = {};
  
  @override
  void initState() {
    super.initState();
    _scrollController = widget.controller ?? ScrollController();
    _scrollController.addListener(_onScroll);
    _preloadVisiblePages();
  }
  
  @override
  void dispose() {
    if (widget.controller == null) {
      _scrollController.dispose();
    }
    super.dispose();
  }
  
  void _onScroll() {
    _preloadVisiblePages();
  }
  
  void _preloadVisiblePages() {
    final viewport = _scrollController.position.viewportDimension;
    final scrollOffset = _scrollController.position.pixels;
    final itemHeight = widget.itemExtent ?? 100.0; // Estimate if not provided
    
    final firstVisibleIndex = (scrollOffset / itemHeight).floor();
    final lastVisibleIndex = ((scrollOffset + viewport) / itemHeight).ceil();
    
    final firstPage = firstVisibleIndex ~/ widget.itemsPerPage;
    final lastPage = lastVisibleIndex ~/ widget.itemsPerPage;
    
    // Preload current, previous, and next pages
    for (var page = (firstPage - 1).clamp(0, double.infinity).toInt();
         page <= lastPage + 1;
         page++) {
      _loadPageIfNeeded(page);
    }
  }
  
  Future<void> _loadPageIfNeeded(int page) async {
    if (_pageCache.containsKey(page) || _loadingPages.contains(page)) {
      return;
    }
    
    _loadingPages.add(page);
    
    try {
      final result = await LazyLoadingService.loadPage<T>(
        cacheKey: widget.cacheKey,
        page: page,
        pageSize: widget.itemsPerPage,
        loader: widget.loader,
      );
      
      result.fold(
        (failure) {
          // Handle error
          _loadingPages.remove(page);
        },
        (paginatedResult) {
          if (mounted) {
            setState(() {
              _pageCache[page] = paginatedResult.items;
              _loadingPages.remove(page);
            });
          }
        },
      );
    } catch (e) {
      _loadingPages.remove(page);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      controller: _scrollController,
      itemCount: widget.itemCount,
      itemExtent: widget.itemExtent,
      itemBuilder: (context, index) {
        final page = index ~/ widget.itemsPerPage;
        final indexInPage = index % widget.itemsPerPage;
        
        if (!_pageCache.containsKey(page)) {
          _loadPageIfNeeded(page);
          return const SizedBox(
            height: 100,
            child: Center(child: CircularProgressIndicator()),
          );
        }
        
        final pageItems = _pageCache[page]!;
        if (indexInPage >= pageItems.length) {
          return const SizedBox.shrink();
        }
        
        return widget.itemBuilder(context, index);
      },
    );
  }
}