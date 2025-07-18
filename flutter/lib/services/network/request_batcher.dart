import 'package:flutter/foundation.dart';
import 'package:dio/dio.dart';
import 'package:rxdart/rxdart.dart';
import 'dart:async';
import 'dart:collection';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';

/// Service for batching and throttling network requests
class RequestBatcher {
  static const Duration _defaultBatchWindow = Duration(milliseconds: 100);
  static const Duration _defaultThrottleDelay = Duration(milliseconds: 500);
  static const int _defaultMaxBatchSize = 10;
  static const int _defaultMaxConcurrentRequests = 3;
  
  // Singleton instance
  static final RequestBatcher _instance = RequestBatcher._internal();
  factory RequestBatcher() => _instance;
  RequestBatcher._internal();
  
  // Request queues and batches
  final Map<String, BatchQueue> _batchQueues = {};
  final Map<String, ThrottleQueue> _throttleQueues = {};
  final Map<String, StreamController<BatchResult>> _resultStreams = {};
  
  // Active requests tracking
  final Set<String> _activeRequests = {};
  int _concurrentRequests = 0;
  
  // Dio instance for making requests
  final Dio _dio = Dio();
  
  /// Add a request to be batched
  Future<T> addBatchRequest<T>({
    required String batchKey,
    required String requestId,
    required BatchableRequest request,
    Duration batchWindow = _defaultBatchWindow,
    int maxBatchSize = _defaultMaxBatchSize,
  }) async {
    // Get or create batch queue
    _batchQueues[batchKey] ??= BatchQueue(
      batchKey: batchKey,
      batchWindow: batchWindow,
      maxBatchSize: maxBatchSize,
    );
    
    final queue = _batchQueues[batchKey]!;
    
    // Add request to queue
    final completer = Completer<T>();
    queue.addRequest(BatchQueueItem(
      requestId: requestId,
      request: request,
      completer: completer,
    ));
    
    // Schedule batch execution
    _scheduleBatchExecution(batchKey);
    
    return completer.future;
  }
  
  /// Add a request to be throttled
  Future<Response> addThrottledRequest({
    required String throttleKey,
    required String url,
    required String method,
    Map<String, dynamic>? data,
    Map<String, dynamic>? queryParameters,
    Map<String, dynamic>? headers,
    Duration throttleDelay = _defaultThrottleDelay,
    RequestPriority priority = RequestPriority.normal,
  }) async {
    // Get or create throttle queue
    _throttleQueues[throttleKey] ??= ThrottleQueue(
      throttleKey: throttleKey,
      throttleDelay: throttleDelay,
    );
    
    final queue = _throttleQueues[throttleKey]!;
    
    // Create request item
    final requestItem = ThrottledRequest(
      id: '${throttleKey}_${DateTime.now().millisecondsSinceEpoch}',
      url: url,
      method: method,
      data: data,
      queryParameters: queryParameters,
      headers: headers,
      priority: priority,
      timestamp: DateTime.now(),
    );
    
    // Add to queue
    final completer = Completer<Response>();
    queue.addRequest(requestItem, completer);
    
    // Process queue
    _processThrottleQueue(throttleKey);
    
    return completer.future;
  }
  
  /// Batch multiple GET requests
  Future<Map<String, Either<Failure, T>>> batchGetRequests<T>({
    required Map<String, String> requests, // id -> url
    required T Function(Map<String, dynamic>) parser,
    Map<String, dynamic>? commonHeaders,
    Duration batchWindow = _defaultBatchWindow,
  }) async {
    final results = <String, Either<Failure, T>>{};
    final futures = <String, Future<T>>{};
    
    // Group requests by base URL for efficient batching
    final groupedRequests = _groupRequestsByBaseUrl(requests);
    
    for (final entry in groupedRequests.entries) {
      final baseUrl = entry.key;
      final urlMap = entry.value;
      
      // Create batch request
      final batchRequest = BatchableRequest(
        type: BatchRequestType.multiGet,
        baseUrl: baseUrl,
        requests: urlMap.entries.map((e) => SingleRequest(
          id: e.key,
          path: e.value.replaceFirst(baseUrl, ''),
          method: 'GET',
        )).toList(),
        headers: commonHeaders,
      );
      
      // Add to batch
      for (final id in urlMap.keys) {
        futures[id] = addBatchRequest<T>(
          batchKey: baseUrl,
          requestId: id,
          request: batchRequest,
          batchWindow: batchWindow,
        );
      }
    }
    
    // Wait for all results
    await Future.forEach(futures.entries, (entry) async {
      try {
        final result = await entry.value;
        results[entry.key] = Right(result);
      } catch (e) {
        results[entry.key] = Left(ServerFailure(e.toString()));
      }
    });
    
    return results;
  }
  
  /// Schedule batch execution
  void _scheduleBatchExecution(String batchKey) {
    final queue = _batchQueues[batchKey];
    if (queue == null || queue.isProcessing) return;
    
    // Schedule execution after batch window
    Timer(queue.batchWindow, () {
      _executeBatch(batchKey);
    });
  }
  
  /// Execute a batch of requests
  Future<void> _executeBatch(String batchKey) async {
    final queue = _batchQueues[batchKey];
    if (queue == null || queue.isEmpty) return;
    
    queue.isProcessing = true;
    
    // Get requests to process (up to max batch size)
    final requests = queue.getNextBatch();
    if (requests.isEmpty) {
      queue.isProcessing = false;
      return;
    }
    
    try {
      // Wait for available concurrent slot
      await _waitForConcurrentSlot();
      _concurrentRequests++;
      
      // Group requests by type for efficient processing
      final groupedRequests = _groupRequestsByType(requests);
      
      // Execute each group
      for (final entry in groupedRequests.entries) {
        await _executeRequestGroup(entry.key, entry.value);
      }
    } catch (e) {
      // Handle batch failure
      for (final item in requests) {
        item.completer.completeError(e);
      }
    } finally {
      _concurrentRequests--;
      queue.isProcessing = false;
      
      // Schedule next batch if queue not empty
      if (!queue.isEmpty) {
        _scheduleBatchExecution(batchKey);
      }
    }
  }
  
  /// Execute a group of similar requests
  Future<void> _executeRequestGroup(
    BatchRequestType type,
    List<BatchQueueItem> items,
  ) async {
    if (items.isEmpty) return;
    
    final firstRequest = items.first.request;
    
    switch (type) {
      case BatchRequestType.multiGet:
        await _executeMultiGet(firstRequest.baseUrl, items);
        break;
      case BatchRequestType.graphQL:
        await _executeGraphQLBatch(firstRequest.baseUrl, items);
        break;
      case BatchRequestType.custom:
        await _executeCustomBatch(items);
        break;
    }
  }
  
  /// Execute multiple GET requests efficiently
  Future<void> _executeMultiGet(
    String baseUrl,
    List<BatchQueueItem> items,
  ) async {
    try {
      // Create batch endpoint if server supports it
      final batchUrl = '$baseUrl/batch';
      final batchData = {
        'requests': items.map((item) => {
          'id': item.requestId,
          'method': 'GET',
          'path': item.request.requests.firstWhere(
            (r) => r.id == item.requestId,
          ).path,
        }).toList(),
      };
      
      final response = await _dio.post(
        batchUrl,
        data: batchData,
        options: Options(
          headers: items.first.request.headers,
        ),
      );
      
      // Parse batch response
      final batchResults = response.data['results'] as List;
      
      for (final result in batchResults) {
        final item = items.firstWhere(
          (i) => i.requestId == result['id'],
        );
        
        if (result['error'] != null) {
          item.completer.completeError(result['error']);
        } else {
          item.completer.complete(result['data']);
        }
      }
    } catch (e) {
      // Fallback to individual requests if batch fails
      await _executeFallbackRequests(items);
    }
  }
  
  /// Execute GraphQL batch requests
  Future<void> _executeGraphQLBatch(
    String endpoint,
    List<BatchQueueItem> items,
  ) async {
    try {
      // Combine GraphQL queries
      final batchedQuery = _combineGraphQLQueries(items);
      
      final response = await _dio.post(
        endpoint,
        data: {'query': batchedQuery},
        options: Options(
          headers: items.first.request.headers,
        ),
      );
      
      // Distribute results
      final data = response.data['data'] as Map<String, dynamic>;
      
      for (final item in items) {
        final resultKey = 'query_${item.requestId}';
        if (data.containsKey(resultKey)) {
          item.completer.complete(data[resultKey]);
        } else {
          item.completer.completeError('No data for query $resultKey');
        }
      }
    } catch (e) {
      // Handle batch failure
      for (final item in items) {
        item.completer.completeError(e);
      }
    }
  }
  
  /// Execute custom batch requests
  Future<void> _executeCustomBatch(List<BatchQueueItem> items) async {
    // Execute custom batch logic based on request configuration
    for (final item in items) {
      try {
        final response = await _executepojedRequest(item.request);
        item.completer.complete(response);
      } catch (e) {
        item.completer.completeError(e);
      }
    }
  }
  
  /// Execute fallback individual requests
  Future<void> _executeFallbackRequests(List<BatchQueueItem> items) async {
    final futures = <Future>[];
    
    for (final item in items) {
      futures.add(_executeSingleRequest(item));
    }
    
    await Future.wait(futures);
  }
  
  /// Execute a single request
  Future<void> _executeSingleRequest(BatchQueueItem item) async {
    try {
      final request = item.request.requests.firstWhere(
        (r) => r.id == item.requestId,
      );
      
      final response = await _dio.request(
        '${item.request.baseUrl}${request.path}',
        data: request.data,
        queryParameters: request.queryParameters,
        options: Options(
          method: request.method,
          headers: item.request.headers,
        ),
      );
      
      item.completer.complete(response.data);
    } catch (e) {
      item.completer.completeError(e);
    }
  }
  
  /// Process throttle queue
  void _processThrottleQueue(String throttleKey) async {
    final queue = _throttleQueues[throttleKey];
    if (queue == null || queue.isProcessing) return;
    
    queue.isProcessing = true;
    
    while (queue.hasRequests && _concurrentRequests < _defaultMaxConcurrentRequests) {
      final request = queue.getNextRequest();
      if (request == null) break;
      
      // Check if enough time has passed since last request
      final now = DateTime.now();
      if (queue.lastRequestTime != null) {
        final elapsed = now.difference(queue.lastRequestTime!);
        if (elapsed < queue.throttleDelay) {
          // Wait for remaining time
          await Future.delayed(queue.throttleDelay - elapsed);
        }
      }
      
      queue.lastRequestTime = DateTime.now();
      
      // Execute request
      _concurrentRequests++;
      
      try {
        final response = await _dio.request(
          request.item.url,
          data: request.item.data,
          queryParameters: request.item.queryParameters,
          options: Options(
            method: request.item.method,
            headers: request.item.headers,
          ),
        );
        
        request.completer.complete(response);
      } catch (e) {
        request.completer.completeError(e);
      } finally {
        _concurrentRequests--;
      }
    }
    
    queue.isProcessing = false;
  }
  
  /// Wait for available concurrent slot
  Future<void> _waitForConcurrentSlot() async {
    while (_concurrentRequests >= _defaultMaxConcurrentRequests) {
      await Future.delayed(const Duration(milliseconds: 50));
    }
  }
  
  /// Group requests by base URL
  Map<String, Map<String, String>> _groupRequestsByBaseUrl(
    Map<String, String> requests,
  ) {
    final grouped = <String, Map<String, String>>{};
    
    for (final entry in requests.entries) {
      final uri = Uri.parse(entry.value);
      final baseUrl = '${uri.scheme}://${uri.host}';
      
      grouped[baseUrl] ??= {};
      grouped[baseUrl]![entry.key] = entry.value;
    }
    
    return grouped;
  }
  
  /// Group requests by type
  Map<BatchRequestType, List<BatchQueueItem>> _groupRequestsByType(
    List<BatchQueueItem> requests,
  ) {
    final grouped = <BatchRequestType, List<BatchQueueItem>>{};
    
    for (final request in requests) {
      grouped[request.request.type] ??= [];
      grouped[request.request.type]!.add(request);
    }
    
    return grouped;
  }
  
  /// Combine GraphQL queries
  String _combineGraphQLQueries(List<BatchQueueItem> items) {
    final queries = <String>[];
    
    for (final item in items) {
      final query = item.request.graphQLQuery;
      if (query != null) {
        queries.add('query_${item.requestId}: $query');
      }
    }
    
    return '{ ${queries.join(' ')} }';
  }
  
  /// Cancel all pending requests
  void cancelAll() {
    for (final queue in _batchQueues.values) {
      queue.cancelAll();
    }
    
    for (final queue in _throttleQueues.values) {
      queue.cancelAll();
    }
    
    _batchQueues.clear();
    _throttleQueues.clear();
  }
  
  /// Get queue statistics
  RequestBatcherStats getStatistics() {
    int totalQueued = 0;
    int totalActive = _concurrentRequests;
    
    for (final queue in _batchQueues.values) {
      totalQueued += queue.pendingCount;
    }
    
    for (final queue in _throttleQueues.values) {
      totalQueued += queue.pendingCount;
    }
    
    return RequestBatcherStats(
      totalQueued: totalQueued,
      totalActive: totalActive,
      batchQueues: _batchQueues.length,
      throttleQueues: _throttleQueues.length,
    );
  }
}

/// Batch queue for grouping requests
class BatchQueue {
  final String batchKey;
  final Duration batchWindow;
  final int maxBatchSize;
  final Queue<BatchQueueItem> _queue = Queue();
  bool isProcessing = false;
  
  BatchQueue({
    required this.batchKey,
    required this.batchWindow,
    required this.maxBatchSize,
  });
  
  bool get isEmpty => _queue.isEmpty;
  int get pendingCount => _queue.length;
  
  void addRequest(BatchQueueItem item) {
    _queue.add(item);
  }
  
  List<BatchQueueItem> getNextBatch() {
    final batch = <BatchQueueItem>[];
    
    while (_queue.isNotEmpty && batch.length < maxBatchSize) {
      batch.add(_queue.removeFirst());
    }
    
    return batch;
  }
  
  void cancelAll() {
    for (final item in _queue) {
      item.completer.completeError('Request cancelled');
    }
    _queue.clear();
  }
}

/// Throttle queue for rate limiting
class ThrottleQueue {
  final String throttleKey;
  final Duration throttleDelay;
  final PriorityQueue<ThrottleQueueItem> _queue = PriorityQueue();
  bool isProcessing = false;
  DateTime? lastRequestTime;
  
  ThrottleQueue({
    required this.throttleKey,
    required this.throttleDelay,
  });
  
  bool get hasRequests => _queue.isNotEmpty;
  int get pendingCount => _queue.length;
  
  void addRequest(ThrottledRequest request, Completer<Response> completer) {
    _queue.add(ThrottleQueueItem(
      item: request,
      completer: completer,
    ));
  }
  
  ThrottleQueueItem? getNextRequest() {
    if (_queue.isEmpty) return null;
    return _queue.removeFirst();
  }
  
  void cancelAll() {
    while (_queue.isNotEmpty) {
      final item = _queue.removeFirst();
      item.completer.completeError('Request cancelled');
    }
  }
}

/// Models

class BatchableRequest {
  final BatchRequestType type;
  final String baseUrl;
  final List<SingleRequest> requests;
  final Map<String, dynamic>? headers;
  final String? graphQLQuery;
  
  const BatchableRequest({
    required this.type,
    required this.baseUrl,
    required this.requests,
    this.headers,
    this.graphQLQuery,
  });
}

class SingleRequest {
  final String id;
  final String path;
  final String method;
  final dynamic data;
  final Map<String, dynamic>? queryParameters;
  
  const SingleRequest({
    required this.id,
    required this.path,
    required this.method,
    this.data,
    this.queryParameters,
  });
}

class BatchQueueItem {
  final String requestId;
  final BatchableRequest request;
  final Completer completer;
  
  BatchQueueItem({
    required this.requestId,
    required this.request,
    required this.completer,
  });
}

class ThrottledRequest {
  final String id;
  final String url;
  final String method;
  final dynamic data;
  final Map<String, dynamic>? queryParameters;
  final Map<String, dynamic>? headers;
  final RequestPriority priority;
  final DateTime timestamp;
  
  const ThrottledRequest({
    required this.id,
    required this.url,
    required this.method,
    this.data,
    this.queryParameters,
    this.headers,
    required this.priority,
    required this.timestamp,
  });
}

class ThrottleQueueItem implements Comparable<ThrottleQueueItem> {
  final ThrottledRequest item;
  final Completer<Response> completer;
  
  ThrottleQueueItem({
    required this.item,
    required this.completer,
  });
  
  @override
  int compareTo(ThrottleQueueItem other) {
    // Higher priority first
    final priorityCompare = other.item.priority.index.compareTo(item.priority.index);
    if (priorityCompare != 0) return priorityCompare;
    
    // Earlier timestamp first
    return item.timestamp.compareTo(other.item.timestamp);
  }
}

class BatchResult {
  final String requestId;
  final dynamic data;
  final dynamic error;
  
  const BatchResult({
    required this.requestId,
    this.data,
    this.error,
  });
}

class RequestBatcherStats {
  final int totalQueued;
  final int totalActive;
  final int batchQueues;
  final int throttleQueues;
  
  const RequestBatcherStats({
    required this.totalQueued,
    required this.totalActive,
    required this.batchQueues,
    required this.throttleQueues,
  });
}

enum BatchRequestType {
  multiGet,
  graphQL,
  custom,
}

enum RequestPriority {
  low,
  normal,
  high,
  critical,
}

/// Priority queue implementation
class PriorityQueue<T extends Comparable<T>> {
  final List<T> _heap = [];
  
  bool get isEmpty => _heap.isEmpty;
  bool get isNotEmpty => _heap.isNotEmpty;
  int get length => _heap.length;
  
  void add(T item) {
    _heap.add(item);
    _bubbleUp(_heap.length - 1);
  }
  
  T removeFirst() {
    if (_heap.isEmpty) throw StateError('Priority queue is empty');
    
    final first = _heap.first;
    final last = _heap.removeLast();
    
    if (_heap.isNotEmpty) {
      _heap[0] = last;
      _bubbleDown(0);
    }
    
    return first;
  }
  
  void _bubbleUp(int index) {
    while (index > 0) {
      final parentIndex = (index - 1) ~/ 2;
      
      if (_heap[index].compareTo(_heap[parentIndex]) >= 0) break;
      
      final temp = _heap[index];
      _heap[index] = _heap[parentIndex];
      _heap[parentIndex] = temp;
      
      index = parentIndex;
    }
  }
  
  void _bubbleDown(int index) {
    while (true) {
      int smallest = index;
      final left = 2 * index + 1;
      final right = 2 * index + 2;
      
      if (left < _heap.length && 
          _heap[left].compareTo(_heap[smallest]) < 0) {
        smallest = left;
      }
      
      if (right < _heap.length && 
          _heap[right].compareTo(_heap[smallest]) < 0) {
        smallest = right;
      }
      
      if (smallest == index) break;
      
      final temp = _heap[index];
      _heap[index] = _heap[smallest];
      _heap[smallest] = temp;
      
      index = smallest;
    }
  }
}