import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart';

/// Manages search history and provides intelligent search suggestions
class SearchHistoryManager {
  static const String _searchHistoryKey = 'search_history';
  static const String _searchStatsKey = 'search_stats';
  static const int _maxHistoryItems = 50;
  
  static SharedPreferences? _prefs;
  
  /// Initialize the search history manager
  static Future<void> initialize() async {
    _prefs = await SharedPreferences.getInstance();
  }
  
  /// Add a search query to history
  static Future<void> addSearchQuery(String query) async {
    if (query.trim().isEmpty) return;
    
    await _ensureInitialized();
    
    final history = await getSearchHistory();
    final normalizedQuery = query.trim().toLowerCase();
    
    // Remove existing occurrence to avoid duplicates
    history.removeWhere((item) => item.query.toLowerCase() == normalizedQuery);
    
    // Add to beginning of list
    history.insert(0, SearchHistoryItem(
      query: query.trim(),
      timestamp: DateTime.now(),
      searchCount: 1,
    ));
    
    // Keep only the most recent items
    if (history.length > _maxHistoryItems) {
      history.removeRange(_maxHistoryItems, history.length);
    }
    
    await _saveSearchHistory(history);
    await _updateSearchStats(query);
  }
  
  /// Get search history
  static Future<List<SearchHistoryItem>> getSearchHistory() async {
    await _ensureInitialized();
    
    final historyJson = _prefs!.getStringList(_searchHistoryKey) ?? [];
    
    return historyJson.map((json) {
      try {
        return SearchHistoryItem.fromJson(json);
      } catch (e) {
        debugPrint('Error parsing search history item: $e');
        return null;
      }
    }).where((item) => item != null).cast<SearchHistoryItem>().toList();
  }
  
  /// Get recent search queries
  static Future<List<String>> getRecentSearches({int limit = 10}) async {
    final history = await getSearchHistory();
    return history.take(limit).map((item) => item.query).toList();
  }
  
  /// Get popular search queries
  static Future<List<String>> getPopularSearches({int limit = 10}) async {
    final history = await getSearchHistory();
    
    // Group by normalized query and sum search counts
    final queryMap = <String, int>{};
    for (final item in history) {
      final normalized = item.query.toLowerCase();
      queryMap[normalized] = (queryMap[normalized] ?? 0) + item.searchCount;
    }
    
    // Sort by popularity and return original queries
    final popularQueries = queryMap.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    
    return popularQueries
        .take(limit)
        .map((entry) => history.firstWhere(
          (item) => item.query.toLowerCase() == entry.key,
        ).query)
        .toList();
  }
  
  /// Remove a search query from history
  static Future<void> removeSearchQuery(String query) async {
    await _ensureInitialized();
    
    final history = await getSearchHistory();
    history.removeWhere((item) => item.query.toLowerCase() == query.toLowerCase());
    
    await _saveSearchHistory(history);
  }
  
  /// Clear all search history
  static Future<void> clearSearchHistory() async {
    await _ensureInitialized();
    
    await _prefs!.remove(_searchHistoryKey);
    await _prefs!.remove(_searchStatsKey);
  }
  
  /// Get search suggestions based on history
  static Future<List<String>> getSearchSuggestions(
    String query, {
    int limit = 5,
  }) async {
    if (query.trim().isEmpty) return [];
    
    final history = await getSearchHistory();
    final normalizedQuery = query.toLowerCase();
    
    // Find queries that start with the input
    final suggestions = history
        .where((item) => item.query.toLowerCase().startsWith(normalizedQuery))
        .map((item) => item.query)
        .take(limit)
        .toList();
    
    // If we don't have enough, look for queries that contain the input
    if (suggestions.length < limit) {
      final containingSuggestions = history
          .where((item) => 
              item.query.toLowerCase().contains(normalizedQuery) &&
              !suggestions.contains(item.query))
          .map((item) => item.query)
          .take(limit - suggestions.length)
          .toList();
      
      suggestions.addAll(containingSuggestions);
    }
    
    return suggestions;
  }
  
  /// Get search statistics
  static Future<SearchStats> getSearchStats() async {
    await _ensureInitialized();
    
    final statsJson = _prefs!.getString(_searchStatsKey);
    if (statsJson != null) {
      try {
        return SearchStats.fromJson(statsJson);
      } catch (e) {
        debugPrint('Error parsing search stats: $e');
      }
    }
    
    return SearchStats(
      totalSearches: 0,
      uniqueQueries: 0,
      averageQueryLength: 0,
      mostPopularQuery: '',
      lastSearchDate: null,
    );
  }
  
  /// Save search history to storage
  static Future<void> _saveSearchHistory(List<SearchHistoryItem> history) async {
    final historyJson = history.map((item) => item.toJson()).toList();
    await _prefs!.setStringList(_searchHistoryKey, historyJson);
  }
  
  /// Update search statistics
  static Future<void> _updateSearchStats(String query) async {
    final stats = await getSearchStats();
    final history = await getSearchHistory();
    
    final updatedStats = SearchStats(
      totalSearches: stats.totalSearches + 1,
      uniqueQueries: history.map((item) => item.query.toLowerCase()).toSet().length,
      averageQueryLength: history.isEmpty ? 0 : 
          history.map((item) => item.query.length).reduce((a, b) => a + b) / history.length,
      mostPopularQuery: await _getMostPopularQuery(history),
      lastSearchDate: DateTime.now(),
    );
    
    await _prefs!.setString(_searchStatsKey, updatedStats.toJson());
  }
  
  /// Get the most popular query
  static Future<String> _getMostPopularQuery(List<SearchHistoryItem> history) async {
    if (history.isEmpty) return '';
    
    final queryMap = <String, int>{};
    for (final item in history) {
      final normalized = item.query.toLowerCase();
      queryMap[normalized] = (queryMap[normalized] ?? 0) + item.searchCount;
    }
    
    if (queryMap.isEmpty) return '';
    
    final mostPopular = queryMap.entries.reduce((a, b) => a.value > b.value ? a : b);
    return history.firstWhere((item) => item.query.toLowerCase() == mostPopular.key).query;
  }
  
  /// Ensure the manager is initialized
  static Future<void> _ensureInitialized() async {
    _prefs ??= await SharedPreferences.getInstance();
  }
}

/// Search history item
class SearchHistoryItem {
  final String query;
  final DateTime timestamp;
  final int searchCount;
  
  const SearchHistoryItem({
    required this.query,
    required this.timestamp,
    required this.searchCount,
  });
  
  Map<String, dynamic> toMap() {
    return {
      'query': query,
      'timestamp': timestamp.millisecondsSinceEpoch,
      'searchCount': searchCount,
    };
  }
  
  factory SearchHistoryItem.fromMap(Map<String, dynamic> map) {
    return SearchHistoryItem(
      query: map['query'] ?? '',
      timestamp: DateTime.fromMillisecondsSinceEpoch(map['timestamp'] ?? 0),
      searchCount: map['searchCount'] ?? 1,
    );
  }
  
  String toJson() {
    return '{"query":"$query","timestamp":${timestamp.millisecondsSinceEpoch},"searchCount":$searchCount}';
  }
  
  factory SearchHistoryItem.fromJson(String json) {
    // Simple JSON parsing - in production, use proper JSON parsing
    final regex = RegExp(r'"query":"([^"]+)","timestamp":(\d+),"searchCount":(\d+)');
    final match = regex.firstMatch(json);
    
    if (match != null) {
      return SearchHistoryItem(
        query: match.group(1) ?? '',
        timestamp: DateTime.fromMillisecondsSinceEpoch(int.tryParse(match.group(2) ?? '0') ?? 0),
        searchCount: int.tryParse(match.group(3) ?? '1') ?? 1,
      );
    }
    
    throw FormatException('Invalid search history item JSON: $json');
  }
  
  @override
  String toString() => 'SearchHistoryItem(query: $query, timestamp: $timestamp, searchCount: $searchCount)';
}

/// Search statistics
class SearchStats {
  final int totalSearches;
  final int uniqueQueries;
  final double averageQueryLength;
  final String mostPopularQuery;
  final DateTime? lastSearchDate;
  
  const SearchStats({
    required this.totalSearches,
    required this.uniqueQueries,
    required this.averageQueryLength,
    required this.mostPopularQuery,
    required this.lastSearchDate,
  });
  
  Map<String, dynamic> toMap() {
    return {
      'totalSearches': totalSearches,
      'uniqueQueries': uniqueQueries,
      'averageQueryLength': averageQueryLength,
      'mostPopularQuery': mostPopularQuery,
      'lastSearchDate': lastSearchDate?.millisecondsSinceEpoch,
    };
  }
  
  factory SearchStats.fromMap(Map<String, dynamic> map) {
    return SearchStats(
      totalSearches: map['totalSearches'] ?? 0,
      uniqueQueries: map['uniqueQueries'] ?? 0,
      averageQueryLength: (map['averageQueryLength'] ?? 0).toDouble(),
      mostPopularQuery: map['mostPopularQuery'] ?? '',
      lastSearchDate: map['lastSearchDate'] != null
          ? DateTime.fromMillisecondsSinceEpoch(map['lastSearchDate'])
          : null,
    );
  }
  
  String toJson() {
    return '{"totalSearches":$totalSearches,"uniqueQueries":$uniqueQueries,"averageQueryLength":$averageQueryLength,"mostPopularQuery":"$mostPopularQuery","lastSearchDate":${lastSearchDate?.millisecondsSinceEpoch}}';
  }
  
  factory SearchStats.fromJson(String json) {
    // Simple JSON parsing - in production, use proper JSON parsing
    final regex = RegExp(r'"totalSearches":(\d+),"uniqueQueries":(\d+),"averageQueryLength":([0-9.]+),"mostPopularQuery":"([^"]*)","lastSearchDate":(\d+|null)');
    final match = regex.firstMatch(json);
    
    if (match != null) {
      return SearchStats(
        totalSearches: int.tryParse(match.group(1) ?? '0') ?? 0,
        uniqueQueries: int.tryParse(match.group(2) ?? '0') ?? 0,
        averageQueryLength: double.tryParse(match.group(3) ?? '0') ?? 0,
        mostPopularQuery: match.group(4) ?? '',
        lastSearchDate: match.group(5) != 'null' 
            ? DateTime.fromMillisecondsSinceEpoch(int.tryParse(match.group(5) ?? '0') ?? 0)
            : null,
      );
    }
    
    throw FormatException('Invalid search stats JSON: $json');
  }
  
  @override
  String toString() => 'SearchStats(totalSearches: $totalSearches, uniqueQueries: $uniqueQueries, averageQueryLength: $averageQueryLength)';
}