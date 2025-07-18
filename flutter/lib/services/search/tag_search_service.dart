import 'package:flutter/material.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/services/search/search_history_manager.dart';
import 'dart:math' as math;

/// Service for tag-based search with auto-completion
class TagSearchService {
  static const int _maxSuggestions = 20;
  static const double _minSimilarityThreshold = 0.3;
  
  /// Get tag suggestions based on query and existing garments
  static List<TagSuggestion> getTagSuggestions(
    String query,
    List<GarmentModel> garments, {
    int maxSuggestions = _maxSuggestions,
  }) {
    if (query.isEmpty) return [];
    
    final suggestions = <TagSuggestion>[];
    final lowerQuery = query.toLowerCase();
    
    // Get all unique tags from garments
    final allTags = <String>{};
    final tagFrequency = <String, int>{};
    
    for (final garment in garments) {
      for (final tag in garment.tags) {
        allTags.add(tag);
        tagFrequency[tag] = (tagFrequency[tag] ?? 0) + 1;
      }
    }
    
    // Score and filter tag suggestions
    for (final tag in allTags) {
      final similarity = _calculateTagSimilarity(lowerQuery, tag.toLowerCase());
      
      if (similarity > _minSimilarityThreshold) {
        final frequency = tagFrequency[tag] ?? 0;
        final popularityScore = frequency / garments.length;
        
        suggestions.add(TagSuggestion(
          tag: tag,
          similarity: similarity,
          frequency: frequency,
          popularityScore: popularityScore,
          matchType: _getMatchType(lowerQuery, tag.toLowerCase()),
        ));
      }
    }
    
    // Add common fashion tags that might not exist in wardrobe
    suggestions.addAll(_getCommonFashionTags(lowerQuery));
    
    // Sort by relevance and return top suggestions
    suggestions.sort((a, b) {
      // Prioritize exact matches, then prefix matches, then similarity
      if (a.matchType != b.matchType) {
        return a.matchType.priority.compareTo(b.matchType.priority);
      }
      
      // Then by similarity score
      if (a.similarity != b.similarity) {
        return b.similarity.compareTo(a.similarity);
      }
      
      // Finally by popularity in wardrobe
      return b.popularityScore.compareTo(a.popularityScore);
    });
    
    return suggestions.take(maxSuggestions).toList();
  }
  
  /// Search garments by multiple tags
  static List<TagSearchResult> searchGarmentsByTags(
    List<String> tags,
    List<GarmentModel> garments, {
    TagSearchMode mode = TagSearchMode.any,
    int maxResults = 50,
  }) {
    if (tags.isEmpty) return [];
    
    final results = <TagSearchResult>[];
    final lowerTags = tags.map((t) => t.toLowerCase()).toList();
    
    for (final garment in garments) {
      final garmentTags = garment.tags.map((t) => t.toLowerCase()).toList();
      final matchScore = _calculateTagMatchScore(lowerTags, garmentTags, mode);
      
      if (matchScore > 0) {
        final matchedTags = _getMatchedTags(lowerTags, garmentTags);
        
        results.add(TagSearchResult(
          garment: garment,
          matchScore: matchScore,
          matchedTags: matchedTags,
          totalTags: garment.tags.length,
          queryTags: tags,
        ));
      }
    }
    
    // Sort by match score and return top results
    results.sort((a, b) => b.matchScore.compareTo(a.matchScore));
    return results.take(maxResults).toList();
  }
  
  /// Get tag categories and their associated tags
  static Map<String, List<String>> getTagCategories(List<GarmentModel> garments) {
    final categories = <String, Set<String>>{
      'Style': <String>{},
      'Color': <String>{},
      'Material': <String>{},
      'Season': <String>{},
      'Occasion': <String>{},
      'Fit': <String>{},
      'Pattern': <String>{},
      'Other': <String>{},
    };
    
    // Extract all tags from garments
    final allTags = <String>{};
    for (final garment in garments) {
      allTags.addAll(garment.tags);
    }
    
    // Categorize tags
    for (final tag in allTags) {
      final category = _categorizeTag(tag);
      categories[category]?.add(tag);
    }
    
    // Convert to sorted lists
    final result = <String, List<String>>{};
    for (final entry in categories.entries) {
      if (entry.value.isNotEmpty) {
        result[entry.key] = entry.value.toList()..sort();
      }
    }
    
    return result;
  }
  
  /// Get related tags for a given tag
  static List<String> getRelatedTags(
    String tag,
    List<GarmentModel> garments, {
    int maxResults = 10,
  }) {
    final lowerTag = tag.toLowerCase();
    final coOccurrences = <String, int>{};
    
    // Find garments that have this tag
    final relevantGarments = garments.where((g) => 
        g.tags.any((t) => t.toLowerCase() == lowerTag)).toList();
    
    // Count co-occurrences of other tags
    for (final garment in relevantGarments) {
      for (final otherTag in garment.tags) {
        if (otherTag.toLowerCase() != lowerTag) {
          coOccurrences[otherTag] = (coOccurrences[otherTag] ?? 0) + 1;
        }
      }
    }
    
    // Sort by frequency and return top results
    final sortedTags = coOccurrences.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    
    return sortedTags.take(maxResults).map((e) => e.key).toList();
  }
  
  /// Save tag search to history
  static Future<void> saveTagSearch(List<String> tags) async {
    final query = tags.join(', ');
    await SearchHistoryManager.addSearchQuery(query);
  }
  
  /// Calculate similarity between query and tag
  static double _calculateTagSimilarity(String query, String tag) {
    // Exact match
    if (query == tag) return 1.0;
    
    // Prefix match
    if (tag.startsWith(query)) return 0.9;
    
    // Contains match
    if (tag.contains(query)) return 0.7;
    
    // Levenshtein distance similarity
    final distance = _levenshteinDistance(query, tag);
    final maxLength = math.max(query.length, tag.length);
    return 1.0 - (distance / maxLength);
  }
  
  /// Calculate Levenshtein distance between two strings
  static int _levenshteinDistance(String a, String b) {
    final matrix = List.generate(
      a.length + 1,
      (i) => List.generate(b.length + 1, (j) => 0),
    );
    
    for (int i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    
    for (int j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }
    
    for (int i = 1; i <= a.length; i++) {
      for (int j = 1; j <= b.length; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;
        matrix[i][j] = [
          matrix[i - 1][j] + 1,      // deletion
          matrix[i][j - 1] + 1,      // insertion
          matrix[i - 1][j - 1] + cost // substitution
        ].reduce(math.min);
      }
    }
    
    return matrix[a.length][b.length];
  }
  
  /// Get match type for tag suggestion
  static TagMatchType _getMatchType(String query, String tag) {
    if (query == tag) return TagMatchType.exact;
    if (tag.startsWith(query)) return TagMatchType.prefix;
    if (tag.contains(query)) return TagMatchType.contains;
    return TagMatchType.similar;
  }
  
  /// Calculate match score for tag search
  static double _calculateTagMatchScore(
    List<String> queryTags,
    List<String> garmentTags,
    TagSearchMode mode,
  ) {
    final matchedTags = _getMatchedTags(queryTags, garmentTags);
    
    if (matchedTags.isEmpty) return 0.0;
    
    switch (mode) {
      case TagSearchMode.any:
        // Score based on number of matched tags
        return matchedTags.length / queryTags.length;
        
      case TagSearchMode.all:
        // All tags must match
        return matchedTags.length == queryTags.length ? 1.0 : 0.0;
        
      case TagSearchMode.exact:
        // Exact tag set match
        return queryTags.toSet().difference(garmentTags.toSet()).isEmpty &&
               garmentTags.toSet().difference(queryTags.toSet()).isEmpty ? 1.0 : 0.0;
    }
  }
  
  /// Get matched tags between query and garment
  static List<String> _getMatchedTags(List<String> queryTags, List<String> garmentTags) {
    final matched = <String>[];
    
    for (final queryTag in queryTags) {
      for (final garmentTag in garmentTags) {
        if (queryTag == garmentTag) {
          matched.add(garmentTag);
          break;
        }
      }
    }
    
    return matched;
  }
  
  /// Get common fashion tags that might not exist in wardrobe
  static List<TagSuggestion> _getCommonFashionTags(String query) {
    final commonTags = [
      // Style tags
      'casual', 'formal', 'sporty', 'elegant', 'trendy', 'classic', 'vintage',
      'bohemian', 'minimalist', 'edgy', 'romantic', 'preppy', 'grunge',
      
      // Occasion tags
      'work', 'party', 'date', 'vacation', 'gym', 'beach', 'wedding',
      'interview', 'everyday', 'special', 'outdoor', 'indoor',
      
      // Season tags
      'spring', 'summer', 'autumn', 'winter', 'fall', 'seasonal',
      
      // Fit tags
      'loose', 'tight', 'fitted', 'oversized', 'slim', 'regular',
      'comfortable', 'stretchy', 'breathable',
      
      // Pattern tags
      'solid', 'striped', 'floral', 'geometric', 'abstract', 'polka dot',
      'plaid', 'checkered', 'animal print', 'paisley',
      
      // Material tags
      'cotton', 'wool', 'silk', 'linen', 'polyester', 'denim', 'leather',
      'cashmere', 'velvet', 'chiffon', 'satin',
    ];
    
    final suggestions = <TagSuggestion>[];
    
    for (final tag in commonTags) {
      final similarity = _calculateTagSimilarity(query, tag);
      
      if (similarity > _minSimilarityThreshold) {
        suggestions.add(TagSuggestion(
          tag: tag,
          similarity: similarity,
          frequency: 0,
          popularityScore: 0.0,
          matchType: _getMatchType(query, tag),
          isCommonTag: true,
        ));
      }
    }
    
    return suggestions;
  }
  
  /// Categorize a tag into a category
  static String _categorizeTag(String tag) {
    final lowerTag = tag.toLowerCase();
    
    // Style categories
    if (['casual', 'formal', 'sporty', 'elegant', 'trendy', 'classic', 'vintage',
         'bohemian', 'minimalist', 'edgy', 'romantic', 'preppy', 'grunge'].contains(lowerTag)) {
      return 'Style';
    }
    
    // Color categories
    if (['black', 'white', 'red', 'blue', 'green', 'yellow', 'orange', 'purple',
         'pink', 'brown', 'grey', 'navy', 'burgundy', 'coral', 'mint'].contains(lowerTag)) {
      return 'Color';
    }
    
    // Material categories
    if (['cotton', 'wool', 'silk', 'linen', 'polyester', 'denim', 'leather',
         'cashmere', 'velvet', 'chiffon', 'satin'].contains(lowerTag)) {
      return 'Material';
    }
    
    // Season categories
    if (['spring', 'summer', 'autumn', 'winter', 'fall', 'seasonal'].contains(lowerTag)) {
      return 'Season';
    }
    
    // Occasion categories
    if (['work', 'party', 'date', 'vacation', 'gym', 'beach', 'wedding',
         'interview', 'everyday', 'special', 'outdoor', 'indoor'].contains(lowerTag)) {
      return 'Occasion';
    }
    
    // Fit categories
    if (['loose', 'tight', 'fitted', 'oversized', 'slim', 'regular',
         'comfortable', 'stretchy', 'breathable'].contains(lowerTag)) {
      return 'Fit';
    }
    
    // Pattern categories
    if (['solid', 'striped', 'floral', 'geometric', 'abstract', 'polka dot',
         'plaid', 'checkered', 'animal print', 'paisley'].contains(lowerTag)) {
      return 'Pattern';
    }
    
    return 'Other';
  }
}

/// Tag suggestion with metadata
class TagSuggestion {
  final String tag;
  final double similarity;
  final int frequency;
  final double popularityScore;
  final TagMatchType matchType;
  final bool isCommonTag;
  
  const TagSuggestion({
    required this.tag,
    required this.similarity,
    required this.frequency,
    required this.popularityScore,
    required this.matchType,
    this.isCommonTag = false,
  });
}

/// Tag search result
class TagSearchResult {
  final GarmentModel garment;
  final double matchScore;
  final List<String> matchedTags;
  final int totalTags;
  final List<String> queryTags;
  
  const TagSearchResult({
    required this.garment,
    required this.matchScore,
    required this.matchedTags,
    required this.totalTags,
    required this.queryTags,
  });
}

/// Tag match types
enum TagMatchType {
  exact,
  prefix,
  contains,
  similar,
}

extension TagMatchTypeExtension on TagMatchType {
  int get priority {
    switch (this) {
      case TagMatchType.exact:
        return 1;
      case TagMatchType.prefix:
        return 2;
      case TagMatchType.contains:
        return 3;
      case TagMatchType.similar:
        return 4;
    }
  }
}

/// Tag search modes
enum TagSearchMode {
  any,    // Match any of the tags
  all,    // Match all tags
  exact,  // Exact tag set match
}