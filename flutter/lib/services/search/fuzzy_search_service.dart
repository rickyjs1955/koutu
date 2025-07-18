import 'package:flutter/foundation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Fuzzy search service with intelligent matching algorithms
class FuzzySearchService {
  static const double _defaultThreshold = 0.5;
  static const int _maxLevenshteinDistance = 3;
  
  /// Performs fuzzy search on garments with intelligent scoring
  static List<GarmentSearchResult> searchGarments(
    List<GarmentModel> garments,
    String query, {
    double threshold = _defaultThreshold,
    int maxResults = 50,
    List<SearchField> searchFields = const [
      SearchField.name,
      SearchField.brand,
      SearchField.category,
      SearchField.tags,
      SearchField.description,
    ],
  }) {
    if (query.isEmpty) return [];
    
    final results = <GarmentSearchResult>[];
    final normalizedQuery = query.toLowerCase().trim();
    
    for (final garment in garments) {
      final score = _calculateGarmentScore(
        garment,
        normalizedQuery,
        searchFields,
      );
      
      if (score >= threshold) {
        results.add(GarmentSearchResult(
          garment: garment,
          score: score,
          matchedFields: _getMatchedFields(garment, normalizedQuery, searchFields),
        ));
      }
    }
    
    // Sort by score (highest first) and take top results
    results.sort((a, b) => b.score.compareTo(a.score));
    return results.take(maxResults).toList();
  }
  
  /// Calculates comprehensive search score for a garment
  static double _calculateGarmentScore(
    GarmentModel garment,
    String query,
    List<SearchField> searchFields,
  ) {
    double totalScore = 0.0;
    double weightSum = 0.0;
    
    for (final field in searchFields) {
      final fieldWeight = _getFieldWeight(field);
      final fieldValue = _getFieldValue(garment, field);
      final fieldScore = _calculateFieldScore(fieldValue, query);
      
      totalScore += fieldScore * fieldWeight;
      weightSum += fieldWeight;
    }
    
    return weightSum > 0 ? totalScore / weightSum : 0.0;
  }
  
  /// Gets the weight for different search fields
  static double _getFieldWeight(SearchField field) {
    switch (field) {
      case SearchField.name:
        return 1.0; // Highest weight
      case SearchField.brand:
        return 0.8;
      case SearchField.category:
        return 0.7;
      case SearchField.tags:
        return 0.6;
      case SearchField.description:
        return 0.4;
      case SearchField.colors:
        return 0.3;
      case SearchField.size:
        return 0.2;
    }
  }
  
  /// Extracts field value from garment
  static String _getFieldValue(GarmentModel garment, SearchField field) {
    switch (field) {
      case SearchField.name:
        return garment.name;
      case SearchField.brand:
        return garment.brand ?? '';
      case SearchField.category:
        return garment.category;
      case SearchField.tags:
        return garment.tags.join(' ');
      case SearchField.description:
        return garment.description ?? '';
      case SearchField.colors:
        return garment.colors.join(' ');
      case SearchField.size:
        return garment.size ?? '';
    }
  }
  
  /// Calculates field-specific search score
  static double _calculateFieldScore(String fieldValue, String query) {
    if (fieldValue.isEmpty) return 0.0;
    
    final normalizedValue = fieldValue.toLowerCase();
    final words = query.split(' ').where((w) => w.isNotEmpty).toList();
    
    double maxScore = 0.0;
    
    for (final word in words) {
      final wordScore = _calculateWordScore(normalizedValue, word);
      maxScore = maxScore > wordScore ? maxScore : wordScore;
    }
    
    return maxScore;
  }
  
  /// Calculates score for a single word match
  static double _calculateWordScore(String text, String word) {
    // Exact match gets highest score
    if (text.contains(word)) {
      if (text == word) return 1.0;
      if (text.startsWith(word)) return 0.9;
      if (text.endsWith(word)) return 0.8;
      return 0.7;
    }
    
    // Fuzzy matching using Levenshtein distance
    final words = text.split(' ');
    double maxFuzzyScore = 0.0;
    
    for (final textWord in words) {
      final distance = _levenshteinDistance(textWord, word);
      if (distance <= _maxLevenshteinDistance) {
        final similarity = 1.0 - (distance / word.length.clamp(1, double.infinity));
        maxFuzzyScore = maxFuzzyScore > similarity ? maxFuzzyScore : similarity;
      }
    }
    
    return maxFuzzyScore;
  }
  
  /// Calculates Levenshtein distance between two strings
  static int _levenshteinDistance(String s1, String s2) {
    if (s1.isEmpty) return s2.length;
    if (s2.isEmpty) return s1.length;
    
    final matrix = List.generate(
      s1.length + 1,
      (i) => List.generate(s2.length + 1, (j) => 0),
    );
    
    for (int i = 0; i <= s1.length; i++) {
      matrix[i][0] = i;
    }
    
    for (int j = 0; j <= s2.length; j++) {
      matrix[0][j] = j;
    }
    
    for (int i = 1; i <= s1.length; i++) {
      for (int j = 1; j <= s2.length; j++) {
        final cost = s1[i - 1] == s2[j - 1] ? 0 : 1;
        matrix[i][j] = [
          matrix[i - 1][j] + 1,      // deletion
          matrix[i][j - 1] + 1,      // insertion
          matrix[i - 1][j - 1] + cost // substitution
        ].reduce((a, b) => a < b ? a : b);
      }
    }
    
    return matrix[s1.length][s2.length];
  }
  
  /// Gets matched fields for a garment
  static List<MatchedField> _getMatchedFields(
    GarmentModel garment,
    String query,
    List<SearchField> searchFields,
  ) {
    final matchedFields = <MatchedField>[];
    
    for (final field in searchFields) {
      final fieldValue = _getFieldValue(garment, field);
      final score = _calculateFieldScore(fieldValue, query);
      
      if (score > 0.3) {
        matchedFields.add(MatchedField(
          field: field,
          value: fieldValue,
          score: score,
        ));
      }
    }
    
    matchedFields.sort((a, b) => b.score.compareTo(a.score));
    return matchedFields;
  }
  
  /// Suggests search corrections for typos
  static List<String> suggestCorrections(
    String query,
    List<GarmentModel> garments, {
    int maxSuggestions = 5,
  }) {
    final suggestions = <String>{};
    final normalizedQuery = query.toLowerCase().trim();
    
    // Extract all searchable text from garments
    final searchableTexts = <String>{};
    for (final garment in garments) {
      searchableTexts.addAll([
        garment.name,
        if (garment.brand != null) garment.brand!,
        garment.category,
        ...garment.tags,
        if (garment.description != null) garment.description!,
      ]);
    }
    
    // Find similar words
    for (final text in searchableTexts) {
      final words = text.toLowerCase().split(' ');
      for (final word in words) {
        if (word.length >= 3) {
          final distance = _levenshteinDistance(normalizedQuery, word);
          if (distance <= 2 && distance > 0) {
            suggestions.add(word);
          }
        }
      }
    }
    
    return suggestions.take(maxSuggestions).toList();
  }
}

/// Search result with score and matched fields
class GarmentSearchResult {
  final GarmentModel garment;
  final double score;
  final List<MatchedField> matchedFields;
  
  const GarmentSearchResult({
    required this.garment,
    required this.score,
    required this.matchedFields,
  });
  
  @override
  String toString() => 'GarmentSearchResult(score: $score, garment: ${garment.name})';
}

/// Matched field information
class MatchedField {
  final SearchField field;
  final String value;
  final double score;
  
  const MatchedField({
    required this.field,
    required this.value,
    required this.score,
  });
  
  @override
  String toString() => 'MatchedField(field: $field, score: $score)';
}

/// Available search fields
enum SearchField {
  name,
  brand,
  category,
  tags,
  description,
  colors,
  size,
}

extension SearchFieldExtension on SearchField {
  String get displayName {
    switch (this) {
      case SearchField.name:
        return 'Name';
      case SearchField.brand:
        return 'Brand';
      case SearchField.category:
        return 'Category';
      case SearchField.tags:
        return 'Tags';
      case SearchField.description:
        return 'Description';
      case SearchField.colors:
        return 'Colors';
      case SearchField.size:
        return 'Size';
    }
  }
  
  String get icon {
    switch (this) {
      case SearchField.name:
        return '🏷️';
      case SearchField.brand:
        return '🏢';
      case SearchField.category:
        return '📂';
      case SearchField.tags:
        return '🏷️';
      case SearchField.description:
        return '📝';
      case SearchField.colors:
        return '🎨';
      case SearchField.size:
        return '📏';
    }
  }
}