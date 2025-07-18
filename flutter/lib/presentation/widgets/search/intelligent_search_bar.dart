import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/services/search/fuzzy_search_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Intelligent search bar with fuzzy matching, suggestions, and auto-completion
class IntelligentSearchBar extends StatefulWidget {
  final String? initialQuery;
  final String hintText;
  final List<GarmentModel> garments;
  final ValueChanged<String> onQueryChanged;
  final ValueChanged<GarmentSearchResult>? onGarmentSelected;
  final VoidCallback? onSearchFocused;
  final VoidCallback? onSearchUnfocused;
  final bool showSuggestions;
  final bool showRecentSearches;
  final List<String> recentSearches;
  final ValueChanged<String>? onRecentSearchSelected;
  
  const IntelligentSearchBar({
    super.key,
    this.initialQuery,
    this.hintText = 'Search garments...',
    required this.garments,
    required this.onQueryChanged,
    this.onGarmentSelected,
    this.onSearchFocused,
    this.onSearchUnfocused,
    this.showSuggestions = true,
    this.showRecentSearches = true,
    this.recentSearches = const [],
    this.onRecentSearchSelected,
  });

  @override
  State<IntelligentSearchBar> createState() => _IntelligentSearchBarState();
}

class _IntelligentSearchBarState extends State<IntelligentSearchBar>
    with SingleTickerProviderStateMixin {
  late final TextEditingController _controller;
  late final FocusNode _focusNode;
  late final AnimationController _animationController;
  late final Animation<double> _fadeAnimation;
  
  String _currentQuery = '';
  List<GarmentSearchResult> _searchResults = [];
  List<String> _suggestions = [];
  bool _isSearching = false;
  bool _showDropdown = false;
  
  @override
  void initState() {
    super.initState();
    _controller = TextEditingController(text: widget.initialQuery);
    _focusNode = FocusNode();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 200),
      vsync: this,
    );
    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
    
    _currentQuery = widget.initialQuery ?? '';
    _focusNode.addListener(_onFocusChanged);
    
    if (_currentQuery.isNotEmpty) {
      _performSearch(_currentQuery);
    }
  }
  
  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    _animationController.dispose();
    super.dispose();
  }
  
  void _onFocusChanged() {
    if (_focusNode.hasFocus) {
      widget.onSearchFocused?.call();
      _showDropdown = true;
      _animationController.forward();
    } else {
      widget.onSearchUnfocused?.call();
      _showDropdown = false;
      _animationController.reverse();
    }
    setState(() {});
  }
  
  void _performSearch(String query) {
    if (query.isEmpty) {
      setState(() {
        _searchResults.clear();
        _suggestions.clear();
        _isSearching = false;
      });
      return;
    }
    
    setState(() {
      _isSearching = true;
    });
    
    // Perform fuzzy search
    final results = FuzzySearchService.searchGarments(
      widget.garments,
      query,
      maxResults: 10,
    );
    
    // Get suggestions for typos
    final suggestions = FuzzySearchService.suggestCorrections(
      query,
      widget.garments,
      maxSuggestions: 3,
    );
    
    setState(() {
      _searchResults = results;
      _suggestions = suggestions;
      _isSearching = false;
    });
    
    widget.onQueryChanged(query);
  }
  
  void _onQueryChanged(String query) {
    _currentQuery = query;
    
    // Debounce search
    Future.delayed(const Duration(milliseconds: 300), () {
      if (_currentQuery == query) {
        _performSearch(query);
      }
    });
  }
  
  void _selectGarment(GarmentSearchResult result) {
    widget.onGarmentSelected?.call(result);
    _focusNode.unfocus();
  }
  
  void _selectSuggestion(String suggestion) {
    _controller.text = suggestion;
    _currentQuery = suggestion;
    _performSearch(suggestion);
  }
  
  void _selectRecentSearch(String query) {
    _controller.text = query;
    _currentQuery = query;
    _performSearch(query);
    widget.onRecentSearchSelected?.call(query);
  }
  
  void _clearSearch() {
    _controller.clear();
    _currentQuery = '';
    _performSearch('');
    HapticFeedback.lightImpact();
  }
  
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Search input
        Container(
          margin: const EdgeInsets.all(AppDimensions.paddingM),
          decoration: BoxDecoration(
            borderRadius: AppDimensions.radiusL,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.1),
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: TextField(
            controller: _controller,
            focusNode: _focusNode,
            onChanged: _onQueryChanged,
            decoration: InputDecoration(
              hintText: widget.hintText,
              hintStyle: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textTertiary,
              ),
              prefixIcon: _isSearching
                  ? const Padding(
                      padding: EdgeInsets.all(12),
                      child: SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                        ),
                      ),
                    )
                  : const Icon(Icons.search),
              suffixIcon: _currentQuery.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: _clearSearch,
                    )
                  : null,
              border: OutlineInputBorder(
                borderRadius: AppDimensions.radiusL,
                borderSide: BorderSide.none,
              ),
              filled: true,
              fillColor: AppColors.surface,
              contentPadding: const EdgeInsets.symmetric(
                horizontal: AppDimensions.paddingM,
                vertical: AppDimensions.paddingM,
              ),
            ),
            style: AppTextStyles.bodyMedium,
            textInputAction: TextInputAction.search,
            onSubmitted: (query) {
              if (query.isNotEmpty) {
                _performSearch(query);
              }
            },
          ),
        ),
        
        // Dropdown with results and suggestions
        if (_showDropdown && _focusNode.hasFocus)
          AppFadeAnimation(
            animation: _fadeAnimation,
            child: Container(
              margin: const EdgeInsets.symmetric(
                horizontal: AppDimensions.paddingM,
              ),
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: AppDimensions.radiusL,
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.1),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Suggestions for typos
                  if (_suggestions.isNotEmpty) ...[
                    _buildSectionHeader('Did you mean?'),
                    ..._suggestions.map((suggestion) => _buildSuggestionItem(suggestion)),
                    const Divider(height: 1),
                  ],
                  
                  // Search results
                  if (_searchResults.isNotEmpty) ...[
                    _buildSectionHeader('Search Results'),
                    ..._searchResults.take(5).map((result) => _buildSearchResultItem(result)),
                    if (_searchResults.length > 5) _buildShowMoreItem(),
                  ],
                  
                  // Recent searches
                  if (_currentQuery.isEmpty && 
                      widget.showRecentSearches && 
                      widget.recentSearches.isNotEmpty) ...[
                    _buildSectionHeader('Recent Searches'),
                    ...widget.recentSearches.take(5).map((query) => _buildRecentSearchItem(query)),
                  ],
                  
                  // Empty state
                  if (_currentQuery.isNotEmpty && 
                      _searchResults.isEmpty && 
                      _suggestions.isEmpty) ...[
                    _buildEmptyState(),
                  ],
                ],
              ),
            ),
          ),
      ],
    );
  }
  
  Widget _buildSectionHeader(String title) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(
        horizontal: AppDimensions.paddingM,
        vertical: AppDimensions.paddingS,
      ),
      child: Text(
        title,
        style: AppTextStyles.labelMedium.copyWith(
          color: AppColors.textSecondary,
        ),
      ),
    );
  }
  
  Widget _buildSuggestionItem(String suggestion) {
    return InkWell(
      onTap: () => _selectSuggestion(suggestion),
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingM,
          vertical: AppDimensions.paddingS,
        ),
        child: Row(
          children: [
            Icon(
              Icons.auto_fix_high,
              size: 16,
              color: AppColors.textSecondary,
            ),
            const SizedBox(width: AppDimensions.paddingS),
            Text(
              suggestion,
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.primary,
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildSearchResultItem(GarmentSearchResult result) {
    return InkWell(
      onTap: () => _selectGarment(result),
      child: Container(
        padding: const EdgeInsets.all(AppDimensions.paddingM),
        child: Row(
          children: [
            // Garment image
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                borderRadius: AppDimensions.radiusS,
                color: AppColors.backgroundSecondary,
              ),
              child: result.garment.images.isNotEmpty
                  ? ClipRRect(
                      borderRadius: AppDimensions.radiusS,
                      child: Image.network(
                        result.garment.images.first.url,
                        fit: BoxFit.cover,
                        width: 40,
                        height: 40,
                        errorBuilder: (context, error, stackTrace) => Icon(
                          Icons.checkroom,
                          size: 20,
                          color: AppColors.textTertiary,
                        ),
                      ),
                    )
                  : Icon(
                      Icons.checkroom,
                      size: 20,
                      color: AppColors.textTertiary,
                    ),
            ),
            const SizedBox(width: AppDimensions.paddingM),
            
            // Garment info
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    result.garment.name,
                    style: AppTextStyles.labelMedium,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Row(
                    children: [
                      if (result.garment.brand != null) ...[
                        Text(
                          result.garment.brand!,
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.textSecondary,
                          ),
                        ),
                        const SizedBox(width: AppDimensions.paddingS),
                      ],
                      Text(
                        result.garment.category,
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                    ],
                  ),
                  if (result.matchedFields.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Row(
                      children: result.matchedFields.take(3).map((field) =>
                        Container(
                          margin: const EdgeInsets.only(right: 4),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 6,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: AppColors.primary.withOpacity(0.1),
                            borderRadius: AppDimensions.radiusXS,
                          ),
                          child: Text(
                            field.field.displayName,
                            style: AppTextStyles.caption.copyWith(
                              color: AppColors.primary,
                              fontSize: 10,
                            ),
                          ),
                        ),
                      ).toList(),
                    ),
                  ],
                ],
              ),
            ),
            
            // Match score
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 8,
                vertical: 4,
              ),
              decoration: BoxDecoration(
                color: _getScoreColor(result.score).withOpacity(0.1),
                borderRadius: AppDimensions.radiusXS,
              ),
              child: Text(
                '${(result.score * 100).round()}%',
                style: AppTextStyles.caption.copyWith(
                  color: _getScoreColor(result.score),
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildRecentSearchItem(String query) {
    return InkWell(
      onTap: () => _selectRecentSearch(query),
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingM,
          vertical: AppDimensions.paddingS,
        ),
        child: Row(
          children: [
            Icon(
              Icons.history,
              size: 16,
              color: AppColors.textSecondary,
            ),
            const SizedBox(width: AppDimensions.paddingS),
            Expanded(
              child: Text(
                query,
                style: AppTextStyles.bodyMedium,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            Icon(
              Icons.north_west,
              size: 16,
              color: AppColors.textTertiary,
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildShowMoreItem() {
    return InkWell(
      onTap: () {
        // TODO: Show all results in overlay or new screen
      },
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingM,
          vertical: AppDimensions.paddingS,
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              'Show ${_searchResults.length - 5} more results',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.primary,
              ),
            ),
            const SizedBox(width: AppDimensions.paddingS),
            Icon(
              Icons.arrow_forward,
              size: 16,
              color: AppColors.primary,
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildEmptyState() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        children: [
          Icon(
            Icons.search_off,
            size: 32,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'No results found',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Try adjusting your search terms',
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textTertiary,
            ),
          ),
        ],
      ),
    );
  }
  
  Color _getScoreColor(double score) {
    if (score >= 0.8) return AppColors.success;
    if (score >= 0.6) return AppColors.warning;
    return AppColors.textSecondary;
  }
}