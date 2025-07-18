import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/services/search/tag_search_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Widget for tag-based search with auto-completion
class TagSearchWidget extends StatefulWidget {
  final List<GarmentModel> garments;
  final Function(List<TagSearchResult>) onSearchResults;
  final Function(List<String>) onTagsChanged;
  final List<String> initialTags;
  final String hintText;
  final bool showCategories;
  
  const TagSearchWidget({
    super.key,
    required this.garments,
    required this.onSearchResults,
    required this.onTagsChanged,
    this.initialTags = const [],
    this.hintText = 'Search by tags...',
    this.showCategories = true,
  });

  @override
  State<TagSearchWidget> createState() => _TagSearchWidgetState();
}

class _TagSearchWidgetState extends State<TagSearchWidget> {
  final TextEditingController _controller = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  final LayerLink _layerLink = LayerLink();
  
  List<String> _selectedTags = [];
  List<TagSuggestion> _suggestions = [];
  Map<String, List<String>> _tagCategories = {};
  String _currentQuery = '';
  bool _showSuggestions = false;
  TagSearchMode _searchMode = TagSearchMode.any;
  OverlayEntry? _overlayEntry;
  
  @override
  void initState() {
    super.initState();
    _selectedTags = List.from(widget.initialTags);
    _loadTagCategories();
    _focusNode.addListener(_onFocusChanged);
  }
  
  @override
  void dispose() {
    _removeOverlay();
    _controller.dispose();
    _focusNode.dispose();
    super.dispose();
  }
  
  void _loadTagCategories() {
    _tagCategories = TagSearchService.getTagCategories(widget.garments);
  }
  
  void _onFocusChanged() {
    if (_focusNode.hasFocus) {
      _showSuggestionOverlay();
    } else {
      _removeOverlay();
    }
  }
  
  void _onQueryChanged(String query) {
    setState(() {
      _currentQuery = query;
    });
    
    if (query.isNotEmpty) {
      final suggestions = TagSearchService.getTagSuggestions(
        query,
        widget.garments,
        maxSuggestions: 15,
      );
      
      setState(() {
        _suggestions = suggestions;
        _showSuggestions = true;
      });
      
      _updateOverlay();
    } else {
      setState(() {
        _suggestions = [];
        _showSuggestions = false;
      });
      _removeOverlay();
    }
  }
  
  void _addTag(String tag) {
    if (!_selectedTags.contains(tag)) {
      setState(() {
        _selectedTags.add(tag);
        _controller.clear();
        _currentQuery = '';
        _suggestions = [];
        _showSuggestions = false;
      });
      
      _removeOverlay();
      _performSearch();
      widget.onTagsChanged(_selectedTags);
      
      // Save to search history
      TagSearchService.saveTagSearch(_selectedTags);
    }
  }
  
  void _removeTag(String tag) {
    setState(() {
      _selectedTags.remove(tag);
    });
    
    _performSearch();
    widget.onTagsChanged(_selectedTags);
  }
  
  void _clearTags() {
    setState(() {
      _selectedTags.clear();
    });
    
    _performSearch();
    widget.onTagsChanged(_selectedTags);
  }
  
  void _performSearch() {
    if (_selectedTags.isEmpty) {
      widget.onSearchResults([]);
      return;
    }
    
    final results = TagSearchService.searchGarmentsByTags(
      _selectedTags,
      widget.garments,
      mode: _searchMode,
    );
    
    widget.onSearchResults(results);
  }
  
  void _showSuggestionOverlay() {
    if (_overlayEntry != null) return;
    
    _overlayEntry = OverlayEntry(
      builder: (context) => Positioned(
        width: MediaQuery.of(context).size.width - (AppDimensions.paddingM * 2),
        child: CompositedTransformFollower(
          link: _layerLink,
          showWhenUnlinked: false,
          offset: const Offset(0, 60),
          child: Material(
            elevation: 4,
            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            child: _buildSuggestionsList(),
          ),
        ),
      ),
    );
    
    Overlay.of(context).insert(_overlayEntry!);
  }
  
  void _updateOverlay() {
    _overlayEntry?.markNeedsBuild();
  }
  
  void _removeOverlay() {
    _overlayEntry?.remove();
    _overlayEntry = null;
  }
  
  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Search input and controls
        CompositedTransformTarget(
          link: _layerLink,
          child: Container(
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
              border: Border.all(
                color: _focusNode.hasFocus ? AppColors.primary : AppColors.border,
                width: 1,
              ),
            ),
            child: Column(
              children: [
                // Selected tags
                if (_selectedTags.isNotEmpty)
                  Container(
                    padding: const EdgeInsets.all(AppDimensions.paddingS),
                    child: Wrap(
                      spacing: AppDimensions.paddingS,
                      runSpacing: AppDimensions.paddingS,
                      children: _selectedTags.map((tag) => _TagChip(
                        tag: tag,
                        onRemove: () => _removeTag(tag),
                      )).toList(),
                    ),
                  ),
                
                // Search input
                TextField(
                  controller: _controller,
                  focusNode: _focusNode,
                  onChanged: _onQueryChanged,
                  onSubmitted: (value) {
                    if (value.isNotEmpty) {
                      _addTag(value);
                    }
                  },
                  decoration: InputDecoration(
                    hintText: widget.hintText,
                    prefixIcon: const Icon(Icons.local_offer),
                    suffixIcon: _selectedTags.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.clear),
                            onPressed: _clearTags,
                          )
                        : null,
                    border: InputBorder.none,
                    contentPadding: const EdgeInsets.all(AppDimensions.paddingM),
                  ),
                ),
              ],
            ),
          ),
        ),
        
        // Search mode selector
        const SizedBox(height: AppDimensions.paddingS),
        Row(
          children: [
            Text(
              'Search mode:',
              style: AppTextStyles.caption.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
            const SizedBox(width: AppDimensions.paddingS),
            ...TagSearchMode.values.map((mode) => Padding(
              padding: const EdgeInsets.only(right: AppDimensions.paddingS),
              child: FilterChip(
                label: Text(_getSearchModeLabel(mode)),
                selected: _searchMode == mode,
                onSelected: (selected) {
                  if (selected) {
                    setState(() {
                      _searchMode = mode;
                    });
                    _performSearch();
                  }
                },
              ),
            )).toList(),
          ],
        ),
        
        // Tag categories (when not searching)
        if (widget.showCategories && _currentQuery.isEmpty && _selectedTags.isEmpty)
          _buildTagCategories(),
      ],
    );
  }
  
  Widget _buildSuggestionsList() {
    if (_suggestions.isEmpty) {
      return Container(
        padding: const EdgeInsets.all(AppDimensions.paddingM),
        child: Text(
          'No tag suggestions found',
          style: AppTextStyles.bodyMedium.copyWith(
            color: AppColors.textSecondary,
          ),
        ),
      );
    }
    
    return Container(
      constraints: const BoxConstraints(maxHeight: 300),
      child: ListView.builder(
        shrinkWrap: true,
        itemCount: _suggestions.length,
        itemBuilder: (context, index) {
          final suggestion = _suggestions[index];
          
          return ListTile(
            leading: Icon(
              _getTagIcon(suggestion.tag),
              size: 20,
              color: _getTagColor(suggestion.matchType),
            ),
            title: RichText(
              text: TextSpan(
                style: AppTextStyles.bodyMedium,
                children: _buildHighlightedText(suggestion.tag, _currentQuery),
              ),
            ),
            subtitle: suggestion.frequency > 0
                ? Text(
                    '${suggestion.frequency} items',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  )
                : suggestion.isCommonTag
                    ? Text(
                        'Common tag',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      )
                    : null,
            trailing: Icon(
              _getMatchTypeIcon(suggestion.matchType),
              size: 16,
              color: _getTagColor(suggestion.matchType),
            ),
            onTap: () => _addTag(suggestion.tag),
          );
        },
      ),
    );
  }
  
  Widget _buildTagCategories() {
    if (_tagCategories.isEmpty) return const SizedBox.shrink();
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: AppDimensions.paddingM),
        Text(
          'Browse by category:',
          style: AppTextStyles.labelMedium,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        ..._tagCategories.entries.map((entry) => _buildTagCategory(
          entry.key,
          entry.value,
        )).toList(),
      ],
    );
  }
  
  Widget _buildTagCategory(String category, List<String> tags) {
    return ExpansionTile(
      title: Text(
        category,
        style: AppTextStyles.labelMedium,
      ),
      children: [
        Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingS),
          child: Wrap(
            spacing: AppDimensions.paddingS,
            runSpacing: AppDimensions.paddingS,
            children: tags.map((tag) => ActionChip(
              label: Text(tag),
              onPressed: () => _addTag(tag),
            )).toList(),
          ),
        ),
      ],
    );
  }
  
  List<TextSpan> _buildHighlightedText(String text, String query) {
    if (query.isEmpty) {
      return [TextSpan(text: text, style: AppTextStyles.bodyMedium)];
    }
    
    final lowerText = text.toLowerCase();
    final lowerQuery = query.toLowerCase();
    final index = lowerText.indexOf(lowerQuery);
    
    if (index == -1) {
      return [TextSpan(text: text, style: AppTextStyles.bodyMedium)];
    }
    
    return [
      if (index > 0)
        TextSpan(text: text.substring(0, index), style: AppTextStyles.bodyMedium),
      TextSpan(
        text: text.substring(index, index + query.length),
        style: AppTextStyles.bodyMedium.copyWith(
          color: AppColors.primary,
          fontWeight: FontWeight.bold,
        ),
      ),
      if (index + query.length < text.length)
        TextSpan(
          text: text.substring(index + query.length),
          style: AppTextStyles.bodyMedium,
        ),
    ];
  }
  
  String _getSearchModeLabel(TagSearchMode mode) {
    switch (mode) {
      case TagSearchMode.any:
        return 'Any';
      case TagSearchMode.all:
        return 'All';
      case TagSearchMode.exact:
        return 'Exact';
    }
  }
  
  IconData _getTagIcon(String tag) {
    final category = TagSearchService.getTagCategories([]).keys.firstWhere(
      (cat) => TagSearchService.getTagCategories([]).containsKey(cat),
      orElse: () => 'Other',
    );
    
    switch (category) {
      case 'Style':
        return Icons.style;
      case 'Color':
        return Icons.palette;
      case 'Material':
        return Icons.texture;
      case 'Season':
        return Icons.wb_sunny;
      case 'Occasion':
        return Icons.event;
      case 'Fit':
        return Icons.straighten;
      case 'Pattern':
        return Icons.pattern;
      default:
        return Icons.local_offer;
    }
  }
  
  Color _getTagColor(TagMatchType matchType) {
    switch (matchType) {
      case TagMatchType.exact:
        return AppColors.success;
      case TagMatchType.prefix:
        return AppColors.primary;
      case TagMatchType.contains:
        return AppColors.warning;
      case TagMatchType.similar:
        return AppColors.textSecondary;
    }
  }
  
  IconData _getMatchTypeIcon(TagMatchType matchType) {
    switch (matchType) {
      case TagMatchType.exact:
        return Icons.check_circle;
      case TagMatchType.prefix:
        return Icons.start;
      case TagMatchType.contains:
        return Icons.search;
      case TagMatchType.similar:
        return Icons.similarity;
    }
  }
}

class _TagChip extends StatelessWidget {
  final String tag;
  final VoidCallback onRemove;
  
  const _TagChip({
    required this.tag,
    required this.onRemove,
  });
  
  @override
  Widget build(BuildContext context) {
    return Chip(
      label: Text(
        tag,
        style: AppTextStyles.caption.copyWith(
          color: AppColors.primary,
        ),
      ),
      deleteIcon: const Icon(Icons.close, size: 18),
      onDeleted: onRemove,
      backgroundColor: AppColors.primary.withOpacity(0.1),
      side: BorderSide(
        color: AppColors.primary.withOpacity(0.3),
        width: 1,
      ),
    );
  }
}