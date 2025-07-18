import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/services/color/color_palette_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Advanced color filter widget with palette recognition
class ColorFilterWidget extends StatefulWidget {
  final List<GarmentModel> garments;
  final List<String> selectedColors;
  final ValueChanged<List<String>> onColorsChanged;
  final bool showSeasonalPalettes;
  final bool showMatchingColors;
  
  const ColorFilterWidget({
    super.key,
    required this.garments,
    required this.selectedColors,
    required this.onColorsChanged,
    this.showSeasonalPalettes = true,
    this.showMatchingColors = true,
  });

  @override
  State<ColorFilterWidget> createState() => _ColorFilterWidgetState();
}

class _ColorFilterWidgetState extends State<ColorFilterWidget>
    with SingleTickerProviderStateMixin {
  late final TabController _tabController;
  final TextEditingController _searchController = TextEditingController();
  
  List<String> _availableColors = [];
  List<ColorInfo> _searchResults = [];
  List<ColorInfo> _matchingColors = [];
  String _searchQuery = '';
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _loadAvailableColors();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }
  
  void _loadAvailableColors() {
    final allColors = <String>{};
    
    // Extract colors from garments
    for (final garment in widget.garments) {
      allColors.addAll(garment.colors);
    }
    
    setState(() {
      _availableColors = allColors.toList()..sort();
    });
    
    // Load matching colors if we have selected colors
    if (widget.selectedColors.isNotEmpty) {
      _loadMatchingColors();
    }
  }
  
  void _loadMatchingColors() {
    if (widget.selectedColors.isEmpty) return;
    
    final matchingColors = <ColorInfo>{};
    
    for (final colorName in widget.selectedColors) {
      final color = ColorPaletteService.getColorFromName(colorName);
      if (color != null) {
        final matches = ColorPaletteService.findMatchingColors(
          color,
          maxResults: 8,
          maxDistance: 80,
        );
        matchingColors.addAll(matches);
      }
    }
    
    setState(() {
      _matchingColors = matchingColors.toList()
        ..sort((a, b) => b.percentage.compareTo(a.percentage));
    });
  }
  
  void _searchColors(String query) {
    if (query.isEmpty) {
      setState(() {
        _searchResults = [];
        _searchQuery = '';
      });
      return;
    }
    
    final results = ColorPaletteService.searchColorsByName(query);
    setState(() {
      _searchResults = results;
      _searchQuery = query;
    });
  }
  
  void _toggleColor(String colorName) {
    final newSelectedColors = List<String>.from(widget.selectedColors);
    
    if (newSelectedColors.contains(colorName)) {
      newSelectedColors.remove(colorName);
    } else {
      newSelectedColors.add(colorName);
    }
    
    widget.onColorsChanged(newSelectedColors);
    _loadMatchingColors();
  }
  
  void _clearAllColors() {
    widget.onColorsChanged([]);
    setState(() {
      _matchingColors = [];
    });
  }
  
  @override
  Widget build(BuildContext context) {
    return Container(
      height: MediaQuery.of(context).size.height * 0.7,
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: const BorderRadius.vertical(
          top: Radius.circular(AppDimensions.radiusL),
        ),
      ),
      child: Column(
        children: [
          // Handle
          Container(
            width: 40,
            height: 4,
            margin: const EdgeInsets.symmetric(vertical: AppDimensions.paddingS),
            decoration: BoxDecoration(
              color: AppColors.border,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          
          // Header
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingL),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Color Filter',
                        style: AppTextStyles.h3,
                      ),
                      if (widget.selectedColors.isNotEmpty) ...[
                        const SizedBox(height: 4),
                        Text(
                          '${widget.selectedColors.length} color${widget.selectedColors.length == 1 ? '' : 's'} selected',
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.textSecondary,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                if (widget.selectedColors.isNotEmpty)
                  TextButton(
                    onPressed: _clearAllColors,
                    child: const Text('Clear All'),
                  ),
              ],
            ),
          ),
          
          // Search bar
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingL),
            child: TextField(
              controller: _searchController,
              onChanged: _searchColors,
              decoration: InputDecoration(
                hintText: 'Search colors...',
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchQuery.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchController.clear();
                          _searchColors('');
                        },
                      )
                    : null,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                  borderSide: BorderSide.none,
                ),
                filled: true,
                fillColor: AppColors.backgroundSecondary,
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: AppDimensions.paddingM,
                  vertical: AppDimensions.paddingS,
                ),
              ),
            ),
          ),
          
          const SizedBox(height: AppDimensions.paddingM),
          
          // Tabs
          TabBar(
            controller: _tabController,
            isScrollable: true,
            labelStyle: AppTextStyles.labelMedium,
            unselectedLabelStyle: AppTextStyles.labelMedium,
            labelColor: AppColors.primary,
            unselectedLabelColor: AppColors.textSecondary,
            indicatorColor: AppColors.primary,
            tabs: const [
              Tab(text: 'All Colors'),
              Tab(text: 'Seasonal'),
              Tab(text: 'Matching'),
              Tab(text: 'Available'),
            ],
          ),
          
          // Content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildAllColorsTab(),
                _buildSeasonalTab(),
                _buildMatchingTab(),
                _buildAvailableTab(),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildAllColorsTab() {
    final colors = _searchQuery.isNotEmpty
        ? _searchResults
        : ColorPaletteService.getAllColorNames()
            .map((name) => ColorInfo(
                  color: ColorPaletteService.getColorFromName(name) ?? Colors.grey,
                  name: name,
                  percentage: 1.0,
                ))
            .toList();
    
    return _buildColorGrid(colors);
  }
  
  Widget _buildSeasonalTab() {
    return DefaultTabController(
      length: 4,
      child: Column(
        children: [
          TabBar(
            isScrollable: true,
            labelStyle: AppTextStyles.caption,
            unselectedLabelStyle: AppTextStyles.caption,
            labelColor: AppColors.primary,
            unselectedLabelColor: AppColors.textSecondary,
            indicatorColor: AppColors.primary,
            tabs: Season.values.map((season) => Tab(
              text: '${season.emoji} ${season.displayName}',
            )).toList(),
          ),
          Expanded(
            child: TabBarView(
              children: Season.values.map((season) {
                final colors = ColorPaletteService.getSeasonalPalette(season)
                    .map((color) => ColorInfo(
                          color: color,
                          name: ColorPaletteService.getColorName(color),
                          percentage: 1.0,
                        ))
                    .toList();
                
                return _buildColorGrid(colors);
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildMatchingTab() {
    if (widget.selectedColors.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.palette_outlined,
              size: 48,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Text(
              'Select colors to see matches',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      );
    }
    
    return _buildColorGrid(_matchingColors);
  }
  
  Widget _buildAvailableTab() {
    final colors = _availableColors
        .map((name) => ColorInfo(
              color: ColorPaletteService.getColorFromName(name) ?? Colors.grey,
              name: name,
              percentage: 1.0,
            ))
        .toList();
    
    if (colors.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.color_lens_outlined,
              size: 48,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Text(
              'No colors available',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      );
    }
    
    return _buildColorGrid(colors);
  }
  
  Widget _buildColorGrid(List<ColorInfo> colors) {
    return GridView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 5,
        crossAxisSpacing: AppDimensions.paddingS,
        mainAxisSpacing: AppDimensions.paddingS,
        childAspectRatio: 0.8,
      ),
      itemCount: colors.length,
      itemBuilder: (context, index) {
        final colorInfo = colors[index];
        final isSelected = widget.selectedColors.contains(colorInfo.name);
        
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: _ColorItem(
            colorInfo: colorInfo,
            isSelected: isSelected,
            onTap: () => _toggleColor(colorInfo.name),
          ),
        );
      },
    );
  }
}

class _ColorItem extends StatelessWidget {
  final ColorInfo colorInfo;
  final bool isSelected;
  final VoidCallback onTap;
  
  const _ColorItem({
    required this.colorInfo,
    required this.isSelected,
    required this.onTap,
  });
  
  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(AppDimensions.radiusM),
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(AppDimensions.radiusM),
          border: Border.all(
            color: isSelected ? AppColors.primary : AppColors.border,
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Column(
          children: [
            // Color circle
            Expanded(
              flex: 3,
              child: Container(
                margin: const EdgeInsets.all(AppDimensions.paddingS),
                decoration: BoxDecoration(
                  color: colorInfo.color,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: AppColors.border.withOpacity(0.3),
                    width: 0.5,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 4,
                      offset: const Offset(0, 2),
                    ),
                  ],
                ),
                child: isSelected
                    ? Center(
                        child: Icon(
                          Icons.check,
                          color: _getContrastColor(colorInfo.color),
                          size: 16,
                        ),
                      )
                    : null,
              ),
            ),
            
            // Color name
            Expanded(
              flex: 2,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppDimensions.paddingXS,
                  vertical: AppDimensions.paddingXS,
                ),
                child: Text(
                  colorInfo.name.replaceAll('_', ' ').toUpperCase(),
                  style: AppTextStyles.caption.copyWith(
                    color: isSelected ? AppColors.primary : AppColors.textSecondary,
                    fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                  ),
                  textAlign: TextAlign.center,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  Color _getContrastColor(Color color) {
    // Calculate relative luminance
    final luminance = color.computeLuminance();
    
    // Return black or white based on luminance
    return luminance > 0.5 ? Colors.black : Colors.white;
  }
}