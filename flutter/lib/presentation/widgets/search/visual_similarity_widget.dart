import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/services/search/visual_similarity_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Widget for displaying visual similarity search results
class VisualSimilarityWidget extends StatefulWidget {
  final GarmentModel targetGarment;
  final List<GarmentModel> allGarments;
  final Function(GarmentModel) onGarmentTap;
  final Function(List<GarmentModel>) onCompareGarments;
  
  const VisualSimilarityWidget({
    super.key,
    required this.targetGarment,
    required this.allGarments,
    required this.onGarmentTap,
    required this.onCompareGarments,
  });

  @override
  State<VisualSimilarityWidget> createState() => _VisualSimilarityWidgetState();
}

class _VisualSimilarityWidgetState extends State<VisualSimilarityWidget>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  
  List<VisualSimilarityResult> _allSimilarResults = [];
  List<VisualSimilarityResult> _colorSimilarResults = [];
  List<VisualSimilarityResult> _patternSimilarResults = [];
  Map<String, List<GarmentModel>> _similarityGroups = {};
  
  bool _isLoading = true;
  double _similarityThreshold = 0.3;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _findSimilarGarments();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }
  
  void _findSimilarGarments() async {
    setState(() => _isLoading = true);
    
    try {
      // Find overall similar garments
      _allSimilarResults = VisualSimilarityService.findSimilarGarments(
        widget.targetGarment,
        widget.allGarments,
        maxResults: 20,
        minSimilarity: _similarityThreshold,
      );
      
      // Find color similar garments
      _colorSimilarResults = VisualSimilarityService.findSimilarColors(
        widget.targetGarment.colors,
        widget.allGarments,
        maxResults: 15,
        colorThreshold: 0.4,
      );
      
      // Find pattern similar garments
      final patternTags = widget.targetGarment.tags
          .where((tag) => _isPatternTag(tag))
          .toList();
      
      _patternSimilarResults = [];
      for (final pattern in patternTags) {
        final results = VisualSimilarityService.findSimilarPatterns(
          pattern,
          widget.allGarments,
          maxResults: 10,
        );
        _patternSimilarResults.addAll(results);
      }
      
      // Remove duplicates and sort
      _patternSimilarResults = _patternSimilarResults.toSet().toList();
      _patternSimilarResults.sort((a, b) => b.similarityScore.compareTo(a.similarityScore));
      
      // Group by similarity
      _similarityGroups = VisualSimilarityService.groupBySimilarity(
        widget.allGarments,
        similarityThreshold: 0.6,
      );
      
    } catch (e) {
      debugPrint('Error finding similar garments: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  bool _isPatternTag(String tag) {
    final patternTags = [
      'solid', 'striped', 'floral', 'geometric', 'abstract', 'polka dot',
      'plaid', 'checkered', 'animal print', 'paisley', 'tribal', 'tropical',
      'chevron', 'herringbone', 'houndstooth', 'argyle', 'camouflage'
    ];
    return patternTags.contains(tag.toLowerCase());
  }
  
  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Center(
        child: AppLoadingIndicator(),
      );
    }
    
    return Column(
      children: [
        // Target garment header
        _buildTargetGarmentHeader(),
        
        // Similarity threshold slider
        _buildSimilarityControls(),
        
        // Tab bar
        Container(
          decoration: BoxDecoration(
            color: AppColors.surface,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.05),
                blurRadius: 4,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: TabBar(
            controller: _tabController,
            isScrollable: true,
            labelColor: AppColors.primary,
            unselectedLabelColor: AppColors.textSecondary,
            indicatorColor: AppColors.primary,
            tabs: [
              Tab(
                icon: const Icon(Icons.auto_awesome, size: 20),
                text: 'All Similar (${_allSimilarResults.length})',
              ),
              Tab(
                icon: const Icon(Icons.palette, size: 20),
                text: 'Colors (${_colorSimilarResults.length})',
              ),
              Tab(
                icon: const Icon(Icons.pattern, size: 20),
                text: 'Patterns (${_patternSimilarResults.length})',
              ),
              Tab(
                icon: const Icon(Icons.group_work, size: 20),
                text: 'Groups (${_similarityGroups.length})',
              ),
            ],
          ),
        ),
        
        // Content
        Expanded(
          child: TabBarView(
            controller: _tabController,
            children: [
              _buildSimilarityList(_allSimilarResults),
              _buildSimilarityList(_colorSimilarResults),
              _buildSimilarityList(_patternSimilarResults),
              _buildSimilarityGroups(),
            ],
          ),
        ),
      ],
    );
  }
  
  Widget _buildTargetGarmentHeader() {
    return Container(
      margin: const EdgeInsets.all(AppDimensions.paddingM),
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            AppColors.primary.withOpacity(0.1),
            AppColors.primary.withOpacity(0.05),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(AppDimensions.radiusL),
        border: Border.all(
          color: AppColors.primary.withOpacity(0.2),
          width: 1,
        ),
      ),
      child: Row(
        children: [
          // Target garment image
          ClipRRect(
            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            child: SizedBox(
              width: 80,
              height: 80,
              child: widget.targetGarment.images.isNotEmpty
                  ? CachedNetworkImage(
                      imageUrl: widget.targetGarment.images.first.url,
                      fit: BoxFit.cover,
                      placeholder: (context, url) => Container(
                        color: AppColors.backgroundSecondary,
                        child: const Center(
                          child: AppLoadingIndicator(
                            size: LoadingIndicatorSize.small,
                          ),
                        ),
                      ),
                    )
                  : Container(
                      color: AppColors.backgroundSecondary,
                      child: Icon(
                        Icons.checkroom,
                        color: AppColors.textTertiary,
                        size: 32,
                      ),
                    ),
            ),
          ),
          
          const SizedBox(width: AppDimensions.paddingM),
          
          // Target garment info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      Icons.search,
                      size: 20,
                      color: AppColors.primary,
                    ),
                    const SizedBox(width: AppDimensions.paddingS),
                    Text(
                      'Finding Similar Items',
                      style: AppTextStyles.labelMedium.copyWith(
                        color: AppColors.primary,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  widget.targetGarment.name,
                  style: AppTextStyles.h3,
                ),
                const SizedBox(height: 4),
                Text(
                  widget.targetGarment.category,
                  style: AppTextStyles.caption.copyWith(
                    color: AppColors.textSecondary,
                  ),
                ),
                if (widget.targetGarment.colors.isNotEmpty) ...[\n                  const SizedBox(height: 8),\n                  Wrap(\n                    spacing: 4,\n                    children: widget.targetGarment.colors.take(5).map((color) => Container(\n                      width: 16,\n                      height: 16,\n                      decoration: BoxDecoration(\n                        shape: BoxShape.circle,\n                        color: _getColorFromName(color),\n                        border: Border.all(\n                          color: AppColors.border,\n                          width: 1,\n                        ),\n                      ),\n                    )).toList(),\n                  ),\n                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildSimilarityControls() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
      child: Row(
        children: [
          Text(
            'Similarity:',
            style: AppTextStyles.labelMedium,
          ),
          Expanded(
            child: Slider(
              value: _similarityThreshold,
              min: 0.1,
              max: 0.9,
              divisions: 8,
              label: '${(_similarityThreshold * 100).round()}%',
              onChanged: (value) {
                setState(() {
                  _similarityThreshold = value;
                });
              },
              onChangeEnd: (value) {
                _findSimilarGarments();
              },
            ),
          ),
          Text(
            '${(_similarityThreshold * 100).round()}%',
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildSimilarityList(List<VisualSimilarityResult> results) {
    if (results.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.search_off,
              size: 64,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Text(
              'No Similar Items Found',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              'Try adjusting the similarity threshold',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
            ),
          ],
        ),
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: results.length,
      itemBuilder: (context, index) {
        final result = results[index];
        
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _SimilarityResultCard(
            result: result,
            onTap: () => widget.onGarmentTap(result.garment),
            onCompare: () => widget.onCompareGarments([
              widget.targetGarment,
              result.garment,
            ]),
          ),
        );
      },
    );
  }
  
  Widget _buildSimilarityGroups() {
    if (_similarityGroups.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.group_work_outlined,
              size: 64,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Text(
              'No Similar Groups Found',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              'Add more garments to see visual similarity groups',
              style: AppTextStyles.bodyMedium.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: _similarityGroups.length,
      itemBuilder: (context, index) {
        final entry = _similarityGroups.entries.elementAt(index);
        final groupName = entry.key;
        final garments = entry.value;
        
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _SimilarityGroupCard(
            groupName: groupName,
            garments: garments,
            onGarmentTap: widget.onGarmentTap,
          ),
        );
      },
    );
  }
  
  Color _getColorFromName(String colorName) {
    final colors = {
      'black': Colors.black,
      'white': Colors.white,
      'grey': Colors.grey,
      'red': Colors.red,
      'blue': Colors.blue,
      'green': Colors.green,
      'yellow': Colors.yellow,
      'orange': Colors.orange,
      'purple': Colors.purple,
      'pink': Colors.pink,
      'brown': Colors.brown,
    };
    return colors[colorName.toLowerCase()] ?? Colors.grey;
  }
}

class _SimilarityResultCard extends StatelessWidget {
  final VisualSimilarityResult result;
  final VoidCallback onTap;
  final VoidCallback onCompare;
  
  const _SimilarityResultCard({
    required this.result,
    required this.onTap,
    required this.onCompare,
  });
  
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          child: Row(
            children: [
              // Garment image
              ClipRRect(
                borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                child: SizedBox(
                  width: 80,
                  height: 80,
                  child: result.garment.images.isNotEmpty
                      ? CachedNetworkImage(
                          imageUrl: result.garment.images.first.url,
                          fit: BoxFit.cover,
                          placeholder: (context, url) => Container(
                            color: AppColors.backgroundSecondary,
                            child: const Center(
                              child: AppLoadingIndicator(
                                size: LoadingIndicatorSize.small,
                              ),
                            ),
                          ),
                        )
                      : Container(
                          color: AppColors.backgroundSecondary,
                          child: Icon(
                            Icons.checkroom,
                            color: AppColors.textTertiary,
                            size: 32,
                          ),
                        ),
                ),
              ),
              
              const SizedBox(width: AppDimensions.paddingM),
              
              // Garment info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            result.garment.name,
                            style: AppTextStyles.labelLarge,
                          ),
                        ),
                        // Similarity score
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: AppDimensions.paddingS,
                            vertical: AppDimensions.paddingXS,
                          ),
                          decoration: BoxDecoration(
                            color: _getScoreColor(result.similarityScore),
                            borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                          ),
                          child: Text(
                            '${(result.similarityScore * 100).toInt()}%',
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      result.garment.category,
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                    const SizedBox(height: 8),
                    // Similarity reasons
                    Wrap(
                      spacing: 4,
                      runSpacing: 4,
                      children: result.similarityReasons.map((reason) => Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppDimensions.paddingS,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.primary.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                        ),
                        child: Text(
                          reason,
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.primary,
                          ),
                        ),
                      )).toList(),
                    ),
                  ],
                ),
              ),
              
              // Actions
              Column(
                children: [
                  IconButton(
                    icon: const Icon(Icons.compare_arrows),
                    onPressed: onCompare,
                  ),
                  IconButton(
                    icon: const Icon(Icons.arrow_forward),
                    onPressed: onTap,
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Color _getScoreColor(double score) {
    if (score >= 0.8) return AppColors.success;
    if (score >= 0.6) return AppColors.warning;
    return AppColors.textSecondary;
  }
}

class _SimilarityGroupCard extends StatelessWidget {
  final String groupName;
  final List<GarmentModel> garments;
  final Function(GarmentModel) onGarmentTap;
  
  const _SimilarityGroupCard({
    required this.groupName,
    required this.garments,
    required this.onGarmentTap,
  });
  
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: Padding(
        padding: const EdgeInsets.all(AppDimensions.paddingM),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.group_work,
                  size: 20,
                  color: AppColors.primary,
                ),
                const SizedBox(width: AppDimensions.paddingS),
                Text(
                  'Similar Group (${garments.length} items)',
                  style: AppTextStyles.labelLarge,
                ),
              ],
            ),
            const SizedBox(height: AppDimensions.paddingM),
            SizedBox(
              height: 100,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemCount: garments.length,
                itemBuilder: (context, index) {
                  final garment = garments[index];
                  
                  return GestureDetector(
                    onTap: () => onGarmentTap(garment),
                    child: Container(
                      width: 80,
                      margin: const EdgeInsets.only(right: AppDimensions.paddingS),
                      child: Column(
                        children: [
                          Expanded(
                            child: ClipRRect(
                              borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                              child: garment.images.isNotEmpty
                                  ? CachedNetworkImage(
                                      imageUrl: garment.images.first.url,
                                      fit: BoxFit.cover,
                                      width: double.infinity,
                                      placeholder: (context, url) => Container(
                                        color: AppColors.backgroundSecondary,
                                        child: const Center(
                                          child: AppLoadingIndicator(
                                            size: LoadingIndicatorSize.small,
                                          ),
                                        ),
                                      ),
                                    )
                                  : Container(
                                      color: AppColors.backgroundSecondary,
                                      child: Icon(
                                        Icons.checkroom,
                                        color: AppColors.textTertiary,
                                        size: 24,
                                      ),
                                    ),
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            garment.name,
                            style: AppTextStyles.caption,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}