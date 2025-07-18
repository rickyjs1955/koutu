import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/services/recommendation/style_recommendation_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/user/user_model.dart';

/// Widget to display AI-powered style recommendations
class StyleRecommendationsWidget extends StatefulWidget {
  final List<GarmentModel> garments;
  final UserModel user;
  final Function(GarmentModel) onGarmentTap;
  final Function(List<GarmentModel>) onOutfitTap;
  
  const StyleRecommendationsWidget({
    super.key,
    required this.garments,
    required this.user,
    required this.onGarmentTap,
    required this.onOutfitTap,
  });

  @override
  State<StyleRecommendationsWidget> createState() => _StyleRecommendationsWidgetState();
}

class _StyleRecommendationsWidgetState extends State<StyleRecommendationsWidget>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  
  List<StyleRecommendation> _allRecommendations = [];
  List<StyleRecommendation> _outfitRecommendations = [];
  List<StyleRecommendation> _similarRecommendations = [];
  List<StyleRecommendation> _colorMatchRecommendations = [];
  List<StyleRecommendation> _seasonalRecommendations = [];
  
  bool _isLoading = true;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 5, vsync: this);
    _generateRecommendations();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }
  
  void _generateRecommendations() async {
    setState(() => _isLoading = true);
    
    try {
      // Generate all types of recommendations
      _allRecommendations = StyleRecommendationService.generateRecommendations(
        widget.garments,
        widget.user,
        type: RecommendationType.all,
        maxResults: 20,
      );
      
      _outfitRecommendations = StyleRecommendationService.generateRecommendations(
        widget.garments,
        widget.user,
        type: RecommendationType.outfits,
        maxResults: 15,
      );
      
      _similarRecommendations = StyleRecommendationService.generateRecommendations(
        widget.garments,
        widget.user,
        type: RecommendationType.similar,
        maxResults: 15,
      );
      
      _colorMatchRecommendations = StyleRecommendationService.generateRecommendations(
        widget.garments,
        widget.user,
        type: RecommendationType.colorMatch,
        maxResults: 15,
      );
      
      _seasonalRecommendations = StyleRecommendationService.generateRecommendations(
        widget.garments,
        widget.user,
        type: RecommendationType.seasonal,
        maxResults: 15,
      );
      
    } catch (e) {
      debugPrint('Error generating recommendations: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Center(
        child: AppLoadingIndicator(),
      );
    }
    
    if (_allRecommendations.isEmpty) {
      return _buildEmptyState();
    }
    
    return Column(
      children: [
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
            labelStyle: AppTextStyles.labelMedium,
            unselectedLabelStyle: AppTextStyles.labelMedium,
            tabs: [
              Tab(
                icon: Icon(RecommendationType.all.icon, size: 20),
                text: 'All',
              ),
              Tab(
                icon: Icon(RecommendationType.outfits.icon, size: 20),
                text: 'Outfits',
              ),
              Tab(
                icon: Icon(RecommendationType.similar.icon, size: 20),
                text: 'Similar',
              ),
              Tab(
                icon: Icon(RecommendationType.colorMatch.icon, size: 20),
                text: 'Colors',
              ),
              Tab(
                icon: Icon(RecommendationType.seasonal.icon, size: 20),
                text: 'Seasonal',
              ),
            ],
          ),
        ),
        
        // Tab content
        Expanded(
          child: TabBarView(
            controller: _tabController,
            children: [
              _buildRecommendationsList(_allRecommendations),
              _buildRecommendationsList(_outfitRecommendations),
              _buildRecommendationsList(_similarRecommendations),
              _buildRecommendationsList(_colorMatchRecommendations),
              _buildRecommendationsList(_seasonalRecommendations),
            ],
          ),
        ),
      ],
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.auto_awesome,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Recommendations Yet',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Add more garments to get personalized style recommendations',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Widget _buildRecommendationsList(List<StyleRecommendation> recommendations) {
    if (recommendations.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.style,
              size: 48,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Text(
              'No recommendations in this category',
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
      itemCount: recommendations.length,
      itemBuilder: (context, index) {
        final recommendation = recommendations[index];
        
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _RecommendationCard(
            recommendation: recommendation,
            onGarmentTap: widget.onGarmentTap,
            onOutfitTap: widget.onOutfitTap,
          ),
        );
      },
    );
  }
}

class _RecommendationCard extends StatelessWidget {
  final StyleRecommendation recommendation;
  final Function(GarmentModel) onGarmentTap;
  final Function(List<GarmentModel>) onOutfitTap;
  
  const _RecommendationCard({
    required this.recommendation,
    required this.onGarmentTap,
    required this.onOutfitTap,
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
            // Header
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(AppDimensions.paddingS),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                  child: Icon(
                    recommendation.type.icon,
                    size: 20,
                    color: AppColors.primary,
                  ),
                ),
                const SizedBox(width: AppDimensions.paddingM),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        recommendation.title,
                        style: AppTextStyles.labelLarge,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        recommendation.description,
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                // Relevance score
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppDimensions.paddingS,
                    vertical: AppDimensions.paddingXS,
                  ),
                  decoration: BoxDecoration(
                    color: _getScoreColor(recommendation.relevanceScore),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                  child: Text(
                    '${(recommendation.relevanceScore * 100).toInt()}%',
                    style: AppTextStyles.caption.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
            
            const SizedBox(height: AppDimensions.paddingM),
            
            // Garment images
            SizedBox(
              height: 120,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemCount: recommendation.garments.length,
                itemBuilder: (context, index) {
                  final garment = recommendation.garments[index];
                  
                  return GestureDetector(
                    onTap: () {
                      if (recommendation.garments.length == 1) {
                        onGarmentTap(garment);
                      } else {
                        onOutfitTap(recommendation.garments);
                      }
                    },
                    child: Container(
                      width: 100,
                      margin: const EdgeInsets.only(right: AppDimensions.paddingS),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                        border: Border.all(
                          color: AppColors.border,
                          width: 1,
                        ),
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Image
                            Expanded(
                              flex: 3,
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
                                      errorWidget: (context, url, error) => Container(
                                        color: AppColors.backgroundSecondary,
                                        child: Icon(
                                          Icons.checkroom,
                                          color: AppColors.textTertiary,
                                          size: 24,
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
                            
                            // Name
                            Expanded(
                              flex: 1,
                              child: Container(
                                padding: const EdgeInsets.all(AppDimensions.paddingXS),
                                child: Text(
                                  garment.name,
                                  style: AppTextStyles.caption,
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingM),
            
            // Reason
            Container(
              padding: const EdgeInsets.all(AppDimensions.paddingS),
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
                borderRadius: BorderRadius.circular(AppDimensions.radiusS),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.lightbulb_outline,
                    size: 16,
                    color: AppColors.textSecondary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Expanded(
                    child: Text(
                      recommendation.reason,
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
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