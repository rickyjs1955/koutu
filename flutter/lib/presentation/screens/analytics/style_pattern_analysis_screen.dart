import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/services/analytics/wardrobe_analytics_service.dart';
import 'package:go_router/go_router.dart';

/// Screen for style pattern analysis with trends
class StylePatternAnalysisScreen extends StatefulWidget {
  final String wardrobeId;
  
  const StylePatternAnalysisScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<StylePatternAnalysisScreen> createState() => _StylePatternAnalysisScreenState();
}

class _StylePatternAnalysisScreenState extends State<StylePatternAnalysisScreen> {
  Map<String, dynamic>? _stylePatterns;
  bool _isLoading = true;
  
  @override
  void initState() {
    super.initState();
    _loadStylePatterns();
  }
  
  void _loadStylePatterns() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.getStylePatterns(
        'current_user_id', // In real app, get from auth state
        widget.wardrobeId,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to load patterns: ${failure.message}')),
          );
        },
        (patterns) {
          setState(() {
            _stylePatterns = patterns;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading style patterns: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Style Pattern Analysis',
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadStylePatterns,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _stylePatterns == null
              ? const Center(child: Text('No pattern data available'))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Personal uniform
                      _buildPersonalUniform(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Dominant patterns
                      _buildDominantPatterns(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Color patterns
                      _buildColorPatterns(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Outfit formulas
                      _buildOutfitFormulas(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Style evolution
                      _buildStyleEvolution(),
                    ],
                  ),
                ),
    );
  }
  
  Widget _buildPersonalUniform() {
    final uniform = _stylePatterns!['personal_uniform'] as Map<String, dynamic>;
    
    if (!uniform['exists']) return const SizedBox.shrink();
    
    return AppFadeAnimation(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.style,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Your Personal Uniform',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.primary.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      uniform['description'],
                      style: AppTextStyles.labelLarge,
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Row(
                      children: [
                        Icon(
                          Icons.repeat,
                          size: 16,
                          color: AppColors.primary,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'Worn ${(uniform['frequency'] * 100).toInt()}% of the time',
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.primary,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildDominantPatterns() {
    final patterns = _stylePatterns!['dominant_patterns'] as List;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Dominant Style Patterns',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Wrap(
                spacing: AppDimensions.paddingS,
                runSpacing: AppDimensions.paddingS,
                children: patterns.map((pattern) => Chip(
                  label: Text(pattern),
                  backgroundColor: AppColors.primary.withOpacity(0.1),
                  labelStyle: AppTextStyles.labelMedium.copyWith(
                    color: AppColors.primary,
                  ),
                )).toList(),
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Text(
                'These patterns appear most frequently in your outfit choices',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildColorPatterns() {
    final colorPatterns = _stylePatterns!['color_patterns'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Color Combination Patterns',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 200,
                child: PieChart(
                  PieChartData(
                    sections: colorPatterns.entries.map((entry) {
                      return PieChartSectionData(
                        color: _getColorPatternColor(entry.key),
                        value: entry.value * 100,
                        title: '${(entry.value * 100).toInt()}%',
                        radius: 80,
                        titleStyle: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      );
                    }).toList(),
                    sectionsSpace: 2,
                    centerSpaceRadius: 40,
                  ),
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Legend
              Wrap(
                spacing: AppDimensions.paddingM,
                runSpacing: AppDimensions.paddingS,
                children: colorPatterns.entries.map((entry) {
                  return Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 12,
                        height: 12,
                        decoration: BoxDecoration(
                          color: _getColorPatternColor(entry.key),
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        _formatColorPatternName(entry.key),
                        style: AppTextStyles.caption,
                      ),
                    ],
                  );
                }).toList(),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildOutfitFormulas() {
    final formulas = _stylePatterns!['outfit_formulas'] as List;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 300),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Your Outfit Formulas',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'Recurring combinations that work for you',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingM),
              ...formulas.map((formula) {
                final data = formula as Map<String, dynamic>;
                return Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  decoration: BoxDecoration(
                    color: AppColors.backgroundSecondary,
                    borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            data['name'],
                            style: AppTextStyles.labelLarge,
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: AppDimensions.paddingS,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: AppColors.primary,
                              borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                            ),
                            child: Text(
                              '${(data['frequency'] * 100).toInt()}%',
                              style: AppTextStyles.caption.copyWith(
                                color: Colors.white,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: AppDimensions.paddingS),
                      Wrap(
                        spacing: AppDimensions.paddingXS,
                        children: (data['components'] as List).map((component) => Text(
                          '• $component',
                          style: AppTextStyles.caption,
                        )).toList(),
                      ),
                    ],
                  ),
                );
              }).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildStyleEvolution() {
    final evolution = _stylePatterns!['style_evolution'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 400),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.trending_up,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Style Evolution',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              
              // Past year changes
              if (evolution['past_year'] != null) ...[
                Text(
                  'Changes in the Past Year',
                  style: AppTextStyles.labelLarge,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                ...(evolution['past_year'] as List).map((change) => Padding(
                  padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
                  child: Row(
                    children: [
                      Icon(
                        Icons.arrow_forward,
                        size: 16,
                        color: AppColors.primary,
                      ),
                      const SizedBox(width: AppDimensions.paddingS),
                      Expanded(
                        child: Text(
                          _formatEvolutionChange(change),
                          style: AppTextStyles.bodyMedium,
                        ),
                      ),
                    ],
                  ),
                )).toList(),
              ],
              
              const SizedBox(height: AppDimensions.paddingL),
              
              // Emerging trends
              if (evolution['emerging_trends'] != null) ...[
                Text(
                  'Emerging Trends',
                  style: AppTextStyles.labelLarge,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                Wrap(
                  spacing: AppDimensions.paddingS,
                  runSpacing: AppDimensions.paddingS,
                  children: (evolution['emerging_trends'] as List).map((trend) => Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingM,
                      vertical: AppDimensions.paddingS,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.success.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                      border: Border.all(
                        color: AppColors.success.withOpacity(0.3),
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.trending_up,
                          size: 16,
                          color: AppColors.success,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          _formatTrendName(trend),
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.success,
                          ),
                        ),
                      ],
                    ),
                  )).toList(),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
  
  Color _getColorPatternColor(String pattern) {
    final colors = {
      'monochrome': Colors.grey,
      'complementary': AppColors.primary,
      'analogous': AppColors.secondary,
      'neutral': AppColors.textSecondary,
    };
    
    return colors[pattern] ?? AppColors.textTertiary;
  }
  
  String _formatColorPatternName(String pattern) {
    return pattern.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
  
  String _formatEvolutionChange(String change) {
    return change.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
  
  String _formatTrendName(String trend) {
    return trend.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
}