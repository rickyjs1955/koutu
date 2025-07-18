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

/// Screen for seasonal usage analytics
class SeasonalUsageScreen extends StatefulWidget {
  final String wardrobeId;
  
  const SeasonalUsageScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<SeasonalUsageScreen> createState() => _SeasonalUsageScreenState();
}

class _SeasonalUsageScreenState extends State<SeasonalUsageScreen> {
  Map<String, dynamic>? _seasonalData;
  bool _isLoading = true;
  String _selectedSeason = 'current';
  
  @override
  void initState() {
    super.initState();
    _loadSeasonalData();
  }
  
  void _loadSeasonalData() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.getSeasonalAnalytics(
        'current_user_id', // In real app, get from auth state
        widget.wardrobeId,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to load data: ${failure.message}')),
          );
        },
        (data) {
          setState(() {
            _seasonalData = data;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading seasonal data: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Seasonal Analytics',
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadSeasonalData,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _seasonalData == null
              ? const Center(child: Text('No seasonal data available'))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Current season readiness
                      _buildSeasonReadiness(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Season selector
                      _buildSeasonSelector(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Seasonal distribution
                      _buildSeasonalDistribution(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Transition items
                      _buildTransitionItems(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Seasonal gaps
                      _buildSeasonalGaps(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Weather alignment
                      _buildWeatherAlignment(),
                    ],
                  ),
                ),
    );
  }
  
  Widget _buildSeasonReadiness() {
    final readiness = _seasonalData!['current_season_readiness'] as double;
    final scoreColor = readiness >= 0.8 
        ? AppColors.success 
        : readiness >= 0.6 
            ? AppColors.warning 
            : AppColors.error;
    
    return AppFadeAnimation(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Current Season Readiness',
                        style: AppTextStyles.h3,
                      ),
                      const SizedBox(height: AppDimensions.paddingS),
                      Text(
                        'How prepared your wardrobe is for current weather',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                    ],
                  ),
                  Container(
                    width: 80,
                    height: 80,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: scoreColor,
                        width: 4,
                      ),
                    ),
                    child: Center(
                      child: Text(
                        '${(readiness * 100).toInt()}%',
                        style: AppTextStyles.h3.copyWith(
                          color: scoreColor,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              LinearProgressIndicator(
                value: readiness,
                backgroundColor: AppColors.backgroundSecondary,
                valueColor: AlwaysStoppedAnimation<Color>(scoreColor),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildSeasonSelector() {
    final seasons = ['Spring', 'Summer', 'Fall', 'Winter', 'All Seasons'];
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: SizedBox(
        height: 40,
        child: ListView.builder(
          scrollDirection: Axis.horizontal,
          itemCount: seasons.length,
          itemBuilder: (context, index) {
            final season = seasons[index];
            final isSelected = _selectedSeason == season.toLowerCase().replaceAll(' ', '_');
            
            return Container(
              margin: const EdgeInsets.only(right: AppDimensions.paddingM),
              child: ChoiceChip(
                label: Text(season),
                selected: isSelected,
                onSelected: (selected) {
                  if (selected) {
                    setState(() {
                      _selectedSeason = season.toLowerCase().replaceAll(' ', '_');
                    });
                  }
                },
                selectedColor: AppColors.primary,
                labelStyle: AppTextStyles.labelMedium.copyWith(
                  color: isSelected ? Colors.white : AppColors.textPrimary,
                ),
              ),
            );
          },
        ),
      ),
    );
  }
  
  Widget _buildSeasonalDistribution() {
    final distribution = _seasonalData!['seasonal_distribution'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Seasonal Distribution',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 300,
                child: RadarChart(
                  RadarChartData(
                    radarShape: RadarShape.polygon,
                    radarBorderData: BorderSide(color: AppColors.primary, width: 2),
                    gridBorderData: BorderSide(color: AppColors.backgroundSecondary, width: 1),
                    tickBorderData: BorderSide(color: AppColors.backgroundSecondary, width: 1),
                    tickCount: 4,
                    titleTextStyle: AppTextStyles.labelMedium,
                    titlePositionPercentageOffset: 0.1,
                    getTitle: (index, angle) {
                      final seasons = ['Spring', 'Summer', 'Fall', 'Winter'];
                      if (index < seasons.length) {
                        final season = seasons[index];
                        final data = distribution[season.toLowerCase()] as Map<String, dynamic>;
                        return RadarChartTitle(
                          text: '$season\n${data['items']} items',
                          angle: 0,
                        );
                      }
                      return RadarChartTitle(text: '');
                    },
                    dataSets: [
                      RadarDataSet(
                        fillColor: AppColors.primary.withOpacity(0.3),
                        borderColor: AppColors.primary,
                        borderWidth: 2,
                        dataEntries: distribution.values.map((data) => 
                          RadarEntry(value: (data['utilization'] as double) * 100)
                        ).toList(),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Season details
              ...distribution.entries.map((entry) {
                final seasonData = entry.value as Map<String, dynamic>;
                return Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  decoration: BoxDecoration(
                    color: AppColors.backgroundSecondary,
                    borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        _getSeasonIcon(entry.key),
                        color: _getSeasonColor(entry.key),
                      ),
                      const SizedBox(width: AppDimensions.paddingM),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              _formatSeasonName(entry.key),
                              style: AppTextStyles.labelLarge,
                            ),
                            Text(
                              '${seasonData['items']} items • ${(seasonData['utilization'] * 100).toInt()}% utilization',
                              style: AppTextStyles.caption.copyWith(
                                color: AppColors.textSecondary,
                              ),
                            ),
                          ],
                        ),
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
  
  Widget _buildTransitionItems() {
    final transitionItems = _seasonalData!['transition_items'] as List;
    
    if (transitionItems.isEmpty) return const SizedBox.shrink();
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 300),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.swap_horiz,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Transition Items',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'Versatile pieces that work across multiple seasons',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...transitionItems.map((item) {
                final itemData = item as Map<String, dynamic>;
                return ListTile(
                  leading: CircleAvatar(
                    backgroundColor: AppColors.primary.withOpacity(0.1),
                    child: Icon(
                      Icons.checkroom,
                      color: AppColors.primary,
                    ),
                  ),
                  title: Text(itemData['name']),
                  subtitle: Text('Works in: ${(itemData['seasons'] as List).join(', ')}'),
                  trailing: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingS,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.success.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Text(
                      'Versatile',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.success,
                      ),
                    ),
                  ),
                );
              }).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildSeasonalGaps() {
    final gaps = _seasonalData!['seasonal_gaps'] as Map<String, dynamic>;
    
    if (gaps.isEmpty) return const SizedBox.shrink();
    
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
                    Icons.warning_amber,
                    color: AppColors.warning,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Seasonal Gaps',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'Items you might need for complete seasonal coverage',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...gaps.entries.map((entry) {
                final gapItems = entry.value as List;
                if (gapItems.isEmpty) return const SizedBox.shrink();
                
                return Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingL),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            _getSeasonIcon(entry.key),
                            size: 20,
                            color: _getSeasonColor(entry.key),
                          ),
                          const SizedBox(width: AppDimensions.paddingS),
                          Text(
                            _formatSeasonName(entry.key),
                            style: AppTextStyles.labelLarge,
                          ),
                        ],
                      ),
                      const SizedBox(height: AppDimensions.paddingS),
                      Wrap(
                        spacing: AppDimensions.paddingS,
                        runSpacing: AppDimensions.paddingS,
                        children: gapItems.map((item) => Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: AppDimensions.paddingM,
                            vertical: AppDimensions.paddingS,
                          ),
                          decoration: BoxDecoration(
                            color: AppColors.warning.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                            border: Border.all(
                              color: AppColors.warning.withOpacity(0.3),
                            ),
                          ),
                          child: Text(
                            _formatItemName(item),
                            style: AppTextStyles.caption,
                          ),
                        )).toList(),
                      ),
                    ],
                  ),
                );
              }).toList(),
              const SizedBox(height: AppDimensions.paddingL),
              ElevatedButton.icon(
                onPressed: () {
                  // Navigate to shopping list
                },
                icon: const Icon(Icons.shopping_cart),
                label: const Text('Create Shopping List'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.primary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildWeatherAlignment() {
    final weather = _seasonalData!['weather_alignment'] as Map<String, dynamic>;
    final score = weather['score'] as double;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 500),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.wb_sunny,
                    color: AppColors.warning,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Weather Alignment',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              
              // Score gauge
              SizedBox(
                height: 150,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox(
                      width: 150,
                      height: 150,
                      child: CircularProgressIndicator(
                        value: score,
                        strokeWidth: 12,
                        backgroundColor: AppColors.backgroundSecondary,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          score >= 0.8 
                              ? AppColors.success 
                              : score >= 0.6 
                                  ? AppColors.warning 
                                  : AppColors.error,
                        ),
                      ),
                    ),
                    Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          '${(score * 100).toInt()}%',
                          style: AppTextStyles.h2,
                        ),
                        Text(
                          'Aligned',
                          style: AppTextStyles.labelMedium,
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              
              const SizedBox(height: AppDimensions.paddingL),
              
              // Missing items for current weather
              if (weather['missing_for_current'] != null && 
                  (weather['missing_for_current'] as List).isNotEmpty) ...{
                Text(
                  'Missing for Current Weather',
                  style: AppTextStyles.labelLarge,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                Wrap(
                  spacing: AppDimensions.paddingS,
                  runSpacing: AppDimensions.paddingS,
                  children: (weather['missing_for_current'] as List).map((item) => Chip(
                    label: Text(
                      _formatItemName(item),
                      style: AppTextStyles.caption,
                    ),
                    backgroundColor: AppColors.error.withOpacity(0.1),
                    avatar: Icon(
                      Icons.close,
                      size: 16,
                      color: AppColors.error,
                    ),
                  )).toList(),
                ),
              },
            ],
          ),
        ),
      ),
    );
  }
  
  IconData _getSeasonIcon(String season) {
    switch (season.toLowerCase()) {
      case 'spring':
        return Icons.local_florist;
      case 'summer':
        return Icons.wb_sunny;
      case 'fall':
        return Icons.park;
      case 'winter':
        return Icons.ac_unit;
      default:
        return Icons.calendar_today;
    }
  }
  
  Color _getSeasonColor(String season) {
    switch (season.toLowerCase()) {
      case 'spring':
        return Colors.green;
      case 'summer':
        return Colors.orange;
      case 'fall':
        return Colors.brown;
      case 'winter':
        return Colors.blue;
      default:
        return AppColors.primary;
    }
  }
  
  String _formatSeasonName(String season) {
    return season.split('_').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
  
  String _formatItemName(String item) {
    return item.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
}