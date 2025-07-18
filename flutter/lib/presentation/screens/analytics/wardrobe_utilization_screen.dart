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

/// Screen for wardrobe utilization metrics
class WardrobeUtilizationScreen extends StatefulWidget {
  final String wardrobeId;
  
  const WardrobeUtilizationScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<WardrobeUtilizationScreen> createState() => _WardrobeUtilizationScreenState();
}

class _WardrobeUtilizationScreenState extends State<WardrobeUtilizationScreen> {
  Map<String, dynamic>? _utilizationData;
  bool _isLoading = true;
  
  @override
  void initState() {
    super.initState();
    _loadUtilizationData();
  }
  
  void _loadUtilizationData() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.getUtilizationMetrics(
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
            _utilizationData = data;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading utilization data: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Wardrobe Utilization',
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadUtilizationData,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _utilizationData == null
              ? const Center(child: Text('No utilization data available'))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Overall utilization score
                      _buildOverallScore(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Category utilization
                      _buildCategoryUtilization(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Price range utilization
                      _buildPriceRangeUtilization(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Dead stock analysis
                      _buildDeadStockAnalysis(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Rotation metrics
                      _buildRotationMetrics(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Space efficiency
                      _buildSpaceEfficiency(),
                    ],
                  ),
                ),
    );
  }
  
  Widget _buildOverallScore() {
    final score = _utilizationData!['overall_utilization'] as double;
    final scoreColor = score >= 0.8 
        ? AppColors.success 
        : score >= 0.6 
            ? AppColors.warning 
            : AppColors.error;
    
    return AppFadeAnimation(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            children: [
              Text(
                'Overall Utilization Score',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 150,
                width: 150,
                child: Stack(
                  children: [
                    CircularProgressIndicator(
                      value: score,
                      strokeWidth: 12,
                      backgroundColor: AppColors.backgroundSecondary,
                      valueColor: AlwaysStoppedAnimation<Color>(scoreColor),
                    ),
                    Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            '${(score * 100).toInt()}%',
                            style: AppTextStyles.h1.copyWith(
                              color: scoreColor,
                            ),
                          ),
                          Text(
                            _getScoreLabel(score),
                            style: AppTextStyles.labelMedium,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Text(
                'Items actively worn in your wardrobe',
                style: AppTextStyles.bodyMedium.copyWith(
                  color: AppColors.textSecondary,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildCategoryUtilization() {
    final categoryData = _utilizationData!['category_utilization'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Category Utilization',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 200,
                child: BarChart(
                  BarChartData(
                    alignment: BarChartAlignment.spaceAround,
                    maxY: 1.0,
                    barGroups: categoryData.entries.map((entry) {
                      final index = categoryData.keys.toList().indexOf(entry.key);
                      return BarChartGroupData(
                        x: index,
                        barRods: [
                          BarChartRodData(
                            toY: entry.value,
                            color: _getUtilizationColor(entry.value),
                            width: 30,
                            borderRadius: BorderRadius.circular(4),
                            backDrawRodData: BackgroundBarChartRodData(
                              show: true,
                              toY: 1.0,
                              color: AppColors.backgroundSecondary,
                            ),
                          ),
                        ],
                      );
                    }).toList(),
                    titlesData: FlTitlesData(
                      show: true,
                      bottomTitles: AxisTitles(
                        sideTitles: SideTitles(
                          showTitles: true,
                          getTitlesWidget: (value, meta) {
                            final categories = categoryData.keys.toList();
                            if (value.toInt() < categories.length) {
                              return Text(
                                _formatCategoryName(categories[value.toInt()]),
                                style: AppTextStyles.caption,
                              );
                            }
                            return const Text('');
                          },
                        ),
                      ),
                      leftTitles: AxisTitles(
                        sideTitles: SideTitles(
                          showTitles: true,
                          getTitlesWidget: (value, meta) {
                            return Text(
                              '${(value * 100).toInt()}%',
                              style: AppTextStyles.caption,
                            );
                          },
                        ),
                      ),
                      topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                    ),
                    borderData: FlBorderData(show: false),
                    gridData: FlGridData(
                      show: true,
                      drawHorizontalLine: true,
                      drawVerticalLine: false,
                      getDrawingHorizontalLine: (value) {
                        return FlLine(
                          color: AppColors.backgroundSecondary,
                          strokeWidth: 1,
                        );
                      },
                    ),
                  ),
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Legend
              Wrap(
                spacing: AppDimensions.paddingM,
                runSpacing: AppDimensions.paddingS,
                children: [
                  _buildLegendItem('High', AppColors.success),
                  _buildLegendItem('Medium', AppColors.warning),
                  _buildLegendItem('Low', AppColors.error),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildPriceRangeUtilization() {
    final priceData = _utilizationData!['utilization_by_price_range'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Utilization by Price Range',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'How often you wear items at different price points',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...priceData.entries.map((entry) {
                return Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            _formatPriceRange(entry.key),
                            style: AppTextStyles.labelMedium,
                          ),
                          Text(
                            '${(entry.value * 100).toInt()}%',
                            style: AppTextStyles.labelMedium.copyWith(
                              color: _getUtilizationColor(entry.value),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      LinearProgressIndicator(
                        value: entry.value,
                        backgroundColor: AppColors.backgroundSecondary,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          _getUtilizationColor(entry.value),
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
  
  Widget _buildDeadStockAnalysis() {
    final deadStock = _utilizationData!['dead_stock'] as Map<String, dynamic>;
    
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
                    Icons.warning_amber,
                    color: AppColors.warning,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Dead Stock Analysis',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.warning.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Column(
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                      children: [
                        _buildDeadStockMetric(
                          'Items',
                          deadStock['count'].toString(),
                          Icons.checkroom,
                        ),
                        _buildDeadStockMetric(
                          'Percentage',
                          '${(deadStock['percentage'] * 100).toInt()}%',
                          Icons.pie_chart,
                        ),
                        _buildDeadStockMetric(
                          'Value',
                          '\$${deadStock['value'].toStringAsFixed(0)}',
                          Icons.attach_money,
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Text(
                'Categories with dead stock:',
                style: AppTextStyles.labelMedium,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Wrap(
                spacing: AppDimensions.paddingS,
                children: (deadStock['categories'] as List).map((category) => Chip(
                  label: Text(
                    _formatCategoryName(category),
                    style: AppTextStyles.caption,
                  ),
                  backgroundColor: AppColors.warning.withOpacity(0.1),
                )).toList(),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ElevatedButton.icon(
                onPressed: () {
                  // Navigate to dead stock management
                },
                icon: const Icon(Icons.auto_delete),
                label: const Text('Review Dead Stock'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.warning,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildRotationMetrics() {
    final rotation = _utilizationData!['rotation_metrics'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 400),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Item Rotation',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'How frequently items are worn',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 200,
                child: PieChart(
                  PieChartData(
                    sections: [
                      PieChartSectionData(
                        color: AppColors.success,
                        value: rotation['high_rotation'].toDouble(),
                        title: 'High\n${rotation['high_rotation']}',
                        radius: 80,
                        titleStyle: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      ),
                      PieChartSectionData(
                        color: AppColors.primary,
                        value: rotation['medium_rotation'].toDouble(),
                        title: 'Medium\n${rotation['medium_rotation']}',
                        radius: 80,
                        titleStyle: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      ),
                      PieChartSectionData(
                        color: AppColors.warning,
                        value: rotation['low_rotation'].toDouble(),
                        title: 'Low\n${rotation['low_rotation']}',
                        radius: 80,
                        titleStyle: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      ),
                      PieChartSectionData(
                        color: AppColors.error,
                        value: rotation['no_rotation'].toDouble(),
                        title: 'None\n${rotation['no_rotation']}',
                        radius: 80,
                        titleStyle: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      ),
                    ],
                    sectionsSpace: 2,
                    centerSpaceRadius: 40,
                  ),
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Legend
              Column(
                children: [
                  _buildRotationLegend('High Rotation', 'Worn weekly', AppColors.success),
                  _buildRotationLegend('Medium Rotation', 'Worn monthly', AppColors.primary),
                  _buildRotationLegend('Low Rotation', 'Worn occasionally', AppColors.warning),
                  _buildRotationLegend('No Rotation', 'Never worn', AppColors.error),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildSpaceEfficiency() {
    final space = _utilizationData!['space_efficiency'] as Map<String, dynamic>;
    
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
                    Icons.space_dashboard,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Space Efficiency',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'How well you utilize your storage space',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              
              // Overall space efficiency
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.primary.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'Overall Efficiency',
                      style: AppTextStyles.labelLarge,
                    ),
                    Text(
                      '${(space['overall'] * 100).toInt()}%',
                      style: AppTextStyles.h3.copyWith(
                        color: AppColors.primary,
                      ),
                    ),
                  ],
                ),
              ),
              
              const SizedBox(height: AppDimensions.paddingL),
              
              // Individual space metrics
              _buildSpaceMetric('Hanging Space', space['hanging_space']),
              _buildSpaceMetric('Shelf Space', space['shelf_space']),
              _buildSpaceMetric('Drawer Space', space['drawer_space']),
              
              const SizedBox(height: AppDimensions.paddingL),
              
              // Tips
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.info.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          Icons.lightbulb_outline,
                          size: 16,
                          color: AppColors.info,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'Space Optimization Tips',
                          style: AppTextStyles.labelMedium.copyWith(
                            color: AppColors.info,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      '• Use vertical dividers for shelves\n• Fold heavy sweaters instead of hanging\n• Store out-of-season items separately',
                      style: AppTextStyles.caption,
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
  
  Widget _buildDeadStockMetric(String label, String value, IconData icon) {
    return Column(
      children: [
        Icon(
          icon,
          color: AppColors.warning,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Text(
          value,
          style: AppTextStyles.h3.copyWith(
            color: AppColors.warning,
          ),
        ),
        Text(
          label,
          style: AppTextStyles.caption.copyWith(
            color: AppColors.textSecondary,
          ),
        ),
      ],
    );
  }
  
  Widget _buildLegendItem(String label, Color color) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 12,
          height: 12,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 4),
        Text(
          label,
          style: AppTextStyles.caption,
        ),
      ],
    );
  }
  
  Widget _buildRotationLegend(String label, String description, Color color) {
    return Padding(
      padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
      child: Row(
        children: [
          Container(
            width: 16,
            height: 16,
            decoration: BoxDecoration(
              color: color,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: AppDimensions.paddingS),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: AppTextStyles.labelMedium,
                ),
                Text(
                  description,
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
  }
  
  Widget _buildSpaceMetric(String label, double value) {
    return Container(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                label,
                style: AppTextStyles.labelMedium,
              ),
              Text(
                '${(value * 100).toInt()}%',
                style: AppTextStyles.labelMedium.copyWith(
                  color: _getUtilizationColor(value),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          LinearProgressIndicator(
            value: value,
            backgroundColor: AppColors.backgroundSecondary,
            valueColor: AlwaysStoppedAnimation<Color>(
              _getUtilizationColor(value),
            ),
          ),
        ],
      ),
    );
  }
  
  String _getScoreLabel(double score) {
    if (score >= 0.9) return 'Excellent';
    if (score >= 0.8) return 'Very Good';
    if (score >= 0.7) return 'Good';
    if (score >= 0.6) return 'Fair';
    return 'Needs Improvement';
  }
  
  Color _getUtilizationColor(double value) {
    if (value >= 0.8) return AppColors.success;
    if (value >= 0.6) return AppColors.warning;
    return AppColors.error;
  }
  
  String _formatCategoryName(String category) {
    return category.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
  }
  
  String _formatPriceRange(String range) {
    final formatted = range.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ');
    
    final priceRanges = {
      'Budget': '\$0-50',
      'Mid Range': '\$50-150',
      'Premium': '\$150-500',
      'Luxury': '\$500+',
    };
    
    return '$formatted (${priceRanges[formatted] ?? ''})';
  }
}