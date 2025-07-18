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

/// Screen for cost per wear calculations
class CostPerWearScreen extends StatefulWidget {
  final String wardrobeId;
  
  const CostPerWearScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<CostPerWearScreen> createState() => _CostPerWearScreenState();
}

class _CostPerWearScreenState extends State<CostPerWearScreen> {
  Map<String, dynamic>? _costData;
  bool _isLoading = true;
  String _sortBy = 'best_value';
  
  @override
  void initState() {
    super.initState();
    _loadCostData();
  }
  
  void _loadCostData() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.getCostPerWear(
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
            _costData = data;
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading cost data: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Cost Per Wear Analysis',
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: _showInfoDialog,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _costData == null
              ? const Center(child: Text('No cost data available'))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Summary metrics
                      _buildSummaryMetrics(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Cost by category chart
                      _buildCostByCategory(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Sort selector
                      _buildSortSelector(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Best value items
                      _buildBestValueItems(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Worst value items
                      _buildWorstValueItems(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Value optimization tips
                      _buildOptimizationTips(),
                    ],
                  ),
                ),
    );
  }
  
  Widget _buildSummaryMetrics() {
    return AppFadeAnimation(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            children: [
              Text(
                'Cost Per Wear Overview',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _buildMetricCard(
                    'Average CPW',
                    '\$${_costData!['average_cost_per_wear'].toStringAsFixed(2)}',
                    Icons.trending_down,
                    AppColors.primary,
                  ),
                  _buildMetricCard(
                    'Total Value',
                    '\$${(_costData!['total_wardrobe_value'] as double).toStringAsFixed(0)}',
                    Icons.account_balance_wallet,
                    AppColors.info,
                  ),
                  _buildMetricCard(
                    'Total Wears',
                    _costData!['total_wears'].toString(),
                    Icons.checkroom,
                    AppColors.success,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.success.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.lightbulb_outline,
                      color: AppColors.success,
                    ),
                    const SizedBox(width: AppDimensions.paddingM),
                    Expanded(
                      child: Text(
                        'Lower cost per wear means better value from your wardrobe investment',
                        style: AppTextStyles.bodyMedium.copyWith(
                          color: AppColors.success,
                        ),
                      ),
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
  
  Widget _buildCostByCategory() {
    final categoryData = _costData!['cost_per_wear_by_category'] as Map<String, dynamic>;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Cost Per Wear by Category',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 250,
                child: BarChart(
                  BarChartData(
                    alignment: BarChartAlignment.spaceAround,
                    maxY: categoryData.values.reduce((a, b) => a > b ? a : b) * 1.2,
                    barGroups: categoryData.entries.map((entry) {
                      final index = categoryData.keys.toList().indexOf(entry.key);
                      return BarChartGroupData(
                        x: index,
                        barRods: [
                          BarChartRodData(
                            toY: entry.value,
                            color: _getCategoryColor(entry.value),
                            width: 30,
                            borderRadius: BorderRadius.circular(4),
                            backDrawRodData: BackgroundBarChartRodData(
                              show: true,
                              toY: categoryData.values.reduce((a, b) => a > b ? a : b) * 1.2,
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
                              return RotatedBox(
                                quarterTurns: 1,
                                child: Text(
                                  _formatCategoryName(categories[value.toInt()]),
                                  style: AppTextStyles.caption,
                                ),
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
                              '\$${value.toInt()}',
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
              // Value indicator
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _buildValueIndicator('Excellent', '<\$5', AppColors.success),
                  _buildValueIndicator('Good', '\$5-15', AppColors.primary),
                  _buildValueIndicator('Fair', '\$15-50', AppColors.warning),
                  _buildValueIndicator('Poor', '>\$50', AppColors.error),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildSortSelector() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(AppDimensions.radiusM),
          border: Border.all(color: AppColors.backgroundSecondary),
        ),
        child: DropdownButton<String>(
          value: _sortBy,
          isExpanded: true,
          underline: const SizedBox(),
          items: const [
            DropdownMenuItem(value: 'best_value', child: Text('Best Value First')),
            DropdownMenuItem(value: 'worst_value', child: Text('Worst Value First')),
            DropdownMenuItem(value: 'most_worn', child: Text('Most Worn')),
            DropdownMenuItem(value: 'highest_price', child: Text('Highest Price')),
          ],
          onChanged: (value) {
            if (value != null) {
              setState(() {
                _sortBy = value;
              });
            }
          },
        ),
      ),
    );
  }
  
  Widget _buildBestValueItems() {
    final bestItems = _costData!['best_value_items'] as List;
    
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
                    Icons.star,
                    color: AppColors.warning,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Best Value Items',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'Items with the lowest cost per wear',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...bestItems.map((item) {
                final itemData = item as Map<String, dynamic>;
                return _buildValueItemCard(
                  itemData,
                  isGoodValue: true,
                );
              }).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildWorstValueItems() {
    final worstItems = _costData!['worst_value_items'] as List;
    
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
                    color: AppColors.error,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Items Needing Attention',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'High cost items with low wear frequency',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...worstItems.map((item) {
                final itemData = item as Map<String, dynamic>;
                return _buildValueItemCard(
                  itemData,
                  isGoodValue: false,
                );
              }).toList(),
              const SizedBox(height: AppDimensions.paddingL),
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
                          Icons.tips_and_updates,
                          size: 16,
                          color: AppColors.info,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'Improvement Suggestions',
                          style: AppTextStyles.labelMedium.copyWith(
                            color: AppColors.info,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      '• Style these items more frequently\n• Consider renting formal wear for rare occasions\n• Sell or donate items you won\'t wear',
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
  
  Widget _buildOptimizationTips() {
    final tips = _costData!['value_optimization_tips'] as List;
    
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
                    Icons.auto_awesome,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Value Optimization Tips',
                    style: AppTextStyles.h3,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...tips.asMap().entries.map((entry) {
                final index = entry.key;
                final tip = entry.value;
                return Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  decoration: BoxDecoration(
                    color: AppColors.primary.withOpacity(0.05),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                    border: Border.all(
                      color: AppColors.primary.withOpacity(0.2),
                    ),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        width: 24,
                        height: 24,
                        decoration: BoxDecoration(
                          color: AppColors.primary,
                          shape: BoxShape.circle,
                        ),
                        child: Center(
                          child: Text(
                            '${index + 1}',
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: AppDimensions.paddingM),
                      Expanded(
                        child: Text(
                          tip,
                          style: AppTextStyles.bodyMedium,
                        ),
                      ),
                    ],
                  ),
                );
              }).toList(),
              const SizedBox(height: AppDimensions.paddingL),
              // ROI calculator
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      AppColors.primary.withOpacity(0.1),
                      AppColors.primary.withOpacity(0.05),
                    ],
                  ),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Quick ROI Calculator',
                      style: AppTextStyles.labelLarge,
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      'Target CPW = Item Price ÷ Expected Wears',
                      style: AppTextStyles.bodyMedium,
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      'Example: \$100 item worn 50 times = \$2 per wear',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
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
  
  Widget _buildMetricCard(String label, String value, IconData icon, Color color) {
    return Column(
      children: [
        Icon(
          icon,
          color: color,
          size: 32,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Text(
          value,
          style: AppTextStyles.h3.copyWith(
            color: color,
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
  
  Widget _buildValueIndicator(String label, String range, Color color) {
    return Row(
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
          '$label ($range)',
          style: AppTextStyles.caption,
        ),
      ],
    );
  }
  
  Widget _buildValueItemCard(Map<String, dynamic> item, {required bool isGoodValue}) {
    final cpw = item['cost_per_wear'] as double;
    final valueColor = isGoodValue ? AppColors.success : AppColors.error;
    
    return Container(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
        border: Border.all(
          color: valueColor.withOpacity(0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Text(
                  item['name'],
                  style: AppTextStyles.labelLarge,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: AppDimensions.paddingM,
                  vertical: AppDimensions.paddingS,
                ),
                decoration: BoxDecoration(
                  color: valueColor.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Text(
                  '\$${cpw.toStringAsFixed(2)}/wear',
                  style: AppTextStyles.labelMedium.copyWith(
                    color: valueColor,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: AppDimensions.paddingM),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _buildItemDetail('Price', '\$${item['price'].toStringAsFixed(2)}'),
              _buildItemDetail('Wears', item['wears'].toString()),
              _buildItemDetail('Cost/Wear', '\$${cpw.toStringAsFixed(2)}'),
            ],
          ),
          if (!isGoodValue) ...{
            const SizedBox(height: AppDimensions.paddingM),
            LinearProgressIndicator(
              value: item['wears'] / 100.0, // Assuming 100 wears is good
              backgroundColor: AppColors.backgroundSecondary,
              valueColor: AlwaysStoppedAnimation<Color>(valueColor),
            ),
          },
        ],
      ),
    );
  }
  
  Widget _buildItemDetail(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: AppTextStyles.caption.copyWith(
            color: AppColors.textSecondary,
          ),
        ),
        Text(
          value,
          style: AppTextStyles.labelMedium,
        ),
      ],
    );
  }
  
  Color _getCategoryColor(double cpw) {
    if (cpw < 5) return AppColors.success;
    if (cpw < 15) return AppColors.primary;
    if (cpw < 50) return AppColors.warning;
    return AppColors.error;
  }
  
  String _formatCategoryName(String category) {
    return category.replaceAll('_', ' ').split(' ').map((word) => 
      word.isNotEmpty ? '${word[0].toUpperCase()}${word.substring(1)}' : ''
    ).join(' ').replaceAll(' Wear', '');
  }
  
  void _showInfoDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Understanding Cost Per Wear'),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Cost Per Wear (CPW) helps you understand the true value of your clothing investments.',
                style: AppTextStyles.bodyMedium,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Text(
                'How it\'s calculated:',
                style: AppTextStyles.labelLarge,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                'CPW = Item Price ÷ Number of Wears',
                style: AppTextStyles.bodyMedium.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Text(
                'Examples:',
                style: AppTextStyles.labelLarge,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                '• \$50 shirt worn 50 times = \$1 per wear\n• \$200 jacket worn 10 times = \$20 per wear\n• \$500 suit worn 5 times = \$100 per wear',
                style: AppTextStyles.bodyMedium,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              Text(
                'Lower CPW indicates better value from your investment.',
                style: AppTextStyles.bodyMedium.copyWith(
                  fontStyle: FontStyle.italic,
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Got it'),
          ),
        ],
      ),
    );
  }
}