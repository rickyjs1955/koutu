import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/data/models/analytics/wardrobe_analytics_model.dart';
import 'package:koutu/services/analytics/wardrobe_analytics_service.dart';
import 'package:go_router/go_router.dart';

/// Comprehensive wardrobe analytics dashboard
class WardrobeAnalyticsDashboard extends StatefulWidget {
  final String wardrobeId;
  
  const WardrobeAnalyticsDashboard({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<WardrobeAnalyticsDashboard> createState() => _WardrobeAnalyticsDashboardState();
}

class _WardrobeAnalyticsDashboardState extends State<WardrobeAnalyticsDashboard> {
  WardrobeAnalytics? _analytics;
  bool _isLoading = true;
  String _selectedTimeframe = 'All Time';
  
  final List<String> _timeframes = ['All Time', 'Last Year', 'Last 6 Months', 'Last Month'];
  
  @override
  void initState() {
    super.initState();
    _loadAnalytics();
  }
  
  void _loadAnalytics() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.generateWardrobeAnalytics(
        'current_user_id', // In real app, get from auth state
        widget.wardrobeId,
      );
      
      result.fold(
        (failure) {
          // Handle error
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to load analytics: ${failure.message}')),
          );
        },
        (analytics) {
          setState(() {
            _analytics = analytics;
          });
        },
      );
    } catch (e) {
      // Handle error
      debugPrint('Error loading analytics: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onTimeframeChanged(String timeframe) {
    setState(() {
      _selectedTimeframe = timeframe;
    });
    _loadAnalytics(); // Reload with new timeframe
  }
  
  void _onExportReport() async {
    final format = await showDialog<String>(
      context: context,
      builder: (context) => SimpleDialog(
        title: const Text('Export Format'),
        children: [
          SimpleDialogOption(
            onPressed: () => Navigator.pop(context, 'pdf'),
            child: const Text('PDF Report'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.pop(context, 'csv'),
            child: const Text('CSV Data'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.pop(context, 'json'),
            child: const Text('JSON Data'),
          ),
        ],
      ),
    );
    
    if (format != null) {
      final result = await WardrobeAnalyticsService.exportAnalyticsReport(
        'current_user_id',
        widget.wardrobeId,
        format,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Export failed: ${failure.message}')),
          );
        },
        (url) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Report exported successfully'),
              action: SnackBarAction(
                label: 'View',
                onPressed: () {
                  // Open URL
                },
              ),
            ),
          );
        },
      );
    }
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Wardrobe Analytics',
        actions: [
          PopupMenuButton<String>(
            onSelected: _onTimeframeChanged,
            itemBuilder: (context) => _timeframes.map((timeframe) => 
              PopupMenuItem(
                value: timeframe,
                child: Text(timeframe),
              ),
            ).toList(),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
              child: Row(
                children: [
                  Text(_selectedTimeframe, style: AppTextStyles.labelMedium),
                  const Icon(Icons.arrow_drop_down),
                ],
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.download),
            onPressed: _onExportReport,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _analytics == null
              ? const Center(child: Text('No analytics available'))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(AppDimensions.paddingM),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Health Score Card
                      _buildHealthScoreCard(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Key Insights
                      _buildKeyInsights(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Overview Metrics
                      _buildOverviewMetrics(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Category Breakdown
                      _buildCategoryBreakdown(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Color Analysis
                      _buildColorAnalysis(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Usage Metrics
                      _buildUsageMetrics(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Value Metrics
                      _buildValueMetrics(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Style Insights
                      _buildStyleInsights(),
                      
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Trends
                      _buildTrends(),
                    ],
                  ),
                ),
    );
  }
  
  Widget _buildHealthScoreCard() {
    final healthScore = _analytics!.overallHealthScore;
    final scoreColor = healthScore >= 0.8 
        ? AppColors.success 
        : healthScore >= 0.6 
            ? AppColors.warning 
            : AppColors.error;
    
    return AppFadeAnimation(
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            children: [
              Text(
                'Wardrobe Health Score',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 150,
                width: 150,
                child: Stack(
                  children: [
                    CircularProgressIndicator(
                      value: healthScore,
                      strokeWidth: 12,
                      backgroundColor: AppColors.backgroundSecondary,
                      valueColor: AlwaysStoppedAnimation<Color>(scoreColor),
                    ),
                    Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            '${(healthScore * 100).toInt()}%',
                            style: AppTextStyles.h1.copyWith(
                              color: scoreColor,
                            ),
                          ),
                          Text(
                            _getHealthScoreLabel(healthScore),
                            style: AppTextStyles.labelMedium,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Score breakdown
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _buildScoreIndicator('Utilization', _analytics!.usageMetrics.utilizationRate),
                  _buildScoreIndicator('Value', _analytics!.valueMetrics.valueEfficiencyScore),
                  _buildScoreIndicator('Style', _analytics!.styleInsights.styleConsistencyScore),
                  _buildScoreIndicator('Versatility', _analytics!.styleInsights.versatilityScore),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildScoreIndicator(String label, double score) {
    return Column(
      children: [
        Text(
          '${(score * 100).toInt()}%',
          style: AppTextStyles.labelLarge.copyWith(
            color: score >= 0.7 ? AppColors.success : AppColors.warning,
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
  
  Widget _buildKeyInsights() {
    final insights = _analytics!.topInsights;
    
    if (insights.isEmpty) return const SizedBox.shrink();
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Key Insights',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingM),
              ...insights.map((insight) => Padding(
                padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      Icons.lightbulb_outline,
                      color: AppColors.warning,
                      size: 20,
                    ),
                    const SizedBox(width: AppDimensions.paddingS),
                    Expanded(
                      child: Text(
                        insight,
                        style: AppTextStyles.bodyMedium,
                      ),
                    ),
                  ],
                ),
              )).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildOverviewMetrics() {
    final overview = _analytics!.overview;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Overview',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              GridView.count(
                crossAxisCount: 2,
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                childAspectRatio: 2.5,
                crossAxisSpacing: AppDimensions.paddingM,
                mainAxisSpacing: AppDimensions.paddingM,
                children: [
                  _buildMetricTile('Total Items', overview.totalGarments.toString()),
                  _buildMetricTile('Active Items', overview.activeGarments.toString()),
                  _buildMetricTile('Total Value', '\$${overview.totalValue.toStringAsFixed(0)}'),
                  _buildMetricTile('Avg. Value', '\$${overview.averageGarmentValue.toStringAsFixed(0)}'),
                  _buildMetricTile('Brands', overview.uniqueBrands.toString()),
                  _buildMetricTile('Colors', overview.uniqueColors.toString()),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildMetricTile(String label, String value) {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      decoration: BoxDecoration(
        color: AppColors.backgroundSecondary,
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(
            value,
            style: AppTextStyles.h3,
          ),
          Text(
            label,
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildCategoryBreakdown() {
    final categories = _analytics!.categoryBreakdown;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 300),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Category Breakdown',
                    style: AppTextStyles.h3,
                  ),
                  TextButton(
                    onPressed: () {
                      context.push('/analytics/categories/${widget.wardrobeId}');
                    },
                    child: const Text('Details'),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              SizedBox(
                height: 200,
                child: PieChart(
                  PieChartData(
                    sections: categories.categories.map((category) {
                      return PieChartSectionData(
                        color: _getCategoryColor(category.category),
                        value: category.percentage * 100,
                        title: '${(category.percentage * 100).toInt()}%',
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
                children: categories.categories.map((category) {
                  return Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 12,
                        height: 12,
                        decoration: BoxDecoration(
                          color: _getCategoryColor(category.category),
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        '${category.category} (${category.count})',
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
  
  Widget _buildColorAnalysis() {
    final colors = _analytics!.colorAnalysis;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 400),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Color Analysis',
                    style: AppTextStyles.h3,
                  ),
                  TextButton(
                    onPressed: () {
                      context.push('/analytics/colors/${widget.wardrobeId}');
                    },
                    child: const Text('Details'),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Color palette
              Container(
                height: 60,
                child: ListView.builder(
                  scrollDirection: Axis.horizontal,
                  itemCount: colors.colors.length,
                  itemBuilder: (context, index) {
                    final color = colors.colors[index];
                    return Container(
                      width: 60,
                      margin: const EdgeInsets.only(right: AppDimensions.paddingS),
                      decoration: BoxDecoration(
                        color: Color(int.parse(color.hexCode.replaceAll('#', '0xFF'))),
                        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                        border: Border.all(
                          color: AppColors.backgroundSecondary,
                          width: 2,
                        ),
                      ),
                      child: Center(
                        child: Text(
                          '${color.count}',
                          style: AppTextStyles.caption.copyWith(
                            color: _getContrastingColor(color.hexCode),
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Color harmony score
              Row(
                children: [
                  Icon(
                    Icons.palette,
                    color: AppColors.primary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Color Harmony: ${colors.colorHarmony.harmonyType}',
                    style: AppTextStyles.labelMedium,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingS),
              LinearProgressIndicator(
                value: colors.colorHarmony.harmonyScore,
                backgroundColor: AppColors.backgroundSecondary,
                valueColor: AlwaysStoppedAnimation<Color>(
                  colors.colorHarmony.harmonyScore >= 0.7 
                      ? AppColors.success 
                      : AppColors.warning,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildUsageMetrics() {
    final usage = _analytics!.usageMetrics;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 500),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Usage Patterns',
                    style: AppTextStyles.h3,
                  ),
                  TextButton(
                    onPressed: () {
                      context.push('/analytics/usage/${widget.wardrobeId}');
                    },
                    child: const Text('Details'),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Key metrics
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceAround,
                children: [
                  _buildUsageMetric(
                    'Avg. Wears',
                    usage.averageWearFrequency.toStringAsFixed(1),
                    Icons.refresh,
                  ),
                  _buildUsageMetric(
                    'Total Wears',
                    usage.totalWears.toString(),
                    Icons.checkroom,
                  ),
                  _buildUsageMetric(
                    'Unworn',
                    usage.unwornItems.toString(),
                    Icons.warning_amber,
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Most worn items
              Text(
                'Most Worn Items',
                style: AppTextStyles.labelLarge,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              ...usage.mostWorn.take(3).map((item) => ListTile(
                leading: CircleAvatar(
                  backgroundColor: AppColors.primary.withOpacity(0.1),
                  child: Text(
                    item.timesWorn.toString(),
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.primary,
                    ),
                  ),
                ),
                title: Text(item.name),
                subtitle: Text(item.category),
                trailing: Text(
                  '\$${item.costPerWear.toStringAsFixed(2)}/wear',
                  style: AppTextStyles.caption.copyWith(
                    color: AppColors.success,
                  ),
                ),
              )).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildUsageMetric(String label, String value, IconData icon) {
    return Column(
      children: [
        Icon(
          icon,
          color: AppColors.textSecondary,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Text(
          value,
          style: AppTextStyles.h3,
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
  
  Widget _buildValueMetrics() {
    final value = _analytics!.valueMetrics;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 600),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Value Analysis',
                    style: AppTextStyles.h3,
                  ),
                  TextButton(
                    onPressed: () {
                      context.push('/analytics/value/${widget.wardrobeId}');
                    },
                    child: const Text('Details'),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Cost per wear
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: AppColors.primary.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Average Cost Per Wear',
                          style: AppTextStyles.labelMedium,
                        ),
                        Text(
                          '\$${value.averageCostPerWear.toStringAsFixed(2)}',
                          style: AppTextStyles.h2.copyWith(
                            color: AppColors.primary,
                          ),
                        ),
                      ],
                    ),
                    Icon(
                      Icons.trending_down,
                      color: AppColors.success,
                      size: 32,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Value distribution
              Text(
                'Investment Distribution',
                style: AppTextStyles.labelLarge,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              SizedBox(
                height: 150,
                child: BarChart(
                  BarChartData(
                    alignment: BarChartAlignment.spaceAround,
                    maxY: value.costPerWearByCategory.values.reduce((a, b) => a > b ? a : b) * 1.2,
                    barGroups: value.costPerWearByCategory.entries.map((entry) {
                      final index = value.costPerWearByCategory.keys.toList().indexOf(entry.key);
                      return BarChartGroupData(
                        x: index,
                        barRods: [
                          BarChartRodData(
                            toY: entry.value,
                            color: AppColors.primary,
                            width: 20,
                            borderRadius: BorderRadius.circular(4),
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
                            final categories = value.costPerWearByCategory.keys.toList();
                            if (value.toInt() < categories.length) {
                              return Text(
                                categories[value.toInt()].split(' ').first,
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
                    gridData: FlGridData(show: false),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildStyleInsights() {
    final style = _analytics!.styleInsights;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 700),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Style Profile',
                    style: AppTextStyles.h3,
                  ),
                  TextButton(
                    onPressed: () {
                      context.push('/analytics/style/${widget.wardrobeId}');
                    },
                    child: const Text('Details'),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Dominant style
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
                child: Row(
                  children: [
                    Icon(
                      Icons.style,
                      color: AppColors.primary,
                      size: 32,
                    ),
                    const SizedBox(width: AppDimensions.paddingM),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Your Style',
                            style: AppTextStyles.caption.copyWith(
                              color: AppColors.textSecondary,
                            ),
                          ),
                          Text(
                            style.dominantStyle,
                            style: AppTextStyles.h3,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Style personalities
              Text(
                'Style Personalities',
                style: AppTextStyles.labelLarge,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Wrap(
                spacing: AppDimensions.paddingS,
                children: style.stylePersonalities.map((personality) => Chip(
                  label: Text(personality),
                  backgroundColor: AppColors.primary.withOpacity(0.1),
                )).toList(),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              // Recommendations
              if (style.recommendations.isNotEmpty) ...[
                Text(
                  'Recommendations',
                  style: AppTextStyles.labelLarge,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                ...style.recommendations.take(2).map((rec) => ListTile(
                  leading: Icon(
                    Icons.lightbulb_outline,
                    color: AppColors.warning,
                  ),
                  title: Text(rec.recommendation),
                  subtitle: Text(rec.reason),
                  contentPadding: EdgeInsets.zero,
                )).toList(),
              ],
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildTrends() {
    final trends = _analytics!.trends;
    
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 800),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingL),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Trends',
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingL),
              ...trends.map((trend) => Container(
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
                          trend.metric,
                          style: AppTextStyles.labelLarge,
                        ),
                        Row(
                          children: [
                            Icon(
                              trend.direction == TrendDirection.up
                                  ? Icons.trending_up
                                  : trend.direction == TrendDirection.down
                                      ? Icons.trending_down
                                      : Icons.trending_flat,
                              color: trend.direction == TrendDirection.up
                                  ? AppColors.success
                                  : trend.direction == TrendDirection.down
                                      ? AppColors.error
                                      : AppColors.textSecondary,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              '${trend.changePercentage > 0 ? '+' : ''}${trend.changePercentage.toStringAsFixed(1)}%',
                              style: AppTextStyles.labelMedium.copyWith(
                                color: trend.changePercentage > 0
                                    ? AppColors.success
                                    : trend.changePercentage < 0
                                        ? AppColors.error
                                        : AppColors.textSecondary,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      trend.insight,
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
              )).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  String _getHealthScoreLabel(double score) {
    if (score >= 0.9) return 'Excellent';
    if (score >= 0.8) return 'Very Good';
    if (score >= 0.7) return 'Good';
    if (score >= 0.6) return 'Fair';
    return 'Needs Attention';
  }
  
  Color _getCategoryColor(String category) {
    final colors = {
      'Tops': AppColors.primary,
      'Bottoms': AppColors.secondary,
      'Outerwear': AppColors.tertiary,
      'Shoes': AppColors.warning,
      'Accessories': AppColors.info,
    };
    
    return colors[category] ?? AppColors.textSecondary;
  }
  
  Color _getContrastingColor(String hexCode) {
    final color = Color(int.parse(hexCode.replaceAll('#', '0xFF')));
    final luminance = color.computeLuminance();
    return luminance > 0.5 ? Colors.black : Colors.white;
  }
}