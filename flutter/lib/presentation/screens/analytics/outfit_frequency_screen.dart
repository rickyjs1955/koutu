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
import 'package:intl/intl.dart';

/// Screen for outfit frequency tracking and analysis
class OutfitFrequencyScreen extends StatefulWidget {
  final String wardrobeId;
  
  const OutfitFrequencyScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<OutfitFrequencyScreen> createState() => _OutfitFrequencyScreenState();
}

class _OutfitFrequencyScreenState extends State<OutfitFrequencyScreen> {
  List<OutfitFrequencyTracking> _outfits = [];
  bool _isLoading = true;
  String _sortBy = 'frequency';
  String _filterBy = 'all';
  DateTimeRange? _dateRange;
  
  @override
  void initState() {
    super.initState();
    _loadOutfitFrequency();
  }
  
  void _loadOutfitFrequency() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await WardrobeAnalyticsService.getOutfitFrequency(
        'current_user_id', // In real app, get from auth state
        widget.wardrobeId,
        startDate: _dateRange?.start,
        endDate: _dateRange?.end,
        limit: 50,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to load data: ${failure.message}')),
          );
        },
        (outfits) {
          setState(() {
            _outfits = _sortOutfits(outfits);
          });
        },
      );
    } catch (e) {
      debugPrint('Error loading outfit frequency: $e');
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  List<OutfitFrequencyTracking> _sortOutfits(List<OutfitFrequencyTracking> outfits) {
    switch (_sortBy) {
      case 'frequency':
        outfits.sort((a, b) => b.timesWorn.compareTo(a.timesWorn));
        break;
      case 'recent':
        outfits.sort((a, b) => b.lastWorn.compareTo(a.lastWorn));
        break;
      case 'satisfaction':
        outfits.sort((a, b) => b.satisfactionRating.compareTo(a.satisfactionRating));
        break;
      case 'name':
        outfits.sort((a, b) => a.name.compareTo(b.name));
        break;
    }
    
    if (_filterBy != 'all') {
      outfits = outfits.where((outfit) {
        switch (_filterBy) {
          case 'high':
            return outfit.timesWorn > 10;
          case 'medium':
            return outfit.timesWorn > 5 && outfit.timesWorn <= 10;
          case 'low':
            return outfit.timesWorn <= 5;
          default:
            return true;
        }
      }).toList();
    }
    
    return outfits;
  }
  
  void _onSortChanged(String? value) {
    if (value != null) {
      setState(() {
        _sortBy = value;
        _outfits = _sortOutfits(_outfits);
      });
    }
  }
  
  void _onFilterChanged(String? value) {
    if (value != null) {
      setState(() {
        _filterBy = value;
        _outfits = _sortOutfits(_outfits);
      });
    }
  }
  
  void _selectDateRange() async {
    final picked = await showDateRangePicker(
      context: context,
      firstDate: DateTime.now().subtract(const Duration(days: 365)),
      lastDate: DateTime.now(),
      initialDateRange: _dateRange,
    );
    
    if (picked != null) {
      setState(() {
        _dateRange = picked;
      });
      _loadOutfitFrequency();
    }
  }
  
  void _clearDateRange() {
    setState(() {
      _dateRange = null;
    });
    _loadOutfitFrequency();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Outfit Frequency',
        actions: [
          IconButton(
            icon: const Icon(Icons.calendar_today),
            onPressed: _selectDateRange,
          ),
        ],
      ),
      body: Column(
        children: [
          // Filters and sort
          _buildFilters(),
          
          // Date range indicator
          if (_dateRange != null)
            _buildDateRangeIndicator(),
          
          // Content
          Expanded(
            child: _isLoading
                ? const Center(child: AppLoadingIndicator())
                : _outfits.isEmpty
                    ? _buildEmptyState()
                    : _buildOutfitList(),
          ),
        ],
      ),
    );
  }
  
  Widget _buildFilters() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      decoration: BoxDecoration(
        color: AppColors.surface,
        border: Border(
          bottom: BorderSide(
            color: AppColors.backgroundSecondary,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Sort dropdown
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
                borderRadius: BorderRadius.circular(AppDimensions.radiusM),
              ),
              child: DropdownButton<String>(
                value: _sortBy,
                isExpanded: true,
                underline: const SizedBox(),
                items: const [
                  DropdownMenuItem(value: 'frequency', child: Text('Most Worn')),
                  DropdownMenuItem(value: 'recent', child: Text('Recently Worn')),
                  DropdownMenuItem(value: 'satisfaction', child: Text('Highest Rated')),
                  DropdownMenuItem(value: 'name', child: Text('Name')),
                ],
                onChanged: _onSortChanged,
              ),
            ),
          ),
          
          const SizedBox(width: AppDimensions.paddingM),
          
          // Filter dropdown
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
                borderRadius: BorderRadius.circular(AppDimensions.radiusM),
              ),
              child: DropdownButton<String>(
                value: _filterBy,
                isExpanded: true,
                underline: const SizedBox(),
                items: const [
                  DropdownMenuItem(value: 'all', child: Text('All Outfits')),
                  DropdownMenuItem(value: 'high', child: Text('High Frequency')),
                  DropdownMenuItem(value: 'medium', child: Text('Medium Frequency')),
                  DropdownMenuItem(value: 'low', child: Text('Low Frequency')),
                ],
                onChanged: _onFilterChanged,
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildDateRangeIndicator() {
    final formatter = DateFormat('MMM d');
    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: AppDimensions.paddingM,
        vertical: AppDimensions.paddingS,
      ),
      color: AppColors.primary.withOpacity(0.1),
      child: Row(
        children: [
          Icon(
            Icons.date_range,
            size: 16,
            color: AppColors.primary,
          ),
          const SizedBox(width: AppDimensions.paddingS),
          Text(
            '${formatter.format(_dateRange!.start)} - ${formatter.format(_dateRange!.end)}',
            style: AppTextStyles.caption.copyWith(
              color: AppColors.primary,
            ),
          ),
          const Spacer(),
          GestureDetector(
            onTap: _clearDateRange,
            child: Icon(
              Icons.close,
              size: 16,
              color: AppColors.primary,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildOutfitList() {
    // Calculate statistics
    final totalWears = _outfits.fold<int>(0, (sum, outfit) => sum + outfit.timesWorn);
    final avgWears = totalWears / _outfits.length;
    final maxWears = _outfits.map((o) => o.timesWorn).reduce((a, b) => a > b ? a : b);
    
    return ListView(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      children: [
        // Summary stats
        _buildSummaryStats(totalWears, avgWears, maxWears),
        
        const SizedBox(height: AppDimensions.paddingL),
        
        // Frequency chart
        _buildFrequencyChart(),
        
        const SizedBox(height: AppDimensions.paddingL),
        
        // Outfit list
        Text(
          'Outfit Details',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        
        ..._outfits.asMap().entries.map((entry) {
          final index = entry.key;
          final outfit = entry.value;
          return AppFadeAnimation(
            delay: Duration(milliseconds: index * 50),
            child: _buildOutfitCard(outfit),
          );
        }).toList(),
      ],
    );
  }
  
  Widget _buildSummaryStats(int totalWears, double avgWears, int maxWears) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Frequency Summary',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _buildStatItem('Total Wears', totalWears.toString()),
                _buildStatItem('Avg. Wears', avgWears.toStringAsFixed(1)),
                _buildStatItem('Max Wears', maxWears.toString()),
              ],
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildStatItem(String label, String value) {
    return Column(
      children: [
        Text(
          value,
          style: AppTextStyles.h2.copyWith(
            color: AppColors.primary,
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
  
  Widget _buildFrequencyChart() {
    final topOutfits = _outfits.take(10).toList();
    
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Top 10 Most Worn Outfits',
              style: AppTextStyles.h3,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            SizedBox(
              height: 250,
              child: BarChart(
                BarChartData(
                  alignment: BarChartAlignment.spaceAround,
                  maxY: topOutfits.first.timesWorn.toDouble() * 1.2,
                  barGroups: topOutfits.asMap().entries.map((entry) {
                    final index = entry.key;
                    final outfit = entry.value;
                    return BarChartGroupData(
                      x: index,
                      barRods: [
                        BarChartRodData(
                          toY: outfit.timesWorn.toDouble(),
                          color: AppColors.primary,
                          width: 20,
                          borderRadius: BorderRadius.circular(4),
                          backDrawRodData: BackgroundBarChartRodData(
                            show: true,
                            toY: topOutfits.first.timesWorn.toDouble() * 1.2,
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
                          if (value.toInt() < topOutfits.length) {
                            return RotatedBox(
                              quarterTurns: 1,
                              child: Text(
                                topOutfits[value.toInt()].name.length > 10
                                    ? '${topOutfits[value.toInt()].name.substring(0, 10)}...'
                                    : topOutfits[value.toInt()].name,
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
                            value.toInt().toString(),
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
          ],
        ),
      ),
    );
  }
  
  Widget _buildOutfitCard(OutfitFrequencyTracking outfit) {
    final daysSinceWorn = DateTime.now().difference(outfit.lastWorn).inDays;
    final wearRate = outfit.timesWorn / DateTime.now().difference(outfit.firstWorn).inDays * 30;
    
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: InkWell(
        onTap: () {
          context.push('/outfit/${outfit.outfitId}');
        },
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                children: [
                  Expanded(
                    child: Text(
                      outfit.name,
                      style: AppTextStyles.labelLarge,
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingS,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: _getFrequencyColor(outfit.timesWorn).withOpacity(0.1),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Text(
                      '${outfit.timesWorn} wears',
                      style: AppTextStyles.caption.copyWith(
                        color: _getFrequencyColor(outfit.timesWorn),
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ],
              ),
              
              const SizedBox(height: AppDimensions.paddingS),
              
              // Stats row
              Row(
                children: [
                  _buildOutfitStat(
                    Icons.calendar_today,
                    daysSinceWorn == 0 
                        ? 'Worn today' 
                        : '$daysSinceWorn days ago',
                  ),
                  const SizedBox(width: AppDimensions.paddingL),
                  _buildOutfitStat(
                    Icons.trending_up,
                    '${wearRate.toStringAsFixed(1)}/month',
                  ),
                  const SizedBox(width: AppDimensions.paddingL),
                  _buildOutfitStat(
                    Icons.star,
                    outfit.satisfactionRating.toStringAsFixed(1),
                  ),
                ],
              ),
              
              const SizedBox(height: AppDimensions.paddingM),
              
              // Occasion breakdown
              if (outfit.wearsByOccasion.isNotEmpty) ...[
                Text(
                  'Worn for:',
                  style: AppTextStyles.caption.copyWith(
                    color: AppColors.textSecondary,
                  ),
                ),
                const SizedBox(height: 4),
                Wrap(
                  spacing: AppDimensions.paddingS,
                  children: outfit.wearsByOccasion.entries.map((entry) => Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingS,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: AppColors.backgroundSecondary,
                      borderRadius: BorderRadius.circular(AppDimensions.radiusXS),
                    ),
                    child: Text(
                      '${entry.key} (${entry.value})',
                      style: AppTextStyles.caption,
                    ),
                  )).toList(),
                ),
              ],
              
              const SizedBox(height: AppDimensions.paddingM),
              
              // Garment count
              Row(
                children: [
                  Icon(
                    Icons.checkroom,
                    size: 16,
                    color: AppColors.textSecondary,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    '${outfit.garmentIds.length} items',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildOutfitStat(IconData icon, String value) {
    return Row(
      children: [
        Icon(
          icon,
          size: 16,
          color: AppColors.textSecondary,
        ),
        const SizedBox(width: 4),
        Text(
          value,
          style: AppTextStyles.caption.copyWith(
            color: AppColors.textSecondary,
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
            Icons.checkroom_outlined,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Outfit Data',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Start wearing and tracking your outfits',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Color _getFrequencyColor(int wears) {
    if (wears > 10) return AppColors.success;
    if (wears > 5) return AppColors.warning;
    return AppColors.error;
  }
}