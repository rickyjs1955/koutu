import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/shopping_recommendation_provider.dart';
import 'package:koutu/services/notification/shopping_recommendation_service.dart';
import 'package:koutu/widgets/common/error_view.dart';
import 'package:koutu/widgets/common/loading_indicator.dart';
import 'package:intl/intl.dart';

class ShoppingRecommendationsScreen extends ConsumerStatefulWidget {
  const ShoppingRecommendationsScreen({super.key});

  @override
  ConsumerState<ShoppingRecommendationsScreen> createState() => 
      _ShoppingRecommendationsScreenState();
}

class _ShoppingRecommendationsScreenState 
    extends ConsumerState<ShoppingRecommendationsScreen> {
  ShoppingCategory? _selectedCategory;
  PriceRange? _selectedPriceRange;
  final _currencyFormat = NumberFormat.currency(symbol: '\$');
  
  @override
  Widget build(BuildContext context) {
    final analysisAsync = ref.watch(wardrobeAnalysisProvider);
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Shopping Recommendations'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => const ShoppingSettingsScreen(),
                ),
              );
            },
          ),
        ],
      ),
      body: analysisAsync.when(
        data: (analysis) => _buildContent(analysis),
        loading: () => const Center(child: LoadingIndicator()),
        error: (error, stack) => ErrorView(
          error: error.toString(),
          onRetry: () => ref.refresh(wardrobeAnalysisProvider),
        ),
      ),
    );
  }
  
  Widget _buildContent(WardrobeAnalysis analysis) {
    return RefreshIndicator(
      onRefresh: () async {
        ref.refresh(wardrobeAnalysisProvider);
      },
      child: CustomScrollView(
        slivers: [
          // Wardrobe overview
          SliverToBoxAdapter(
            child: _WardrobeOverviewCard(analysis: analysis),
          ),
          
          // Filters
          SliverToBoxAdapter(
            child: _buildFilters(),
          ),
          
          // Deals section
          SliverToBoxAdapter(
            child: _buildDealsSection(),
          ),
          
          // Recommendations
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'RECOMMENDATIONS',
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
          ),
          
          _buildRecommendationsList(),
        ],
      ),
    );
  }
  
  Widget _buildFilters() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Expanded(
            child: _FilterChip(
              label: _selectedCategory?.name ?? 'All Categories',
              onTap: _showCategoryFilter,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: _FilterChip(
              label: _selectedPriceRange?.name ?? 'All Prices',
              onTap: _showPriceFilter,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildDealsSection() {
    final dealsAsync = ref.watch(shoppingDealsProvider);
    
    return dealsAsync.when(
      data: (deals) {
        if (deals.isEmpty) return const SizedBox.shrink();
        
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    '🔥 HOT DEALS',
                    style: Theme.of(context).textTheme.labelLarge,
                  ),
                  TextButton(
                    onPressed: () {
                      // Navigate to deals screen
                    },
                    child: const Text('See All'),
                  ),
                ],
              ),
            ),
            SizedBox(
              height: 160,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: deals.length,
                itemBuilder: (context, index) {
                  final deal = deals[index];
                  return _DealCard(deal: deal);
                },
              ),
            ),
            const SizedBox(height: 16),
          ],
        );
      },
      loading: () => const SizedBox.shrink(),
      error: (_, __) => const SizedBox.shrink(),
    );
  }
  
  Widget _buildRecommendationsList() {
    final params = ShoppingRecommendationParams(
      category: _selectedCategory,
      priceRange: _selectedPriceRange,
    );
    
    final recommendationsAsync = ref.watch(
      shoppingRecommendationsProvider(params),
    );
    
    return recommendationsAsync.when(
      data: (recommendations) {
        if (recommendations.isEmpty) {
          return SliverFillRemaining(
            child: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.shopping_bag_outlined,
                    size: 64,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No recommendations found',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  const Text('Try adjusting your filters'),
                ],
              ),
            ),
          );
        }
        
        return SliverPadding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          sliver: SliverList(
            delegate: SliverChildBuilderDelegate(
              (context, index) {
                final recommendation = recommendations[index];
                return _RecommendationCard(
                  recommendation: recommendation,
                  onAction: (action) => _handleAction(recommendation, action),
                );
              },
              childCount: recommendations.length,
            ),
          ),
        );
      },
      loading: () => const SliverFillRemaining(
        child: Center(child: CircularProgressIndicator()),
      ),
      error: (error, stack) => SliverFillRemaining(
        child: Center(
          child: Text('Error loading recommendations: $error'),
        ),
      ),
    );
  }
  
  void _showCategoryFilter() {
    showModalBottomSheet(
      context: context,
      builder: (context) {
        return Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              title: const Text('All Categories'),
              onTap: () {
                setState(() => _selectedCategory = null);
                Navigator.pop(context);
              },
              trailing: _selectedCategory == null
                  ? const Icon(Icons.check)
                  : null,
            ),
            ...ShoppingCategory.values.map((category) {
              return ListTile(
                title: Text(_formatCategory(category)),
                onTap: () {
                  setState(() => _selectedCategory = category);
                  Navigator.pop(context);
                },
                trailing: _selectedCategory == category
                    ? const Icon(Icons.check)
                    : null,
              );
            }).toList(),
          ],
        );
      },
    );
  }
  
  void _showPriceFilter() {
    showModalBottomSheet(
      context: context,
      builder: (context) {
        return Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              title: const Text('All Prices'),
              onTap: () {
                setState(() => _selectedPriceRange = null);
                Navigator.pop(context);
              },
              trailing: _selectedPriceRange == null
                  ? const Icon(Icons.check)
                  : null,
            ),
            ...PriceRange.values.map((range) {
              return ListTile(
                title: Text(_formatPriceRange(range)),
                subtitle: Text(_getPriceRangeDescription(range)),
                onTap: () {
                  setState(() => _selectedPriceRange = range);
                  Navigator.pop(context);
                },
                trailing: _selectedPriceRange == range
                    ? const Icon(Icons.check)
                    : null,
              );
            }).toList(),
          ],
        );
      },
    );
  }
  
  Future<void> _handleAction(
    ShoppingRecommendation recommendation,
    ShoppingAction action,
  ) async {
    final service = ref.read(shoppingRecommendationServiceProvider);
    final result = await service.trackShoppingAction(
      recommendationId: recommendation.id,
      action: action,
    );
    
    result.fold(
      (failure) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to track action: ${failure.message}'),
            backgroundColor: Colors.red,
          ),
        );
      },
      (_) {
        ref.refresh(shoppingRecommendationsProvider(
          ShoppingRecommendationParams(
            category: _selectedCategory,
            priceRange: _selectedPriceRange,
          ),
        ));
      },
    );
  }
  
  String _formatCategory(ShoppingCategory category) {
    switch (category) {
      case ShoppingCategory.tops:
        return 'Tops';
      case ShoppingCategory.bottoms:
        return 'Bottoms';
      case ShoppingCategory.dresses:
        return 'Dresses';
      case ShoppingCategory.outerwear:
        return 'Outerwear';
      case ShoppingCategory.footwear:
        return 'Footwear';
      case ShoppingCategory.accessories:
        return 'Accessories';
      case ShoppingCategory.activewear:
        return 'Activewear';
      case ShoppingCategory.formalwear:
        return 'Formalwear';
      case ShoppingCategory.other:
        return 'Other';
    }
  }
  
  String _formatPriceRange(PriceRange range) {
    switch (range) {
      case PriceRange.budget:
        return 'Budget';
      case PriceRange.medium:
        return 'Medium';
      case PriceRange.premium:
        return 'Premium';
      case PriceRange.luxury:
        return 'Luxury';
    }
  }
  
  String _getPriceRangeDescription(PriceRange range) {
    switch (range) {
      case PriceRange.budget:
        return 'Under \$50';
      case PriceRange.medium:
        return '\$50 - \$150';
      case PriceRange.premium:
        return '\$150 - \$500';
      case PriceRange.luxury:
        return 'Over \$500';
    }
  }
}

/// Wardrobe overview card
class _WardrobeOverviewCard extends StatelessWidget {
  final WardrobeAnalysis analysis;
  
  const _WardrobeOverviewCard({required this.analysis});
  
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.all(16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Your Wardrobe',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                Text(
                  '${analysis.totalGarments} items',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ],
            ),
            const SizedBox(height: 16),
            if (analysis.gaps.isNotEmpty) ...[
              Text(
                'Areas to Improve',
                style: Theme.of(context).textTheme.labelLarge,
              ),
              const SizedBox(height: 8),
              ...analysis.gaps.take(3).map((gap) {
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    children: [
                      Icon(
                        _getGapIcon(gap.type),
                        size: 16,
                        color: _getGapColor(gap.priority, context),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          gap.category,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ),
                      Text(
                        '${gap.currentCount}/${gap.recommendedCount}',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                );
              }).toList(),
            ],
            const SizedBox(height: 8),
            Text(
              'Last analyzed ${_formatDate(analysis.analyzedAt)}',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ],
        ),
      ),
    );
  }
  
  IconData _getGapIcon(GapType type) {
    switch (type) {
      case GapType.category:
        return Icons.category;
      case GapType.color:
        return Icons.palette;
      case GapType.seasonal:
        return Icons.ac_unit;
      case GapType.occasion:
        return Icons.event;
    }
  }
  
  Color _getGapColor(GapPriority priority, BuildContext context) {
    switch (priority) {
      case GapPriority.high:
        return Theme.of(context).colorScheme.error;
      case GapPriority.medium:
        return Theme.of(context).colorScheme.tertiary;
      case GapPriority.low:
        return Theme.of(context).colorScheme.onSurfaceVariant;
    }
  }
  
  String _formatDate(DateTime date) {
    final now = DateTime.now();
    final difference = now.difference(date);
    
    if (difference.inDays == 0) {
      return 'today';
    } else if (difference.inDays == 1) {
      return 'yesterday';
    } else if (difference.inDays < 7) {
      return '${difference.inDays} days ago';
    } else {
      return DateFormat('MMM d').format(date);
    }
  }
}

/// Deal card widget
class _DealCard extends StatelessWidget {
  final ShoppingDeal deal;
  
  const _DealCard({required this.deal});
  
  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(symbol: '\$');
    
    return Card(
      margin: const EdgeInsets.only(right: 12),
      child: InkWell(
        onTap: () {
          // Open deal
        },
        child: Container(
          width: 200,
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.error,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      '${deal.discountPercentage}% OFF',
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.onError,
                        fontWeight: FontWeight.bold,
                        fontSize: 12,
                      ),
                    ),
                  ),
                  Text(
                    _formatTimeLeft(deal.validUntil),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                deal.title,
                style: const TextStyle(fontWeight: FontWeight.bold),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const Spacer(),
              Row(
                children: [
                  Text(
                    currencyFormat.format(deal.originalPrice),
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          decoration: TextDecoration.lineThrough,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    currencyFormat.format(deal.salePrice),
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Text(
                deal.retailer,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  String _formatTimeLeft(DateTime validUntil) {
    final now = DateTime.now();
    final difference = validUntil.difference(now);
    
    if (difference.inDays > 0) {
      return '${difference.inDays}d left';
    } else if (difference.inHours > 0) {
      return '${difference.inHours}h left';
    } else {
      return 'Ending soon';
    }
  }
}

/// Recommendation card widget
class _RecommendationCard extends StatelessWidget {
  final ShoppingRecommendation recommendation;
  final Function(ShoppingAction) onAction;
  
  const _RecommendationCard({
    required this.recommendation,
    required this.onAction,
  });
  
  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(symbol: '\$');
    
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        onTap: () => onAction(ShoppingAction.viewed),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      recommendation.title,
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: _getPriorityColor(
                        recommendation.priority,
                        context,
                      ).withOpacity(0.1),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      _getPriorityLabel(recommendation.priority),
                      style: TextStyle(
                        color: _getPriorityColor(
                          recommendation.priority,
                          context,
                        ),
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                recommendation.description,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Icon(
                    Icons.category,
                    size: 16,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    _formatCategory(recommendation.category),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(width: 16),
                  Icon(
                    Icons.attach_money,
                    size: 16,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    currencyFormat.format(recommendation.estimatedPrice),
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
              if (recommendation.colors.isNotEmpty) ...[
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: recommendation.colors.map((color) {
                    return Chip(
                      label: Text(
                        color,
                        style: const TextStyle(fontSize: 12),
                      ),
                      visualDensity: VisualDensity.compact,
                    );
                  }).toList(),
                ),
              ],
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => onAction(ShoppingAction.dismissed),
                    child: const Text('Dismiss'),
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton(
                    onPressed: () => onAction(ShoppingAction.saved),
                    child: const Text('Save'),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: () => onAction(ShoppingAction.viewed),
                    child: const Text('View'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Color _getPriorityColor(double priority, BuildContext context) {
    if (priority >= 0.7) {
      return Theme.of(context).colorScheme.error;
    } else if (priority >= 0.4) {
      return Theme.of(context).colorScheme.tertiary;
    } else {
      return Theme.of(context).colorScheme.onSurfaceVariant;
    }
  }
  
  String _getPriorityLabel(double priority) {
    if (priority >= 0.7) {
      return 'HIGH';
    } else if (priority >= 0.4) {
      return 'MEDIUM';
    } else {
      return 'LOW';
    }
  }
  
  String _formatCategory(ShoppingCategory category) {
    switch (category) {
      case ShoppingCategory.tops:
        return 'Tops';
      case ShoppingCategory.bottoms:
        return 'Bottoms';
      case ShoppingCategory.dresses:
        return 'Dresses';
      case ShoppingCategory.outerwear:
        return 'Outerwear';
      case ShoppingCategory.footwear:
        return 'Footwear';
      case ShoppingCategory.accessories:
        return 'Accessories';
      case ShoppingCategory.activewear:
        return 'Activewear';
      case ShoppingCategory.formalwear:
        return 'Formalwear';
      case ShoppingCategory.other:
        return 'Other';
    }
  }
}

/// Filter chip widget
class _FilterChip extends StatelessWidget {
  final String label;
  final VoidCallback onTap;
  
  const _FilterChip({
    required this.label,
    required this.onTap,
  });
  
  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          border: Border.all(
            color: Theme.of(context).colorScheme.outline,
          ),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label),
            const Icon(Icons.arrow_drop_down, size: 20),
          ],
        ),
      ),
    );
  }
}

/// Shopping settings screen
class ShoppingSettingsScreen extends ConsumerStatefulWidget {
  const ShoppingSettingsScreen({super.key});

  @override
  ConsumerState<ShoppingSettingsScreen> createState() => 
      _ShoppingSettingsScreenState();
}

class _ShoppingSettingsScreenState 
    extends ConsumerState<ShoppingSettingsScreen> {
  late ShoppingRecommendationSettings _settings;
  final _budgetController = TextEditingController();
  
  @override
  void initState() {
    super.initState();
    _settings = ref.read(shoppingRecommendationServiceProvider).getSettings();
    _budgetController.text = _settings.monthlyBudget?.toString() ?? '';
  }
  
  @override
  void dispose() {
    _budgetController.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Shopping Settings'),
        actions: [
          TextButton(
            onPressed: _saveSettings,
            child: const Text('Save'),
          ),
        ],
      ),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Enable Recommendations'),
            subtitle: const Text('Get personalized shopping suggestions'),
            value: _settings.enabled,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(enabled: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Automatic Analysis'),
            subtitle: const Text('Analyze wardrobe weekly'),
            value: _settings.automaticAnalysis,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(automaticAnalysis: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Personalized Recommendations'),
            subtitle: const Text('Based on your style preferences'),
            value: _settings.personalizedRecommendations,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(personalizedRecommendations: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Deal Alerts'),
            subtitle: const Text('Notify about sales and discounts'),
            value: _settings.dealAlerts,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(dealAlerts: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Follow-up Reminders'),
            subtitle: const Text('Remind about saved items'),
            value: _settings.followUpReminders,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(followUpReminders: value);
              });
            },
          ),
          const Divider(),
          SwitchListTile(
            title: const Text('Budget Tracking'),
            subtitle: const Text('Track monthly shopping budget'),
            value: _settings.budgetTracking,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(budgetTracking: value);
              });
            },
          ),
          if (_settings.budgetTracking)
            ListTile(
              title: const Text('Monthly Budget'),
              subtitle: TextField(
                controller: _budgetController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  prefixText: '\$',
                  hintText: 'Enter monthly budget',
                ),
                onChanged: (value) {
                  final budget = double.tryParse(value);
                  setState(() {
                    _settings = _settings.copyWith(monthlyBudget: budget);
                  });
                },
              ),
            ),
        ],
      ),
    );
  }
  
  Future<void> _saveSettings() async {
    final service = ref.read(shoppingRecommendationServiceProvider);
    final result = await service.updateSettings(_settings);
    
    if (mounted) {
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to save settings: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Settings saved'),
            ),
          );
          Navigator.pop(context);
        },
      );
    }
  }
}