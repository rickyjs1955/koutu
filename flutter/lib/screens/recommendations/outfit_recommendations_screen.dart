import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/recommendation_provider.dart';
import 'package:koutu/services/recommendation/recommendation_engine.dart';
import 'package:koutu/widgets/common/error_view.dart';
import 'package:koutu/widgets/common/loading_indicator.dart';
import 'package:koutu/widgets/outfit/outfit_card.dart';

/// Screen for viewing outfit recommendations
class OutfitRecommendationsScreen extends ConsumerStatefulWidget {
  const OutfitRecommendationsScreen({super.key});

  @override
  ConsumerState<OutfitRecommendationsScreen> createState() => 
      _OutfitRecommendationsScreenState();
}

class _OutfitRecommendationsScreenState 
    extends ConsumerState<OutfitRecommendationsScreen> {
  String? _selectedOccasion;
  String? _selectedSeason;
  bool _considerWeather = true;
  
  final _occasions = [
    'Casual',
    'Work',
    'Formal',
    'Party',
    'Date',
    'Sports',
    'Travel',
  ];
  
  final _seasons = [
    'Spring',
    'Summer',
    'Fall',
    'Winter',
  ];
  
  @override
  void initState() {
    super.initState();
    _loadRecommendations();
  }
  
  void _loadRecommendations() {
    final context = RecommendationContext(
      occasion: _selectedOccasion,
      season: _selectedSeason,
      considerWeather: _considerWeather,
    );
    
    ref.read(recommendationEngineProvider).getOutfitRecommendations(
      context: context,
    );
  }
  
  @override
  Widget build(BuildContext context) {
    final recommendationsAsync = ref.watch(outfitRecommendationsProvider(
      RecommendationContext(
        occasion: _selectedOccasion,
        season: _selectedSeason,
        considerWeather: _considerWeather,
      ),
    ));
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Outfit Recommendations'),
        actions: [
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: _showFilterDialog,
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadRecommendations,
          ),
        ],
      ),
      body: Column(
        children: [
          // Active filters
          if (_selectedOccasion != null || _selectedSeason != null)
            Container(
              height: 40,
              margin: const EdgeInsets.symmetric(vertical: 8),
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                children: [
                  if (_selectedOccasion != null)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: Chip(
                        label: Text(_selectedOccasion!),
                        deleteIcon: const Icon(Icons.close, size: 18),
                        onDeleted: () {
                          setState(() => _selectedOccasion = null);
                          _loadRecommendations();
                        },
                      ),
                    ),
                  if (_selectedSeason != null)
                    Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: Chip(
                        label: Text(_selectedSeason!),
                        deleteIcon: const Icon(Icons.close, size: 18),
                        onDeleted: () {
                          setState(() => _selectedSeason = null);
                          _loadRecommendations();
                        },
                      ),
                    ),
                  if (_considerWeather)
                    const Chip(
                      label: Text('Weather-based'),
                      avatar: Icon(Icons.cloud, size: 18),
                    ),
                ],
              ),
            ),
          
          // Recommendations
          Expanded(
            child: recommendationsAsync.when(
              data: (recommendations) {
                if (recommendations.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.checkroom,
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
                  );
                }
                
                return RefreshIndicator(
                  onRefresh: () async => _loadRecommendations(),
                  child: ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: recommendations.length,
                    itemBuilder: (context, index) {
                      final recommendation = recommendations[index];
                      return _RecommendationCard(
                        recommendation: recommendation,
                        onFeedback: (feedback) => _provideFeedback(
                          recommendation.id,
                          feedback,
                        ),
                      );
                    },
                  ),
                );
              },
              loading: () => const Center(child: LoadingIndicator()),
              error: (error, stack) => ErrorView(
                error: error.toString(),
                onRetry: _loadRecommendations,
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  void _showFilterDialog() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (context) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (context, scrollController) {
          return StatefulBuilder(
            builder: (context, setModalState) {
              return Column(
                children: [
                  AppBar(
                    title: const Text('Filter Recommendations'),
                    automaticallyImplyLeading: false,
                    actions: [
                      TextButton(
                        onPressed: () {
                          setModalState(() {
                            _selectedOccasion = null;
                            _selectedSeason = null;
                            _considerWeather = true;
                          });
                        },
                        child: const Text('Clear'),
                      ),
                      TextButton(
                        onPressed: () {
                          Navigator.pop(context);
                          setState(() {});
                          _loadRecommendations();
                        },
                        child: const Text('Apply'),
                      ),
                    ],
                  ),
                  Expanded(
                    child: ListView(
                      controller: scrollController,
                      padding: const EdgeInsets.all(16),
                      children: [
                        // Occasion
                        Text(
                          'Occasion',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          children: _occasions.map((occasion) {
                            return ChoiceChip(
                              label: Text(occasion),
                              selected: _selectedOccasion == occasion,
                              onSelected: (selected) {
                                setModalState(() {
                                  _selectedOccasion = selected ? occasion : null;
                                });
                              },
                            );
                          }).toList(),
                        ),
                        const SizedBox(height: 24),
                        
                        // Season
                        Text(
                          'Season',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          children: _seasons.map((season) {
                            return ChoiceChip(
                              label: Text(season),
                              selected: _selectedSeason == season,
                              onSelected: (selected) {
                                setModalState(() {
                                  _selectedSeason = selected ? season : null;
                                });
                              },
                            );
                          }).toList(),
                        ),
                        const SizedBox(height: 24),
                        
                        // Weather
                        SwitchListTile(
                          title: const Text('Consider Weather'),
                          subtitle: const Text(
                            'Get recommendations based on current weather',
                          ),
                          value: _considerWeather,
                          onChanged: (value) {
                            setModalState(() => _considerWeather = value);
                          },
                        ),
                      ],
                    ),
                  ),
                ],
              );
            },
          );
        },
      ),
    );
  }
  
  void _provideFeedback(String recommendationId, RecommendationFeedback feedback) {
    ref.read(recommendationEngineProvider).provideFeedback(
      recommendationId: recommendationId,
      feedback: feedback,
    );
  }
}

/// Recommendation card widget
class _RecommendationCard extends StatelessWidget {
  final OutfitRecommendation recommendation;
  final Function(RecommendationFeedback) onFeedback;
  
  const _RecommendationCard({
    required this.recommendation,
    required this.onFeedback,
  });
  
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          ListTile(
            title: Text(
              recommendation.name,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            subtitle: Text(recommendation.reason),
            trailing: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: _getConfidenceColor(recommendation.confidence)
                    .withOpacity(0.2),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Text(
                '${(recommendation.confidence * 100).toInt()}% match',
                style: TextStyle(
                  color: _getConfidenceColor(recommendation.confidence),
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
          
          // Outfit preview
          Container(
            height: 120,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              itemCount: recommendation.garmentIds.length,
              itemBuilder: (context, index) {
                return Container(
                  width: 100,
                  margin: const EdgeInsets.only(right: 8),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceVariant,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Center(
                    child: Icon(
                      Icons.checkroom,
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                );
              },
            ),
          ),
          
          // Actions
          Padding(
            padding: const EdgeInsets.all(8),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                IconButton(
                  icon: const Icon(Icons.thumb_up_outlined),
                  onPressed: () => onFeedback(
                    const RecommendationFeedback(type: FeedbackType.like),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.thumb_down_outlined),
                  onPressed: () => onFeedback(
                    const RecommendationFeedback(type: FeedbackType.dislike),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.bookmark_outline),
                  onPressed: () => onFeedback(
                    const RecommendationFeedback(type: FeedbackType.save),
                  ),
                ),
                ElevatedButton.icon(
                  icon: const Icon(Icons.checkroom),
                  label: const Text('Wear'),
                  onPressed: () => onFeedback(
                    const RecommendationFeedback(type: FeedbackType.wear),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Color _getConfidenceColor(double confidence) {
    if (confidence >= 0.8) return Colors.green;
    if (confidence >= 0.6) return Colors.orange;
    return Colors.red;
  }
}