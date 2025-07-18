import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/recommendations/style_recommendations_widget.dart';
import 'package:koutu/presentation/widgets/weather/weather_outfit_widget.dart';
import 'package:koutu/presentation/router/route_paths.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Screen for displaying AI-powered style recommendations
class RecommendationsScreen extends StatefulWidget {
  const RecommendationsScreen({super.key});

  @override
  State<RecommendationsScreen> createState() => _RecommendationsScreenState();
}

class _RecommendationsScreenState extends State<RecommendationsScreen>
    with SingleTickerProviderStateMixin {
  bool _showIntroduction = true;
  late TabController _tabController;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadGarments();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }
  
  void _loadGarments() {
    context.read<GarmentBloc>().add(const LoadGarments());
  }
  
  void _onGarmentTap(GarmentModel garment) {
    context.push(RoutePaths.garmentDetail(garment.id));
  }
  
  void _onOutfitTap(List<GarmentModel> garments) {
    // TODO: Navigate to outfit view or show outfit details
    _showOutfitDialog(garments);
  }
  
  void _showOutfitDialog(List<GarmentModel> garments) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Recommended Outfit'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('This outfit includes:'),
            const SizedBox(height: AppDimensions.paddingS),
            ...garments.map((garment) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Row(
                children: [
                  Icon(
                    Icons.checkroom,
                    size: 16,
                    color: AppColors.textSecondary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Expanded(
                    child: Text(
                      garment.name,
                      style: AppTextStyles.bodyMedium,
                    ),
                  ),
                ],
              ),
            )).toList(),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Add to favorites or create outfit
            },
            child: const Text('Save Outfit'),
          ),
        ],
      ),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Style Recommendations',
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadGarments,
          ),
          IconButton(
            icon: Icon(_showIntroduction ? Icons.help_outline : Icons.help),
            onPressed: () {
              setState(() {
                _showIntroduction = !_showIntroduction;
              });
            },
          ),
        ],
      ),
      body: BlocBuilder<GarmentBloc, GarmentState>(
        builder: (context, garmentState) {
          return BlocBuilder<AuthBloc, AuthState>(
            builder: (context, authState) {
              if (garmentState is GarmentLoading && garmentState.garments.isEmpty) {
                return const Center(
                  child: AppLoadingIndicator(),
                );
              }
              
              if (garmentState is GarmentError && garmentState.garments.isEmpty) {
                return AppErrorWidget(
                  errorType: ErrorType.generic,
                  message: garmentState.message,
                  onRetry: _loadGarments,
                );
              }
              
              if (garmentState.garments.isEmpty) {
                return _buildEmptyState();
              }
              
              return Column(
                children: [
                  // Introduction section
                  if (_showIntroduction)
                    _buildIntroduction(),
                  
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
                      labelColor: AppColors.primary,
                      unselectedLabelColor: AppColors.textSecondary,
                      indicatorColor: AppColors.primary,
                      tabs: const [
                        Tab(
                          icon: Icon(Icons.wb_sunny),
                          text: 'Weather',
                        ),
                        Tab(
                          icon: Icon(Icons.auto_awesome),
                          text: 'AI Style',
                        ),
                      ],
                    ),
                  ),
                  
                  // Recommendations
                  Expanded(
                    child: authState.whenOrNull(
                      authenticated: (user) => TabBarView(
                        controller: _tabController,
                        children: [
                          WeatherOutfitWidget(
                            garments: garmentState.garments,
                            onOutfitTap: _onOutfitTap,
                            onGarmentTap: _onGarmentTap,
                          ),
                          StyleRecommendationsWidget(
                            garments: garmentState.garments,
                            user: user,
                            onGarmentTap: _onGarmentTap,
                            onOutfitTap: _onOutfitTap,
                          ),
                        ],
                      ),
                    ) ?? const Center(
                      child: Text('Please sign in to get personalized recommendations'),
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
  
  Widget _buildIntroduction() {
    return Container(
      margin: const EdgeInsets.all(AppDimensions.paddingM),
      padding: const EdgeInsets.all(AppDimensions.paddingL),
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
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingS),
                decoration: BoxDecoration(
                  color: AppColors.primary,
                  borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                ),
                child: const Icon(
                  Icons.auto_awesome,
                  color: Colors.white,
                  size: 20,
                ),
              ),
              const SizedBox(width: AppDimensions.paddingM),
              Expanded(
                child: Text(
                  'AI-Powered Style Recommendations',
                  style: AppTextStyles.h3.copyWith(
                    color: AppColors.primary,
                  ),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.close),
                onPressed: () {
                  setState(() {
                    _showIntroduction = false;
                  });
                },
              ),
            ],
          ),
          
          const SizedBox(height: AppDimensions.paddingM),
          
          Text(
            'Get personalized style suggestions based on your wardrobe and preferences:',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          
          const SizedBox(height: AppDimensions.paddingM),
          
          // Feature list
          ..._buildFeatureList(),
          
          const SizedBox(height: AppDimensions.paddingM),
          
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.1),
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.lightbulb_outline,
                  color: AppColors.primary,
                  size: 20,
                ),
                const SizedBox(width: AppDimensions.paddingS),
                Expanded(
                  child: Text(
                    'Tip: The more you use your garments, the better our recommendations become!',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.primary,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  List<Widget> _buildFeatureList() {
    final features = [
      {
        'icon': Icons.checkroom,
        'title': 'Smart Outfit Combos',
        'description': 'AI-curated outfit combinations from your wardrobe',
      },
      {
        'icon': Icons.favorite,
        'title': 'Similar Items',
        'description': 'Discover pieces similar to your favorites',
      },
      {
        'icon': Icons.palette,
        'title': 'Color Harmony',
        'description': 'Perfect color matches and complementary pieces',
      },
      {
        'icon': Icons.wb_sunny,
        'title': 'Seasonal Trends',
        'description': 'Season-appropriate recommendations',
      },
    ];
    
    return features.map((feature) => Padding(
      padding: const EdgeInsets.only(bottom: AppDimensions.paddingS),
      child: Row(
        children: [
          Icon(
            feature['icon'] as IconData,
            size: 20,
            color: AppColors.primary,
          ),
          const SizedBox(width: AppDimensions.paddingM),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  feature['title'] as String,
                  style: AppTextStyles.labelMedium.copyWith(
                    color: AppColors.textPrimary,
                  ),
                ),
                Text(
                  feature['description'] as String,
                  style: AppTextStyles.caption.copyWith(
                    color: AppColors.textSecondary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    )).toList();
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.checkroom_outlined,
              size: 80,
              color: AppColors.textTertiary,
            ),
            const SizedBox(height: AppDimensions.paddingL),
            Text(
              'Build Your Wardrobe First',
              style: AppTextStyles.h2,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Text(
              'Add garments to your wardrobe to get personalized style recommendations powered by AI.',
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: AppDimensions.paddingXL),
            ElevatedButton.icon(
              onPressed: () {
                context.go(RoutePaths.wardrobes);
              },
              icon: const Icon(Icons.add),
              label: const Text('Add Garments'),
            ),
          ],
        ),
      ),
    );
  }
}