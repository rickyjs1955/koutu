import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/services/weather/weather_outfit_service.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

/// Widget for displaying weather-appropriate outfit recommendations
class WeatherOutfitWidget extends StatefulWidget {
  final List<GarmentModel> garments;
  final Function(List<GarmentModel>) onOutfitTap;
  final Function(GarmentModel) onGarmentTap;
  
  const WeatherOutfitWidget({
    super.key,
    required this.garments,
    required this.onOutfitTap,
    required this.onGarmentTap,
  });

  @override
  State<WeatherOutfitWidget> createState() => _WeatherOutfitWidgetState();
}

class _WeatherOutfitWidgetState extends State<WeatherOutfitWidget> {
  WeatherCondition? _currentWeather;
  List<WeatherOutfitRecommendation> _recommendations = [];
  bool _isLoading = true;
  bool _showWeatherDetails = false;
  
  @override
  void initState() {
    super.initState();
    _loadWeatherOutfits();
  }
  
  void _loadWeatherOutfits() async {
    setState(() => _isLoading = true);
    
    try {
      // Get current weather
      _currentWeather = WeatherOutfitService.getCurrentWeather();
      
      // Generate weather-appropriate recommendations
      _recommendations = WeatherOutfitService.generateWeatherOutfits(
        widget.garments,
        _currentWeather!,
        maxResults: 12,
      );
      
    } catch (e) {
      debugPrint('Error loading weather outfits: $e');
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
    
    if (_currentWeather == null) {
      return _buildErrorState();
    }
    
    return Column(
      children: [
        // Weather header
        _buildWeatherHeader(),
        
        // Outfit recommendations
        Expanded(
          child: _recommendations.isEmpty
              ? _buildEmptyState()
              : _buildOutfitList(),
        ),
      ],
    );
  }
  
  Widget _buildWeatherHeader() {
    final weather = _currentWeather!;
    final temperature = weather.temperature.round();
    
    return Container(
      margin: const EdgeInsets.all(AppDimensions.paddingM),
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: _getWeatherGradient(weather.condition),
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(AppDimensions.radiusL),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.1),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        children: [
          // Current weather
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                ),
                child: Icon(
                  weather.condition.icon,
                  size: 32,
                  color: Colors.white,
                ),
              ),
              const SizedBox(width: AppDimensions.paddingM),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Today\'s Weather',
                      style: AppTextStyles.labelMedium.copyWith(
                        color: Colors.white.withOpacity(0.9),
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '${temperature}°C • ${weather.condition.displayName}',
                      style: AppTextStyles.h2.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (_showWeatherDetails) ...[\n                      const SizedBox(height: 8),\n                      Text(\n                        'Humidity: ${weather.humidity.round()}% • Wind: ${weather.windSpeed.round()} km/h',\n                        style: AppTextStyles.caption.copyWith(\n                          color: Colors.white.withOpacity(0.8),\n                        ),\n                      ),\n                    ],
                  ],
                ),
              ),
              IconButton(
                onPressed: () {
                  setState(() {
                    _showWeatherDetails = !_showWeatherDetails;
                  });
                },
                icon: Icon(
                  _showWeatherDetails ? Icons.expand_less : Icons.expand_more,
                  color: Colors.white,
                ),
              ),
            ],
          ),
          
          const SizedBox(height: AppDimensions.paddingM),
          
          // Weather summary
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.15),
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.checkroom,
                  size: 20,
                  color: Colors.white,
                ),
                const SizedBox(width: AppDimensions.paddingS),
                Expanded(
                  child: Text(
                    _getWeatherOutfitAdvice(weather),
                    style: AppTextStyles.bodyMedium.copyWith(
                      color: Colors.white,
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
  
  Widget _buildOutfitList() {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingM),
      itemCount: _recommendations.length,
      itemBuilder: (context, index) {
        final recommendation = _recommendations[index];
        
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _WeatherOutfitCard(
            recommendation: recommendation,
            onTap: () => widget.onOutfitTap(recommendation.garments),
            onGarmentTap: widget.onGarmentTap,
          ),
        );
      },
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.wb_cloudy,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Weather Outfits Found',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Add more garments to get weather-appropriate outfit suggestions',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Widget _buildErrorState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.cloud_off,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Weather Unavailable',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Unable to load weather information',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingL),
          ElevatedButton(
            onPressed: _loadWeatherOutfits,
            child: const Text('Try Again'),
          ),
        ],
      ),
    );
  }
  
  List<Color> _getWeatherGradient(WeatherType condition) {
    switch (condition) {
      case WeatherType.sunny:
        return [
          const Color(0xFFFFD700),
          const Color(0xFFFFA500),
        ];
      case WeatherType.cloudy:
        return [
          const Color(0xFF87CEEB),
          const Color(0xFF708090),
        ];
      case WeatherType.rainy:
        return [
          const Color(0xFF4682B4),
          const Color(0xFF2F4F4F),
        ];
      case WeatherType.snowy:
        return [
          const Color(0xFFB0C4DE),
          const Color(0xFF778899),
        ];
      case WeatherType.windy:
        return [
          const Color(0xFF20B2AA),
          const Color(0xFF008B8B),
        ];
      case WeatherType.foggy:
        return [
          const Color(0xFF696969),
          const Color(0xFF2F4F4F),
        ];
    }
  }
  
  String _getWeatherOutfitAdvice(WeatherCondition weather) {
    final temperature = weather.temperature.round();
    
    if (temperature < 5) {
      return 'Bundle up with warm layers and insulated outerwear';
    } else if (temperature < 15) {
      return 'Layer up with a jacket or sweater for comfort';
    } else if (temperature < 25) {
      return 'Perfect weather for versatile outfit combinations';
    } else {
      return 'Stay cool with lightweight, breathable fabrics';
    }
  }
}

class _WeatherOutfitCard extends StatelessWidget {
  final WeatherOutfitRecommendation recommendation;
  final VoidCallback onTap;
  final Function(GarmentModel) onGarmentTap;
  
  const _WeatherOutfitCard({
    required this.recommendation,
    required this.onTap,
    required this.onGarmentTap,
  });
  
  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(AppDimensions.radiusM),
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
                      color: _getScoreColor(recommendation.weatherScore),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Icon(
                      recommendation.condition.icon,
                      size: 20,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(width: AppDimensions.paddingM),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          recommendation.description,
                          style: AppTextStyles.labelLarge,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${recommendation.temperature.round()}°C • ${recommendation.condition.displayName}',
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  ),
                  // Weather score
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingS,
                      vertical: AppDimensions.paddingXS,
                    ),
                    decoration: BoxDecoration(
                      color: _getScoreColor(recommendation.weatherScore),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                    ),
                    child: Text(
                      '${(recommendation.weatherScore * 100).toInt()}%',
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
                height: 100,
                child: ListView.builder(
                  scrollDirection: Axis.horizontal,
                  itemCount: recommendation.garments.length,
                  itemBuilder: (context, index) {
                    final garment = recommendation.garments[index];
                    
                    return GestureDetector(
                      onTap: () => onGarmentTap(garment),
                      child: Container(
                        width: 80,
                        margin: const EdgeInsets.only(right: AppDimensions.paddingS),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                          border: Border.all(
                            color: AppColors.border,
                            width: 1,
                          ),
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                          child: garment.images.isNotEmpty
                              ? CachedNetworkImage(
                                  imageUrl: garment.images.first.url,
                                  fit: BoxFit.cover,
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
                      ),
                    );
                  },
                ),
              ),
              
              const SizedBox(height: AppDimensions.paddingM),
              
              // Weather reason
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingS),
                decoration: BoxDecoration(
                  color: AppColors.backgroundSecondary,
                  borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.wb_sunny_outlined,
                      size: 16,
                      color: AppColors.textSecondary,
                    ),
                    const SizedBox(width: AppDimensions.paddingS),
                    Expanded(
                      child: Text(
                        recommendation.weatherReason,
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
      ),
    );
  }
  
  Color _getScoreColor(double score) {
    if (score >= 0.8) return AppColors.success;
    if (score >= 0.6) return AppColors.warning;
    return AppColors.textSecondary;
  }
}