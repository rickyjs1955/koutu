import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';
import 'package:koutu/presentation/widgets/common/app_button.dart';
import 'dart:math' as math;

class AIOutfitBuilderScreen extends StatefulWidget {
  const AIOutfitBuilderScreen({Key? key}) : super(key: key);

  @override
  State<AIOutfitBuilderScreen> createState() => _AIOutfitBuilderScreenState();
}

class _AIOutfitBuilderScreenState extends State<AIOutfitBuilderScreen> 
    with TickerProviderStateMixin {
  late AnimationController _floatingController;
  late AnimationController _pulseController;
  
  String _selectedOccasion = 'Casual';
  String _selectedWeather = 'Sunny';
  String _selectedStyle = 'Trendy';
  bool _isGenerating = false;
  
  final List<String> _occasions = ['Casual', 'Business', 'Party', 'Date', 'Sport', 'Formal'];
  final List<String> _weatherOptions = ['Sunny', 'Cloudy', 'Rainy', 'Cold', 'Hot'];
  final List<String> _stylePreferences = ['Trendy', 'Classic', 'Minimalist', 'Bold', 'Comfortable'];
  
  // Selected garments for outfit
  Map<String, dynamic>? _topGarment;
  Map<String, dynamic>? _bottomGarment;
  Map<String, dynamic>? _shoesGarment;
  Map<String, dynamic>? _accessoryGarment;

  @override
  void initState() {
    super.initState();
    _floatingController = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat(reverse: true);
    
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    )..repeat();
  }

  @override
  void dispose() {
    _floatingController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _generateAIOutfit() async {
    setState(() {
      _isGenerating = true;
    });

    // Simulate AI processing
    await Future.delayed(const Duration(seconds: 3));

    // Mock AI-generated outfit
    setState(() {
      _topGarment = {
        'name': 'Classic White Shirt',
        'category': 'Top',
        'color': 'White',
      };
      _bottomGarment = {
        'name': 'Dark Blue Jeans',
        'category': 'Bottom',
        'color': 'Blue',
      };
      _shoesGarment = {
        'name': 'White Sneakers',
        'category': 'Shoes',
        'color': 'White',
      };
      _accessoryGarment = {
        'name': 'Brown Leather Watch',
        'category': 'Accessory',
        'color': 'Brown',
      };
      _isGenerating = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.backgroundLight,
      appBar: AppBar(
        title: Text('AI Outfit Builder', style: AppTextStyles.h3),
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: AppColors.textPrimary),
          onPressed: () => context.pop(),
        ),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            _buildAIHeader(),
            _buildPreferencesSection(),
            _buildOutfitDisplay(),
            _buildGenerateButton(),
            if (_topGarment != null) _buildSaveSection(),
          ],
        ),
      ),
    );
  }

  Widget _buildAIHeader() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      child: Column(
        children: [
          AnimatedBuilder(
            animation: _floatingController,
            builder: (context, child) {
              return Transform.translate(
                offset: Offset(0, math.sin(_floatingController.value * math.pi) * 10),
                child: child,
              );
            },
            child: Container(
              width: 120,
              height: 120,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    AppColors.primary,
                    AppColors.primary.withOpacity(0.6),
                  ],
                ),
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: AppColors.primary.withOpacity(0.3),
                    blurRadius: 20,
                    spreadRadius: 5,
                  ),
                ],
              ),
              child: const Icon(
                Icons.auto_awesome,
                size: 60,
                color: Colors.white,
              ),
            ),
          ),
          const SizedBox(height: AppDimensions.spacingLarge),
          Text(
            'AI Fashion Assistant',
            style: AppTextStyles.h2,
          ),
          const SizedBox(height: AppDimensions.spacingSmall),
          Text(
            'Let AI create the perfect outfit for you',
            style: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildPreferencesSection() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingLarge),
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.05),
            blurRadius: 10,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Your Preferences', style: AppTextStyles.subtitle1),
          const SizedBox(height: AppDimensions.spacingMedium),
          
          // Occasion
          _buildPreferenceSelector(
            label: 'Occasion',
            icon: Icons.event,
            options: _occasions,
            selected: _selectedOccasion,
            onSelected: (value) => setState(() => _selectedOccasion = value),
          ),
          
          const SizedBox(height: AppDimensions.spacingMedium),
          
          // Weather
          _buildPreferenceSelector(
            label: 'Weather',
            icon: Icons.wb_sunny,
            options: _weatherOptions,
            selected: _selectedWeather,
            onSelected: (value) => setState(() => _selectedWeather = value),
          ),
          
          const SizedBox(height: AppDimensions.spacingMedium),
          
          // Style
          _buildPreferenceSelector(
            label: 'Style',
            icon: Icons.style,
            options: _stylePreferences,
            selected: _selectedStyle,
            onSelected: (value) => setState(() => _selectedStyle = value),
          ),
        ],
      ),
    );
  }

  Widget _buildPreferenceSelector({
    required String label,
    required IconData icon,
    required List<String> options,
    required String selected,
    required Function(String) onSelected,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, size: 20, color: AppColors.primary),
            const SizedBox(width: 8),
            Text(label, style: AppTextStyles.caption),
          ],
        ),
        const SizedBox(height: 8),
        SizedBox(
          height: 35,
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            itemCount: options.length,
            separatorBuilder: (context, index) => const SizedBox(width: 8),
            itemBuilder: (context, index) {
              final option = options[index];
              final isSelected = option == selected;
              
              return InkWell(
                onTap: () => onSelected(option),
                borderRadius: BorderRadius.circular(20),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  decoration: BoxDecoration(
                    color: isSelected ? AppColors.primary : AppColors.backgroundLight,
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: isSelected ? AppColors.primary : AppColors.divider,
                    ),
                  ),
                  child: Text(
                    option,
                    style: AppTextStyles.caption.copyWith(
                      color: isSelected ? Colors.white : AppColors.textPrimary,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildOutfitDisplay() {
    if (_isGenerating) {
      return _buildGeneratingAnimation();
    }

    if (_topGarment == null) {
      return Container(
        height: 300,
        margin: const EdgeInsets.all(AppDimensions.paddingLarge),
        decoration: BoxDecoration(
          border: Border.all(color: AppColors.divider, style: BorderStyle.dashed),
          borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
        ),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.checkroom_outlined,
                size: 80,
                color: AppColors.textSecondary.withOpacity(0.5),
              ),
              const SizedBox(height: AppDimensions.spacingMedium),
              Text(
                'Your AI outfit will appear here',
                style: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
              ),
            ],
          ),
        ),
      );
    }

    return Container(
      margin: const EdgeInsets.all(AppDimensions.paddingLarge),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('AI Generated Outfit', style: AppTextStyles.subtitle1),
          const SizedBox(height: AppDimensions.spacingMedium),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _buildGarmentSlot('Top', _topGarment),
              _buildGarmentSlot('Bottom', _bottomGarment),
            ],
          ),
          const SizedBox(height: AppDimensions.spacingMedium),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _buildGarmentSlot('Shoes', _shoesGarment),
              _buildGarmentSlot('Accessory', _accessoryGarment),
            ],
          ),
          const SizedBox(height: AppDimensions.spacingLarge),
          _buildAIExplanation(),
        ],
      ),
    );
  }

  Widget _buildGarmentSlot(String type, Map<String, dynamic>? garment) {
    return Column(
      children: [
        Container(
          width: 150,
          height: 150,
          decoration: BoxDecoration(
            color: garment != null ? AppColors.surface : AppColors.divider,
            borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
            border: Border.all(
              color: garment != null ? AppColors.primary.withOpacity(0.3) : AppColors.divider,
            ),
          ),
          child: garment != null
              ? Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      _getIconForType(type),
                      size: 50,
                      color: AppColors.primary,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      garment['name'],
                      style: AppTextStyles.caption,
                      textAlign: TextAlign.center,
                      maxLines: 2,
                    ),
                  ],
                )
              : Center(
                  child: Icon(
                    _getIconForType(type),
                    size: 40,
                    color: AppColors.textSecondary.withOpacity(0.5),
                  ),
                ),
        ),
        const SizedBox(height: 8),
        Text(
          type,
          style: AppTextStyles.caption.copyWith(color: AppColors.textSecondary),
        ),
      ],
    );
  }

  IconData _getIconForType(String type) {
    switch (type) {
      case 'Top':
        return Icons.dry_cleaning;
      case 'Bottom':
        return Icons.straighten;
      case 'Shoes':
        return Icons.directions_walk;
      case 'Accessory':
        return Icons.watch;
      default:
        return Icons.checkroom;
    }
  }

  Widget _buildGeneratingAnimation() {
    return Container(
      height: 300,
      margin: const EdgeInsets.all(AppDimensions.paddingLarge),
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            AnimatedBuilder(
              animation: _pulseController,
              builder: (context, child) {
                return Container(
                  width: 100,
                  height: 100,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: AppColors.primary.withOpacity(0.1),
                    boxShadow: [
                      BoxShadow(
                        color: AppColors.primary.withOpacity(0.3 * _pulseController.value),
                        blurRadius: 20 * _pulseController.value,
                        spreadRadius: 10 * _pulseController.value,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.auto_awesome,
                    size: 50,
                    color: AppColors.primary,
                  ),
                );
              },
            ),
            const SizedBox(height: AppDimensions.spacingLarge),
            Text(
              'AI is creating your perfect outfit...',
              style: AppTextStyles.body1,
            ),
            const SizedBox(height: AppDimensions.spacingSmall),
            SizedBox(
              width: 200,
              child: LinearProgressIndicator(
                backgroundColor: AppColors.divider,
                valueColor: AlwaysStoppedAnimation<Color>(AppColors.primary),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAIExplanation() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingMedium),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            AppColors.primary.withOpacity(0.1),
            AppColors.primary.withOpacity(0.05),
          ],
        ),
        borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.psychology, color: AppColors.primary),
              const SizedBox(width: 8),
              Text('AI Analysis', style: AppTextStyles.subtitle2),
            ],
          ),
          const SizedBox(height: AppDimensions.spacingSmall),
          Text(
            'This outfit combination is perfect for a $_selectedOccasion occasion in $_selectedWeather weather. '
            'The $_selectedStyle style is achieved through complementary colors and balanced proportions. '
            'The outfit scores 95% in style coherence and weather appropriateness.',
            style: AppTextStyles.caption,
          ),
        ],
      ),
    );
  }

  Widget _buildGenerateButton() {
    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: AppDimensions.paddingLarge,
        vertical: AppDimensions.paddingMedium,
      ),
      child: AppButton(
        text: _topGarment == null ? 'Generate Outfit' : 'Regenerate',
        onPressed: _isGenerating ? null : _generateAIOutfit,
        isFullWidth: true,
        icon: Icons.auto_awesome,
        isLoading: _isGenerating,
      ),
    );
  }

  Widget _buildSaveSection() {
    return Container(
      margin: const EdgeInsets.all(AppDimensions.paddingLarge),
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Expanded(
                child: AppButton(
                  text: 'Save Outfit',
                  onPressed: () {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Outfit saved to your collection!'),
                        backgroundColor: Colors.green,
                      ),
                    );
                  },
                  icon: Icons.bookmark,
                  variant: AppButtonVariant.outlined,
                ),
              ),
              const SizedBox(width: AppDimensions.spacingMedium),
              Expanded(
                child: AppButton(
                  text: 'Wear Today',
                  onPressed: () {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Outfit marked as worn today!'),
                        backgroundColor: AppColors.primary,
                      ),
                    );
                  },
                  icon: Icons.calendar_today,
                ),
              ),
            ],
          ),
          const SizedBox(height: AppDimensions.spacingMedium),
          AppButton(
            text: 'Share Outfit',
            onPressed: () {},
            icon: Icons.share,
            variant: AppButtonVariant.text,
          ),
        ],
      ),
    );
  }
}