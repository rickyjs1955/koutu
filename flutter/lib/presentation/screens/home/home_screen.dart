import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';
import 'package:koutu/core/routing/route_paths.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'dart:math' as math;

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with TickerProviderStateMixin {
  late AnimationController _floatingController;
  late AnimationController _fadeController;

  @override
  void initState() {
    super.initState();
    _floatingController = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat(reverse: true);
    
    _fadeController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    )..forward();
  }

  @override
  void dispose() {
    _floatingController.dispose();
    _fadeController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.backgroundLight,
      body: BlocListener<AuthBloc, AuthState>(
        listener: (context, state) {
          state.maybeWhen(
            unauthenticated: () {
              context.go(RoutePaths.login);
            },
            orElse: () {},
          );
        },
        child: CustomScrollView(
          slivers: [
            _buildSliverAppBar(),
            SliverToBoxAdapter(
              child: FadeTransition(
                opacity: _fadeController,
                child: Column(
                  children: [
                    _buildWelcomeSection(),
                    _buildQuickStats(),
                    _buildFeatureCards(),
                    const SizedBox(height: AppDimensions.spacingXLarge),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSliverAppBar() {
    return SliverAppBar(
      expandedHeight: 200,
      floating: false,
      pinned: true,
      backgroundColor: Colors.transparent,
      flexibleSpace: FlexibleSpaceBar(
        background: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [
                AppColors.primary,
                AppColors.primary.withOpacity(0.7),
              ],
            ),
          ),
          child: Stack(
            children: [
              Positioned(
                right: -50,
                top: -50,
                child: AnimatedBuilder(
                  animation: _floatingController,
                  builder: (context, child) {
                    return Transform.rotate(
                      angle: _floatingController.value * 0.5,
                      child: Icon(
                        Icons.auto_awesome,
                        size: 200,
                        color: Colors.white.withOpacity(0.1),
                      ),
                    );
                  },
                ),
              ),
              Positioned(
                left: 20,
                bottom: 20,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(
                          Icons.auto_awesome,
                          color: Colors.white,
                          size: 30,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'Koutu AI',
                          style: AppTextStyles.h1.copyWith(color: Colors.white),
                        ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Your AI-Powered Fashion Assistant',
                      style: AppTextStyles.body2.copyWith(color: Colors.white70),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
      actions: [
        IconButton(
          icon: const Icon(Icons.notifications_outlined, color: Colors.white),
          onPressed: () {},
        ),
        IconButton(
          icon: const Icon(Icons.person_outline, color: Colors.white),
          onPressed: () {
            context.read<AuthBloc>().add(const AuthEvent.signOut());
          },
        ),
      ],
    );
  }

  Widget _buildWelcomeSection() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      child: BlocBuilder<AuthBloc, AuthState>(
        builder: (context, state) {
          return state.maybeWhen(
            authenticated: (user) => Column(
              children: [
                Text(
                  'Welcome back!',
                  style: AppTextStyles.h2,
                ),
                const SizedBox(height: AppDimensions.spacingSmall),
                Text(
                  'What would you like to do today?',
                  style: AppTextStyles.body1.copyWith(color: AppColors.textSecondary),
                ),
              ],
            ),
            orElse: () => const SizedBox.shrink(),
          );
        },
      ),
    );
  }

  Widget _buildQuickStats() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingLarge),
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
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          _buildStatItem('12', 'Garments', Icons.checkroom),
          _buildStatItem('5', 'Outfits', Icons.style),
          _buildStatItem('3', 'This Week', Icons.calendar_today),
          _buildStatItem('AI', 'Ready', Icons.auto_awesome),
        ],
      ),
    );
  }

  Widget _buildStatItem(String value, String label, IconData icon) {
    return Column(
      children: [
        Icon(icon, color: AppColors.primary, size: 24),
        const SizedBox(height: 4),
        Text(
          value,
          style: AppTextStyles.h3.copyWith(color: AppColors.primary),
        ),
        Text(
          label,
          style: AppTextStyles.caption.copyWith(color: AppColors.textSecondary),
        ),
      ],
    );
  }

  Widget _buildFeatureCards() {
    final features = [
      {
        'title': 'Capture Garment',
        'subtitle': 'Upload & tag with AI polygons',
        'icon': Icons.add_a_photo,
        'color': AppColors.primary,
        'route': '/garment/capture',
      },
      {
        'title': 'My Wardrobe',
        'subtitle': 'View your digital collection',
        'icon': Icons.checkroom,
        'color': Colors.purple,
        'route': '/wardrobe',
      },
      {
        'title': 'AI Outfit Builder',
        'subtitle': 'Get personalized suggestions',
        'icon': Icons.auto_awesome,
        'color': Colors.orange,
        'route': '/outfit/ai-builder',
      },
      {
        'title': 'Analytics',
        'subtitle': 'Track your fashion habits',
        'icon': Icons.analytics,
        'color': Colors.green,
        'route': '/analytics',
      },
    ];

    return Padding(
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Quick Actions', style: AppTextStyles.h3),
          const SizedBox(height: AppDimensions.spacingMedium),
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 2,
              childAspectRatio: 1.2,
              crossAxisSpacing: AppDimensions.spacingMedium,
              mainAxisSpacing: AppDimensions.spacingMedium,
            ),
            itemCount: features.length,
            itemBuilder: (context, index) {
              final feature = features[index];
              return _buildFeatureCard(
                title: feature['title'] as String,
                subtitle: feature['subtitle'] as String,
                icon: feature['icon'] as IconData,
                color: feature['color'] as Color,
                onTap: () => context.push(feature['route'] as String),
              );
            },
          ),
          const SizedBox(height: AppDimensions.spacingLarge),
          _buildAIInsightCard(),
        ],
      ),
    );
  }

  Widget _buildFeatureCard({
    required String title,
    required String subtitle,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      child: Container(
        padding: const EdgeInsets.all(AppDimensions.paddingMedium),
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
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: color.withOpacity(0.1),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(icon, color: color, size: 30),
            ),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: AppTextStyles.subtitle1,
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  style: AppTextStyles.caption.copyWith(
                    color: AppColors.textSecondary,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAIInsightCard() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingLarge),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            AppColors.primary,
            AppColors.primary.withOpacity(0.8),
          ],
        ),
        borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Icon(
                      Icons.tips_and_updates,
                      color: Colors.white,
                      size: 20,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'AI Insight',
                      style: AppTextStyles.subtitle1.copyWith(color: Colors.white),
                    ),
                  ],
                ),
                const SizedBox(height: AppDimensions.spacingSmall),
                Text(
                  'Your white shirt has been worn 5 times this month. '
                  'Try pairing it with your blue blazer for a fresh look!',
                  style: AppTextStyles.caption.copyWith(color: Colors.white70),
                ),
              ],
            ),
          ),
          const SizedBox(width: AppDimensions.spacingMedium),
          AnimatedBuilder(
            animation: _floatingController,
            builder: (context, child) {
              return Transform.scale(
                scale: 1 + (_floatingController.value * 0.1),
                child: Icon(
                  Icons.auto_awesome,
                  color: Colors.white.withOpacity(0.8),
                  size: 40,
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}