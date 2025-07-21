import 'package:flutter/material.dart';
import 'package:lottie/lottie.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/routing/route_paths.dart';

/// Alternative splash screen using Lottie animations
/// To use this, place your wardrobe.json animation file in assets/animations/
/// and update pubspec.yaml to include it
class SplashScreenLottie extends StatefulWidget {
  const SplashScreenLottie({super.key});

  @override
  State<SplashScreenLottie> createState() => _SplashScreenLottieState();
}

class _SplashScreenLottieState extends State<SplashScreenLottie>
    with TickerProviderStateMixin {
  late AnimationController _lottieController;
  bool _showLogo = false;

  @override
  void initState() {
    super.initState();
    _startAnimation();
  }

  void _startAnimation() async {
    // Wait for Lottie animation to complete
    await Future.delayed(const Duration(milliseconds: 2000));
    
    // Show logo with animation
    setState(() {
      _showLogo = true;
    });
    
    // Wait before navigating
    await Future.delayed(const Duration(milliseconds: 2000));
    
    if (mounted) {
      context.go(RoutePaths.home);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: Stack(
        children: [
          // Background gradient
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  AppColors.primary.withOpacity(0.05),
                  AppColors.background,
                  AppColors.secondary.withOpacity(0.05),
                ],
              ),
            ),
          ),
          
          Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Lottie Animation
                SizedBox(
                  width: 300,
                  height: 300,
                  child: Lottie.asset(
                    'assets/animations/wardrobe_opening.json',
                    onLoaded: (composition) {
                      _lottieController = AnimationController(
                        duration: composition.duration,
                        vsync: this,
                      );
                      _lottieController.forward();
                    },
                    controller: _lottieController,
                    errorBuilder: (context, error, stackTrace) {
                      // Fallback to static icon if Lottie file not found
                      return Container(
                        width: 200,
                        height: 200,
                        decoration: BoxDecoration(
                          color: AppColors.primary.withOpacity(0.1),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          Icons.door_sliding_outlined,
                          size: 100,
                          color: AppColors.primary,
                        ),
                      );
                    },
                  ),
                ),
                
                const SizedBox(height: 40),
                
                // Logo
                AnimatedOpacity(
                  opacity: _showLogo ? 1.0 : 0.0,
                  duration: const Duration(milliseconds: 500),
                  child: AnimatedScale(
                    scale: _showLogo ? 1.0 : 0.5,
                    duration: const Duration(milliseconds: 800),
                    curve: Curves.elasticOut,
                    child: Column(
                      children: [
                        // Logo container with glow effect
                        Container(
                          width: 120,
                          height: 120,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: AppColors.primary,
                            boxShadow: _showLogo
                                ? [
                                    BoxShadow(
                                      color: AppColors.primary.withOpacity(0.5),
                                      blurRadius: 30,
                                      spreadRadius: 10,
                                    ),
                                  ]
                                : [],
                          ),
                          child: const Icon(
                            Icons.checkroom,
                            size: 60,
                            color: Colors.white,
                          ),
                        )
                            .animate(
                              onPlay: (controller) => controller.repeat(reverse: true),
                            )
                            .scale(
                              begin: const Offset(1, 1),
                              end: const Offset(1.1, 1.1),
                              duration: 2.seconds,
                              curve: Curves.easeInOut,
                            ),
                        
                        const SizedBox(height: 24),
                        
                        // App name
                        Text(
                          'KOUTU',
                          style: TextStyle(
                            fontSize: 36,
                            fontWeight: FontWeight.w300,
                            color: AppColors.primary,
                            letterSpacing: 6,
                          ),
                        )
                            .animate()
                            .fadeIn(duration: 600.ms)
                            .slideY(begin: 0.2, end: 0),
                        
                        const SizedBox(height: 8),
                        
                        Text(
                          'Your Digital Wardrobe',
                          style: TextStyle(
                            fontSize: 14,
                            color: AppColors.textSecondary,
                            letterSpacing: 1,
                          ),
                        )
                            .animate()
                            .fadeIn(duration: 800.ms, delay: 200.ms)
                            .slideY(begin: 0.2, end: 0),
                      ],
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

  @override
  void dispose() {
    _lottieController.dispose();
    super.dispose();
  }
}