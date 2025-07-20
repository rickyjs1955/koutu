import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:koutu/core/constants/app_colors.dart';

class SimpleSplashScreen extends StatefulWidget {
  const SimpleSplashScreen({super.key});

  @override
  State<SimpleSplashScreen> createState() => _SimpleSplashScreenState();
}

class _SimpleSplashScreenState extends State<SimpleSplashScreen>
    with TickerProviderStateMixin {
  late AnimationController _wardrobeController;
  late AnimationController _logoController;
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  late Animation<double> _logoScaleAnimation;
  late Animation<double> _logoFadeAnimation;
  late Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();
    _initAnimations();
    _startAnimationSequence();
  }

  void _initAnimations() {
    // Wardrobe door animation controller
    _wardrobeController = AnimationController(
      duration: const Duration(milliseconds: 1200),
      vsync: this,
    );

    // Logo animation controller
    _logoController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    );

    // Left door slides to the left
    _leftDoorAnimation = Tween<double>(
      begin: 0.0,
      end: -1.0,
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: Curves.easeInOut,
    ));

    // Right door slides to the right
    _rightDoorAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: Curves.easeInOut,
    ));

    // Logo scale animation
    _logoScaleAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: Curves.elasticOut,
    ));

    // Logo fade animation
    _logoFadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: const Interval(0.0, 0.6, curve: Curves.easeIn),
    ));

    // Glow animation
    _glowAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: Curves.easeInOut,
    ));
  }

  void _startAnimationSequence() async {
    // Wait a moment before starting
    await Future.delayed(const Duration(milliseconds: 500));
    
    // Start wardrobe opening animation
    await _wardrobeController.forward();
    
    // Small delay before logo appears
    await Future.delayed(const Duration(milliseconds: 200));
    
    // Start logo animation
    await _logoController.forward();
    
    // Wait before navigating
    await Future.delayed(const Duration(milliseconds: 1500));
    
    // Navigate to home using standard navigation
    if (mounted) {
      Navigator.of(context).pushReplacementNamed('/home');
    }
  }

  @override
  void dispose() {
    _wardrobeController.dispose();
    _logoController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final wardrobeWidth = size.width * 0.8;
    final wardrobeHeight = size.height * 0.6;

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
                  AppColors.primary.withOpacity(0.1),
                  AppColors.background,
                  AppColors.secondary.withOpacity(0.1),
                ],
              ),
            ),
          ),
          
          // Wardrobe and Logo
          Center(
            child: SizedBox(
              width: wardrobeWidth,
              height: wardrobeHeight,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  // Logo behind wardrobe doors
                  AnimatedBuilder(
                    animation: _logoController,
                    builder: (context, child) {
                      return Transform.scale(
                        scale: _logoScaleAnimation.value,
                        child: Opacity(
                          opacity: _logoFadeAnimation.value,
                          child: Container(
                            width: 200,
                            height: 200,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              boxShadow: [
                                BoxShadow(
                                  color: AppColors.primary.withOpacity(_glowAnimation.value * 0.5),
                                  blurRadius: 50,
                                  spreadRadius: 20,
                                ),
                              ],
                            ),
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                // Logo icon/image placeholder
                                Container(
                                  width: 100,
                                  height: 100,
                                  decoration: BoxDecoration(
                                    color: AppColors.primary,
                                    shape: BoxShape.circle,
                                  ),
                                  child: const Icon(
                                    Icons.checkroom,
                                    size: 50,
                                    color: Colors.white,
                                  ),
                                ),
                                const SizedBox(height: 20),
                                Text(
                                  'KOUTU',
                                  style: TextStyle(
                                    fontSize: 32,
                                    fontWeight: FontWeight.bold,
                                    color: AppColors.primary,
                                    letterSpacing: 3,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      );
                    },
                  ),
                  
                  // Wardrobe doors
                  AnimatedBuilder(
                    animation: _wardrobeController,
                    builder: (context, child) {
                      return Stack(
                        children: [
                          // Left door
                          Transform.translate(
                            offset: Offset(_leftDoorAnimation.value * wardrobeWidth / 2, 0),
                            child: _buildWardrobeDoor(
                              width: wardrobeWidth / 2,
                              height: wardrobeHeight,
                              isLeft: true,
                            ),
                          ),
                          
                          // Right door
                          Transform.translate(
                            offset: Offset(_rightDoorAnimation.value * wardrobeWidth / 2, 0),
                            child: _buildWardrobeDoor(
                              width: wardrobeWidth / 2,
                              height: wardrobeHeight,
                              isLeft: false,
                            ),
                          ),
                        ],
                      );
                    },
                  ),
                ],
              ),
            ),
          ),
          
          // Loading indicator at bottom
          Positioned(
            bottom: 100,
            left: 0,
            right: 0,
            child: Center(
              child: AnimatedBuilder(
                animation: _logoController,
                builder: (context, child) {
                  return Opacity(
                    opacity: 1 - _logoFadeAnimation.value,
                    child: const CircularProgressIndicator(
                      valueColor: AlwaysStoppedAnimation<Color>(AppColors.primary),
                      strokeWidth: 2,
                    ),
                  );
                },
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildWardrobeDoor({
    required double width,
    required double height,
    required bool isLeft,
  }) {
    return Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        color: Colors.brown[800],
        borderRadius: BorderRadius.only(
          topLeft: isLeft ? const Radius.circular(8) : Radius.zero,
          topRight: !isLeft ? const Radius.circular(8) : Radius.zero,
          bottomLeft: isLeft ? const Radius.circular(8) : Radius.zero,
          bottomRight: !isLeft ? const Radius.circular(8) : Radius.zero,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.3),
            blurRadius: 10,
            offset: Offset(isLeft ? -2 : 2, 0),
          ),
        ],
        gradient: LinearGradient(
          begin: isLeft ? Alignment.centerRight : Alignment.centerLeft,
          end: isLeft ? Alignment.centerLeft : Alignment.centerRight,
          colors: [
            Colors.brown[900]!,
            Colors.brown[800]!,
            Colors.brown[700]!,
          ],
        ),
      ),
      child: Stack(
        children: [
          // Wood grain effect
          ...List.generate(
            8,
            (index) => Positioned(
              top: index * (height / 8),
              left: 0,
              right: 0,
              child: Container(
                height: 1,
                color: Colors.brown[600]!.withOpacity(0.3),
              ),
            ),
          ),
          
          // Door handle
          Positioned(
            top: height / 2 - 30,
            left: isLeft ? null : 20,
            right: isLeft ? 20 : null,
            child: Container(
              width: 8,
              height: 60,
              decoration: BoxDecoration(
                color: Colors.amber[700],
                borderRadius: BorderRadius.circular(4),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.3),
                    blurRadius: 4,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
            ),
          ),
          
          // Door panel
          Center(
            child: Container(
              width: width * 0.8,
              height: height * 0.9,
              decoration: BoxDecoration(
                border: Border.all(
                  color: Colors.brown[600]!,
                  width: 2,
                ),
                borderRadius: BorderRadius.circular(4),
              ),
            ),
          ),
        ],
      ),
    );
  }
}