import 'package:flutter/material.dart';
import 'dart:math' as math;

// Define colors directly in this file for now
class AppColors {
  static const Color primary = Color(0xFF667EEA);
  static const Color secondary = Color(0xFF764BA2);
  static const Color background = Color(0xFFF5F5F5);
  static const Color textPrimary = Color(0xFF333333);
}

class EnhancedSplashScreen extends StatefulWidget {
  const EnhancedSplashScreen({super.key});

  @override
  State<EnhancedSplashScreen> createState() => _EnhancedSplashScreenState();
}

class _EnhancedSplashScreenState extends State<EnhancedSplashScreen>
    with TickerProviderStateMixin {
  late AnimationController _wardrobeController;
  late AnimationController _logoController;
  late AnimationController _taglineController;
  late AnimationController _pulseController;
  
  late Animation<double> _wardrobeScaleAnimation;
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  late Animation<double> _perspectiveAnimation;
  late Animation<double> _logoScaleAnimation;
  late Animation<double> _logoFadeAnimation;
  late Animation<double> _taglineFadeAnimation;
  late Animation<double> _taglineSlideAnimation;
  late Animation<double> _pulseAnimation;
  late Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();
    _initAnimations();
    _startAnimationSequence();
  }

  void _initAnimations() {
    // Wardrobe animation controller
    _wardrobeController = AnimationController(
      duration: const Duration(milliseconds: 2000),
      vsync: this,
    );

    // Logo animation controller
    _logoController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );

    // Tagline animation controller
    _taglineController = AnimationController(
      duration: const Duration(milliseconds: 1000),
      vsync: this,
    );

    // Pulse animation controller
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 2000),
      vsync: this,
    )..repeat(reverse: true);

    // Wardrobe scale animation (starts small, grows to full size)
    _wardrobeScaleAnimation = Tween<double>(
      begin: 0.8,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: const Interval(0.0, 0.3, curve: Curves.easeOut),
    ));

    // 3D perspective animation for depth effect
    _perspectiveAnimation = Tween<double>(
      begin: 0.0,
      end: 0.002,
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: const Interval(0.0, 0.5, curve: Curves.easeOut),
    ));

    // Left door opens with 3D rotation
    _leftDoorAnimation = Tween<double>(
      begin: 0.0,
      end: -75.0, // Degrees
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: const Interval(0.3, 1.0, curve: Curves.easeInOut),
    ));

    // Right door opens with 3D rotation
    _rightDoorAnimation = Tween<double>(
      begin: 0.0,
      end: 75.0, // Degrees
    ).animate(CurvedAnimation(
      parent: _wardrobeController,
      curve: const Interval(0.3, 1.0, curve: Curves.easeInOut),
    ));

    // Logo animations
    _logoScaleAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: Curves.elasticOut,
    ));

    _logoFadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: Curves.easeIn,
    ));

    // Tagline animations
    _taglineFadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _taglineController,
      curve: Curves.easeIn,
    ));

    _taglineSlideAnimation = Tween<double>(
      begin: 20.0,
      end: 0.0,
    ).animate(CurvedAnimation(
      parent: _taglineController,
      curve: Curves.easeOut,
    ));

    // Glow animation
    _glowAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoController,
      curve: Curves.easeInOut,
    ));

    // Pulse animation
    _pulseAnimation = Tween<double>(
      begin: 1.0,
      end: 1.1,
    ).animate(CurvedAnimation(
      parent: _pulseController,
      curve: Curves.easeInOut,
    ));
  }

  void _startAnimationSequence() async {
    // Start wardrobe animation
    await _wardrobeController.forward();
    
    // Small delay before logo appears
    await Future.delayed(const Duration(milliseconds: 300));
    
    // Start logo animation
    _logoController.forward();
    
    // Delay before tagline
    await Future.delayed(const Duration(milliseconds: 600));
    
    // Start tagline animation
    await _taglineController.forward();
    
    // Wait before navigating
    await Future.delayed(const Duration(milliseconds: 2000));
    
    // Navigate to home - for now, just pop back
    if (mounted) {
      Navigator.of(context).pop();
    }
  }

  @override
  void dispose() {
    _wardrobeController.dispose();
    _logoController.dispose();
    _taglineController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final wardrobeWidth = size.width * 0.85;
    final wardrobeHeight = size.height * 0.65;

    return Scaffold(
      backgroundColor: AppColors.background,
      body: Stack(
        children: [
          // Animated background gradient
          AnimatedBuilder(
            animation: _wardrobeController,
            builder: (context, child) {
              return Container(
                decoration: BoxDecoration(
                  gradient: RadialGradient(
                    center: Alignment.center,
                    radius: 1.5,
                    colors: [
                      AppColors.primary.withOpacity(0.15 * _wardrobeController.value),
                      AppColors.background,
                      AppColors.secondary.withOpacity(0.1),
                    ],
                  ),
                ),
              );
            },
          ),
          
          // Main content
          Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // 3D Wardrobe Container
                AnimatedBuilder(
                  animation: _wardrobeController,
                  builder: (context, child) {
                    return Transform(
                      alignment: Alignment.center,
                      transform: Matrix4.identity()
                        ..setEntry(3, 2, _perspectiveAnimation.value)
                        ..scale(_wardrobeScaleAnimation.value),
                      child: SizedBox(
                        width: wardrobeWidth,
                        height: wardrobeHeight,
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                            // Logo and content behind doors
                            _buildLogoContent(),
                            
                            // 3D Wardrobe doors
                            _build3DWardrobeDoors(wardrobeWidth, wardrobeHeight),
                          ],
                        ),
                      ),
                    );
                  },
                ),
                
                // Tagline
                const SizedBox(height: 40),
                AnimatedBuilder(
                  animation: _taglineController,
                  builder: (context, child) {
                    return Transform.translate(
                      offset: Offset(0, _taglineSlideAnimation.value),
                      child: Opacity(
                        opacity: _taglineFadeAnimation.value,
                        child: Text(
                          'Your Digital Fashion Assistant',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w300,
                            color: AppColors.textPrimary,
                            letterSpacing: 1.2,
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLogoContent() {
    return AnimatedBuilder(
      animation: Listenable.merge([_logoController, _pulseController]),
      builder: (context, child) {
        return Transform.scale(
          scale: _logoScaleAnimation.value * _pulseAnimation.value,
          child: Opacity(
            opacity: _logoFadeAnimation.value,
            child: Container(
              width: 250,
              height: 250,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                boxShadow: [
                  BoxShadow(
                    color: AppColors.primary.withOpacity(_glowAnimation.value * 0.3),
                    blurRadius: 60,
                    spreadRadius: 30,
                  ),
                  BoxShadow(
                    color: AppColors.primary.withOpacity(_glowAnimation.value * 0.2),
                    blurRadius: 100,
                    spreadRadius: 50,
                  ),
                ],
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Logo
                  Container(
                    width: 120,
                    height: 120,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                        colors: [
                          AppColors.primary,
                          AppColors.primary.withOpacity(0.8),
                        ],
                      ),
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: AppColors.primary.withOpacity(0.4),
                          blurRadius: 20,
                          offset: const Offset(0, 10),
                        ),
                      ],
                    ),
                    child: const Icon(
                      Icons.checkroom,
                      size: 60,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(height: 30),
                  // Koutu text
                  ShaderMask(
                    shaderCallback: (bounds) => LinearGradient(
                      colors: [
                        AppColors.primary,
                        AppColors.secondary,
                      ],
                    ).createShader(bounds),
                    child: const Text(
                      'KOUTU',
                      style: TextStyle(
                        fontSize: 48,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                        letterSpacing: 5,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _build3DWardrobeDoors(double wardrobeWidth, double wardrobeHeight) {
    return Stack(
      children: [
        // Left door with 3D rotation
        Positioned(
          left: 0,
          child: AnimatedBuilder(
            animation: _leftDoorAnimation,
            builder: (context, child) {
              return Transform(
                alignment: Alignment.centerRight,
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.001)
                  ..rotateY(_leftDoorAnimation.value * (math.pi / 180)),
                child: _build3DDoor(
                  width: wardrobeWidth / 2,
                  height: wardrobeHeight,
                  isLeft: true,
                ),
              );
            },
          ),
        ),
        
        // Right door with 3D rotation
        Positioned(
          right: 0,
          child: AnimatedBuilder(
            animation: _rightDoorAnimation,
            builder: (context, child) {
              return Transform(
                alignment: Alignment.centerLeft,
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.001)
                  ..rotateY(_rightDoorAnimation.value * (math.pi / 180)),
                child: _build3DDoor(
                  width: wardrobeWidth / 2,
                  height: wardrobeHeight,
                  isLeft: false,
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _build3DDoor({
    required double width,
    required double height,
    required bool isLeft,
  }) {
    return Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: isLeft ? Alignment.centerLeft : Alignment.centerRight,
          end: isLeft ? Alignment.centerRight : Alignment.centerLeft,
          colors: const [
            Color(0xFF4A3628),
            Color(0xFF6B4E3D),
            Color(0xFF8B6B47),
          ],
        ),
        borderRadius: BorderRadius.only(
          topLeft: isLeft ? const Radius.circular(12) : Radius.zero,
          topRight: !isLeft ? const Radius.circular(12) : Radius.zero,
          bottomLeft: isLeft ? const Radius.circular(12) : Radius.zero,
          bottomRight: !isLeft ? const Radius.circular(12) : Radius.zero,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.4),
            blurRadius: 20,
            offset: Offset(isLeft ? -5 : 5, 5),
          ),
        ],
      ),
      child: Stack(
        children: [
          // Wood texture pattern
          CustomPaint(
            size: Size(width, height),
            painter: WoodTexturePainter(isLeft: isLeft),
          ),
          
          // Door panels
          Positioned(
            top: 20,
            left: isLeft ? 20 : 10,
            right: isLeft ? 10 : 20,
            bottom: 20,
            child: Container(
              decoration: BoxDecoration(
                border: Border.all(
                  color: const Color(0xFF3A2818),
                  width: 3,
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                children: [
                  Expanded(
                    child: Container(
                      margin: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFF5A4334).withOpacity(0.3),
                        borderRadius: BorderRadius.circular(4),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.2),
                            blurRadius: 5,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: Container(
                      margin: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFF5A4334).withOpacity(0.3),
                        borderRadius: BorderRadius.circular(4),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.2),
                            blurRadius: 5,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          
          // Door handle
          Positioned(
            top: height / 2 - 40,
            left: isLeft ? null : 25,
            right: isLeft ? 25 : null,
            child: Container(
              width: 12,
              height: 80,
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    Color(0xFFE4C441),
                    Color(0xFFB8963F),
                    Color(0xFFE4C441),
                  ],
                ),
                borderRadius: BorderRadius.circular(6),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.5),
                    blurRadius: 8,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// Custom painter for wood texture
class WoodTexturePainter extends CustomPainter {
  final bool isLeft;

  WoodTexturePainter({required this.isLeft});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 0.5;

    // Draw wood grain lines
    for (int i = 0; i < 20; i++) {
      paint.color = const Color(0xFF3A2818).withOpacity(0.3);
      final y = (size.height / 20) * i;
      
      final path = Path();
      path.moveTo(0, y);
      
      // Create wavy wood grain effect
      for (double x = 0; x <= size.width; x += 10) {
        final waveY = y + math.sin(x * 0.02) * 2;
        path.lineTo(x, waveY);
      }
      
      canvas.drawPath(path, paint);
    }
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) => false;
}