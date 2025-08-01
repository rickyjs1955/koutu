import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'dart:math';
import 'dart:ui' as ui;
import 'dart:async';
import 'package:koutu/core/constants/app_colors.dart';

/// Ultra-stunning splash screen with advanced visual effects
class EnhancedSplashScreen extends StatefulWidget {
  const EnhancedSplashScreen({super.key});

  @override
  State<EnhancedSplashScreen> createState() => _EnhancedSplashScreenState();
}

class _EnhancedSplashScreenState extends State<EnhancedSplashScreen>
    with TickerProviderStateMixin {
  // Master animation controller
  late AnimationController _masterController;
  
  // Door animations
  late AnimationController _doorController;
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  late Animation<double> _doorShadowAnimation;
  
  // Lighting animations
  late AnimationController _lightController;
  late Animation<double> _spotlightAnimation;
  late Animation<double> _glowAnimation;
  
  // Particle system controllers
  late AnimationController _particleController;
  late AnimationController _sparkleController;
  
  // Clothing reveal
  late AnimationController _clothingController;
  late Animation<double> _clothingFallAnimation;
  late Animation<double> _clothingOpacityAnimation;
  
  // Text and logo animations
  late AnimationController _textController;
  late Animation<double> _logoScaleAnimation;
  late Animation<double> _logoRotationAnimation;
  late Animation<double> _textRevealAnimation;
  late Animation<double> _shimmerAnimation;
  
  // Wardrobe shake animation
  late Animation<double> _shakeAnimation;
  
  // Premium color palette
  final Color _obsidian = const Color(0xFF0A0E27);
  final Color _royalPurple = const Color(0xFF6B5B95);
  final Color _champagneGold = const Color(0xFFD4AF37);
  final Color _roseGold = const Color(0xFFE8B4B8);
  final Color _midnight = const Color(0xFF191970);
  
  // Particle systems
  final List<Particle> _backgroundParticles = [];
  final List<Sparkle> _sparkles = [];
  final List<ClothingItem> _clothingItems = [];

  @override
  void initState() {
    super.initState();
    _initializeAnimations();
    _initializeParticles();
    _startAnimationSequence();
  }

  void _initializeAnimations() {
    // Master controller for overall timing
    _masterController = AnimationController(
      duration: const Duration(milliseconds: 4000),
      vsync: this,
    );

    // Door controller with dramatic timing
    _doorController = AnimationController(
      duration: const Duration(milliseconds: 2500),
      vsync: this,
    );

    // Lighting effects controller
    _lightController = AnimationController(
      duration: const Duration(milliseconds: 3000),
      vsync: this,
    );

    // Particle systems
    _particleController = AnimationController(
      duration: const Duration(seconds: 20),
      vsync: this,
    )..repeat();

    _sparkleController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );

    // Clothing reveal
    _clothingController = AnimationController(
      duration: const Duration(milliseconds: 2000),
      vsync: this,
    );

    // Text animations
    _textController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );

    // Configure door animations with overshoot - doors open outward
    _leftDoorAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: -110.0)
            .chain(CurveTween(curve: Curves.easeInOutBack)),
        weight: 80.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: -110.0, end: -95.0)
            .chain(CurveTween(curve: Curves.elasticOut)),
        weight: 20.0,
      ),
    ]).animate(_doorController);

    _rightDoorAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 110.0)
            .chain(CurveTween(curve: Curves.easeInOutBack)),
        weight: 80.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 110.0, end: 95.0)
            .chain(CurveTween(curve: Curves.elasticOut)),
        weight: 20.0,
      ),
    ]).animate(_doorController);

    // Door shadow intensity
    _doorShadowAnimation = Tween<double>(
      begin: 20.0,
      end: 5.0,
    ).animate(CurvedAnimation(
      parent: _doorController,
      curve: Curves.easeOut,
    ));

    // Spotlight that follows door opening
    _spotlightAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _lightController,
      curve: const Interval(0.2, 0.8, curve: Curves.easeOut),
    ));

    // Magical glow animation
    _glowAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 1.0),
        weight: 50.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.0, end: 0.7),
        weight: 50.0,
      ),
    ]).animate(_lightController);

    // Wardrobe shake before opening
    _shakeAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 5.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 5.0, end: -5.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: -5.0, end: 3.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 3.0, end: 0.0),
        weight: 25.0,
      ),
    ]).animate(CurvedAnimation(
      parent: _doorController,
      curve: const Interval(0.0, 0.2, curve: Curves.elasticIn),
    ));

    // Clothing animations
    _clothingFallAnimation = Tween<double>(
      begin: -100.0,
      end: 0.0,
    ).animate(CurvedAnimation(
      parent: _clothingController,
      curve: Curves.bounceOut,
    ));

    _clothingOpacityAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _clothingController,
      curve: const Interval(0.0, 0.3),
    ));

    // Logo animations
    _logoScaleAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 1.2),
        weight: 70.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.2, end: 1.0),
        weight: 30.0,
      ),
    ]).animate(CurvedAnimation(
      parent: _textController,
      curve: Curves.elasticOut,
    ));

    _logoRotationAnimation = Tween<double>(
      begin: -0.1,
      end: 0.0,
    ).animate(CurvedAnimation(
      parent: _textController,
      curve: Curves.easeOutBack,
    ));

    // Text reveal with shimmer
    _textRevealAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _textController,
      curve: Curves.easeOutExpo,
    ));

    _shimmerAnimation = Tween<double>(
      begin: -1.0,
      end: 2.0,
    ).animate(CurvedAnimation(
      parent: _textController,
      curve: Curves.linear,
    ));
  }

  void _initializeParticles() {
    // Create multi-layer particle system
    for (int i = 0; i < 100; i++) {
      _backgroundParticles.add(Particle(
        position: Offset(
          Random().nextDouble() * 400 - 200,
          Random().nextDouble() * 800 - 400,
        ),
        velocity: Offset(
          Random().nextDouble() * 2 - 1,
          Random().nextDouble() * 2 - 1,
        ),
        size: Random().nextDouble() * 3 + 1,
        color: [_champagneGold, _roseGold, _royalPurple][Random().nextInt(3)],
        depth: Random().nextDouble(),
      ));
    }

    // Initialize clothing items
    final clothingTypes = ['dress', 'suit', 'shirt', 'shoes', 'hat'];
    final clothingIcons = [
      Icons.checkroom,
      Icons.dry_cleaning,
      Icons.iron,
      Icons.shopping_bag,
      Icons.watch,
    ];
    
    for (int i = 0; i < 5; i++) {
      _clothingItems.add(ClothingItem(
        type: clothingTypes[i],
        icon: clothingIcons[i],
        position: Offset(
          -100 + i * 50.0,
          -200.0,
        ),
        rotation: Random().nextDouble() * 0.5 - 0.25,
        delay: i * 0.1,
      ));
    }
  }

  void _startAnimationSequence() async {
    // Start background particles immediately
    _particleController.forward();
    
    // Shake and build anticipation
    await Future.delayed(const Duration(milliseconds: 500));
    _doorController.forward();
    
    // Start lighting effects
    await Future.delayed(const Duration(milliseconds: 300));
    _lightController.forward();
    
    // Trigger sparkles when doors start opening
    await Future.delayed(const Duration(milliseconds: 400));
    _sparkleController.repeat();
    _generateSparkles();
    
    // Reveal clothing items
    await Future.delayed(const Duration(milliseconds: 800));
    _clothingController.forward();
    
    // Show logo and text
    await Future.delayed(const Duration(milliseconds: 500));
    _textController.forward();
    
    // Navigate after full sequence
    await Future.delayed(const Duration(milliseconds: 2000));
    if (mounted) {
      Navigator.of(context).pushReplacementNamed('/home');
    }
  }

  void _generateSparkles() {
    Timer.periodic(const Duration(milliseconds: 100), (timer) {
      if (!mounted || _sparkles.length > 50) {
        timer.cancel();
        return;
      }
      
      _sparkles.add(Sparkle(
        position: Offset(
          Random().nextDouble() * MediaQuery.of(context).size.width,
          Random().nextDouble() * MediaQuery.of(context).size.height,
        ),
        lifespan: 1.0,
      ));
    });
  }

  @override
  void dispose() {
    _masterController.dispose();
    _doorController.dispose();
    _lightController.dispose();
    _particleController.dispose();
    _sparkleController.dispose();
    _clothingController.dispose();
    _textController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;

    return Scaffold(
      backgroundColor: _obsidian,
      body: Stack(
        children: [
          // Animated gradient background
          AnimatedBuilder(
            animation: _lightController,
            builder: (context, child) {
              return Container(
                decoration: BoxDecoration(
                  gradient: RadialGradient(
                    center: Alignment(0, -0.3),
                    radius: 1.5 * _spotlightAnimation.value + 0.5,
                    colors: [
                      _midnight.withOpacity(0.3 * _spotlightAnimation.value),
                      _obsidian,
                      Colors.black,
                    ],
                  ),
                ),
              );
            },
          ),

          // Multi-layer particle system
          ...List.generate(3, (layer) {
            return AnimatedBuilder(
              animation: _particleController,
              builder: (context, child) {
                return CustomPaint(
                  size: Size.infinite,
                  painter: ParallaxParticlePainter(
                    particles: _backgroundParticles
                        .where((p) => p.depth > layer * 0.33 && p.depth <= (layer + 1) * 0.33)
                        .toList(),
                    animation: _particleController,
                    parallaxFactor: 1.0 - (layer * 0.3),
                  ),
                );
              },
            );
          }),

          // Spotlight effect
          AnimatedBuilder(
            animation: _spotlightAnimation,
            builder: (context, child) {
              return CustomPaint(
                size: Size.infinite,
                painter: SpotlightPainter(
                  intensity: _spotlightAnimation.value,
                  glowIntensity: _glowAnimation.value,
                  color: _champagneGold,
                ),
              );
            },
          ),

          // Main wardrobe container
          Center(
            child: AnimatedBuilder(
              animation: Listenable.merge([_doorController, _shakeAnimation]),
              builder: (context, child) {
                return Transform.translate(
                  offset: Offset(_shakeAnimation.value, 0),
                  child: Container(
                    width: size.width * 1.04,  // Increased from 0.8 to 1.04 (30% larger)
                    height: size.height * 0.91, // Increased from 0.7 to 0.91 (30% larger)
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        // Magical glow behind wardrobe
                        _buildMagicalGlow(),
                        
                        // Logo and content
                        _buildLogoContent(),
                        
                        // Clothing items falling out
                        _buildClothingItems(),
                        
                        // Wardrobe doors
                        _buildLuxuryDoors(size.width * 1.04, size.height * 0.91),
                        
                        // Sparkle effects
                        _buildSparkles(),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),

          // Premium text overlay
          _buildTextOverlay(),
        ],
      ),
    );
  }

  Widget _buildMagicalGlow() {
    return AnimatedBuilder(
      animation: _glowAnimation,
      builder: (context, child) {
        return Container(
          width: 390,  // Increased from 300 to 390 (30% larger)
          height: 390, // Increased from 300 to 390 (30% larger)
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: _champagneGold.withOpacity(0.3 * _glowAnimation.value),
                blurRadius: 130, // Increased from 100 to 130 (30% larger)
                spreadRadius: 65, // Increased from 50 to 65 (30% larger)
              ),
              BoxShadow(
                color: _royalPurple.withOpacity(0.2 * _glowAnimation.value),
                blurRadius: 195,  // Increased from 150 to 195 (30% larger)
                spreadRadius: 104, // Increased from 80 to 104 (30% larger)
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildLogoContent() {
    return AnimatedBuilder(
      animation: Listenable.merge([_logoScaleAnimation, _logoRotationAnimation]),
      builder: (context, child) {
        return Transform.scale(
          scale: _logoScaleAnimation.value,
          child: Transform.rotate(
            angle: _logoRotationAnimation.value,
            child: Container(
              width: 260,  // Increased from 200 to 260 (30% larger)
              height: 260, // Increased from 200 to 260 (30% larger)
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    _champagneGold,
                    _roseGold,
                  ],
                ),
                boxShadow: [
                  BoxShadow(
                    color: _champagneGold.withOpacity(0.5),
                    blurRadius: 39, // Increased from 30 to 39 (30% larger)
                    spreadRadius: 13, // Increased from 10 to 13 (30% larger)
                  ),
                ],
              ),
              child: Icon(
                Icons.auto_awesome,
                size: 130, // Increased from 100 to 130 (30% larger)
                color: Colors.white,
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildClothingItems() {
    return AnimatedBuilder(
      animation: _clothingController,
      builder: (context, child) {
        return Stack(
          children: _clothingItems.map((item) {
            return Transform.translate(
              offset: Offset(
                item.position.dx,
                item.position.dy + _clothingFallAnimation.value * (1 + item.delay),
              ),
              child: Transform.rotate(
                angle: item.rotation + _clothingController.value * 0.5,
                child: Opacity(
                  opacity: _clothingOpacityAnimation.value,
                  child: Container(
                    width: 78,  // Increased from 60 to 78 (30% larger)
                    height: 78, // Increased from 60 to 78 (30% larger)
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: RadialGradient(
                        colors: [
                          _roseGold.withOpacity(0.8),
                          _royalPurple.withOpacity(0.6),
                        ],
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: _royalPurple.withOpacity(0.4),
                          blurRadius: 26, // Increased from 20 to 26 (30% larger)
                          spreadRadius: 6.5, // Increased from 5 to 6.5 (30% larger)
                        ),
                      ],
                    ),
                    child: Icon(
                      item.icon,
                      size: 39, // Increased from 30 to 39 (30% larger)
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
            );
          }).toList(),
        );
      },
    );
  }

  Widget _buildLuxuryDoors(double width, double height) {
    return Stack(
      children: [
        // Left door
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
                child: _buildLuxuryDoor(
                  width: width / 2,
                  height: height,
                  isLeft: true,
                ),
              );
            },
          ),
        ),
        
        // Right door
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
                child: _buildLuxuryDoor(
                  width: width / 2,
                  height: height,
                  isLeft: false,
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildLuxuryDoor({
    required double width,
    required double height,
    required bool isLeft,
  }) {
    return Container(
      width: width,
      height: height,
      child: Stack(
        children: [
          // Base door with gradient
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: isLeft ? Alignment.centerRight : Alignment.centerLeft,
                end: isLeft ? Alignment.centerLeft : Alignment.centerRight,
                colors: [
                  const Color(0xFF1a1a2e),
                  const Color(0xFF16213e),
                  const Color(0xFF0f3460),
                ],
              ),
              borderRadius: BorderRadius.only(
                topLeft: isLeft ? const Radius.circular(15) : Radius.zero,
                topRight: !isLeft ? const Radius.circular(15) : Radius.zero,
                bottomLeft: isLeft ? const Radius.circular(15) : Radius.zero,
                bottomRight: !isLeft ? const Radius.circular(15) : Radius.zero,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.5),
                  blurRadius: _doorShadowAnimation.value,
                  offset: Offset(isLeft ? -10 : 10, 10),
                ),
              ],
            ),
          ),
          
          // Metallic trim
          CustomPaint(
            size: Size(width, height),
            painter: MetallicTrimPainter(
              isLeft: isLeft,
              color: _champagneGold,
            ),
          ),
          
          // Glass panel with reflection
          Positioned(
            top: 50,
            left: isLeft ? 30 : 20,
            right: isLeft ? 20 : 30,
            bottom: 50,
            child: Container(
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    Colors.white.withOpacity(0.1),
                    Colors.white.withOpacity(0.05),
                    Colors.transparent,
                  ],
                ),
                border: Border.all(
                  color: _champagneGold.withOpacity(0.5),
                  width: 2,
                ),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: BackdropFilter(
                  filter: ui.ImageFilter.blur(sigmaX: 10, sigmaY: 10),
                  child: Container(
                    color: Colors.transparent,
                  ),
                ),
              ),
            ),
          ),
          
          // Ornate handle
          Positioned(
            top: height / 2 - 65, // Adjusted from -50 to -65 for 30% larger handle
            left: isLeft ? null : 39, // Increased from 30 to 39 (30% larger)
            right: isLeft ? 39 : null, // Increased from 30 to 39 (30% larger)
            child: Container(
              width: 19.5,  // Increased from 15 to 19.5 (30% larger)
              height: 130,  // Increased from 100 to 130 (30% larger)
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    _champagneGold,
                    _champagneGold.withOpacity(0.8),
                    _roseGold,
                    _champagneGold.withOpacity(0.8),
                    _champagneGold,
                  ],
                ),
                borderRadius: BorderRadius.circular(9.75), // Increased from 7.5 to 9.75 (30% larger)
                boxShadow: [
                  BoxShadow(
                    color: _champagneGold.withOpacity(0.6),
                    blurRadius: 19.5, // Increased from 15 to 19.5 (30% larger)
                    spreadRadius: 2.6, // Increased from 2 to 2.6 (30% larger)
                  ),
                  BoxShadow(
                    color: Colors.black.withOpacity(0.3),
                    blurRadius: 13, // Increased from 10 to 13 (30% larger)
                    offset: const Offset(0, 6.5), // Increased from 5 to 6.5 (30% larger)
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSparkles() {
    return AnimatedBuilder(
      animation: _sparkleController,
      builder: (context, child) {
        return CustomPaint(
          size: Size.infinite,
          painter: SparklePainter(
            sparkles: _sparkles,
            animation: _sparkleController,
          ),
        );
      },
    );
  }

  Widget _buildTextOverlay() {
    return Positioned(
      bottom: 80,
      left: 0,
      right: 0,
      child: AnimatedBuilder(
        animation: _textRevealAnimation,
        builder: (context, child) {
          return Opacity(
            opacity: _textRevealAnimation.value,
            child: Column(
              children: [
                // Main title with shimmer effect
                ShaderMask(
                  shaderCallback: (bounds) {
                    return LinearGradient(
                      begin: Alignment(-1 + _shimmerAnimation.value, 0),
                      end: Alignment(1 + _shimmerAnimation.value, 0),
                      colors: [
                        _champagneGold.withOpacity(0.0),
                        _champagneGold,
                        _roseGold,
                        _champagneGold,
                        _champagneGold.withOpacity(0.0),
                      ],
                      stops: const [0.0, 0.3, 0.5, 0.7, 1.0],
                    ).createShader(bounds);
                  },
                  child: const Text(
                    'KOUTU',
                    style: TextStyle(
                      fontSize: 56,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 8,
                      color: Colors.white,
                    ),
                  ),
                ),
                
                const SizedBox(height: 10),
                
                // Animated subtitle
                Transform.scale(
                  scaleX: _textRevealAnimation.value,
                  child: Container(
                    height: 1,
                    width: 200,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Colors.transparent,
                          _champagneGold,
                          Colors.transparent,
                        ],
                      ),
                    ),
                  ),
                ),
                
                const SizedBox(height: 15),
                
                Text(
                  'LUXURY FASHION REIMAGINED',
                  style: TextStyle(
                    fontSize: 14,
                    letterSpacing: 4,
                    fontWeight: FontWeight.w300,
                    color: _champagneGold.withOpacity(0.9),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

// Custom painters and data classes

class ParallaxParticlePainter extends CustomPainter {
  final List<Particle> particles;
  final Animation<double> animation;
  final double parallaxFactor;

  ParallaxParticlePainter({
    required this.particles,
    required this.animation,
    required this.parallaxFactor,
  }) : super(repaint: animation);

  @override
  void paint(Canvas canvas, Size size) {
    for (var particle in particles) {
      final progress = animation.value;
      final parallaxOffset = Offset(
        particle.velocity.dx * progress * 100 * parallaxFactor,
        particle.velocity.dy * progress * 100 * parallaxFactor,
      );
      
      final position = Offset(
        (particle.position.dx + parallaxOffset.dx + size.width) % size.width,
        (particle.position.dy + parallaxOffset.dy + size.height) % size.height,
      );
      
      final paint = Paint()
        ..color = particle.color.withOpacity(0.6 * particle.depth)
        ..style = PaintingStyle.fill
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, 2 * (1 - particle.depth));
      
      canvas.drawCircle(position, particle.size * (0.5 + particle.depth * 0.5), paint);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => true;
}

class SpotlightPainter extends CustomPainter {
  final double intensity;
  final double glowIntensity;
  final Color color;

  SpotlightPainter({
    required this.intensity,
    required this.glowIntensity,
    required this.color,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height * 0.3);
    final radius = size.width * 0.6;
    
    final paint = Paint()
      ..shader = RadialGradient(
        colors: [
          color.withOpacity(0.3 * intensity * glowIntensity),
          color.withOpacity(0.1 * intensity),
          Colors.transparent,
        ],
        stops: const [0.0, 0.5, 1.0],
      ).createShader(Rect.fromCircle(center: center, radius: radius))
      ..maskFilter = MaskFilter.blur(BlurStyle.normal, 50);
    
    canvas.drawCircle(center, radius, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => true;
}

class MetallicTrimPainter extends CustomPainter {
  final bool isLeft;
  final Color color;

  MetallicTrimPainter({required this.isLeft, required this.color});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [
          color,
          color.withOpacity(0.6),
          color,
        ],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));
    
    // Draw ornate trim lines
    final path = Path();
    
    // Outer edge
    if (isLeft) {
      path.moveTo(0, 0);
      path.lineTo(0, size.height);
    } else {
      path.moveTo(size.width, 0);
      path.lineTo(size.width, size.height);
    }
    
    canvas.drawPath(path, paint);
    
    // Inner decorative lines
    paint.strokeWidth = 1;
    paint.color = color.withOpacity(0.5);
    
    for (int i = 1; i <= 3; i++) {
      final inset = i * 10.0;
      final decorativePath = Path();
      
      if (isLeft) {
        decorativePath.moveTo(inset, inset);
        decorativePath.lineTo(inset, size.height - inset);
      } else {
        decorativePath.moveTo(size.width - inset, inset);
        decorativePath.lineTo(size.width - inset, size.height - inset);
      }
      
      canvas.drawPath(decorativePath, paint);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class SparklePainter extends CustomPainter {
  final List<Sparkle> sparkles;
  final Animation<double> animation;

  SparklePainter({required this.sparkles, required this.animation}) : super(repaint: animation);

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..style = PaintingStyle.fill;
    
    for (var sparkle in sparkles) {
      sparkle.lifespan -= 0.02;
      if (sparkle.lifespan <= 0) continue;
      
      paint.color = Colors.white.withOpacity(sparkle.lifespan);
      
      final path = Path();
      final center = sparkle.position;
      final size = 5 * sparkle.lifespan;
      
      // Draw a 4-pointed star
      path.moveTo(center.dx, center.dy - size);
      path.lineTo(center.dx + size * 0.3, center.dy - size * 0.3);
      path.lineTo(center.dx + size, center.dy);
      path.lineTo(center.dx + size * 0.3, center.dy + size * 0.3);
      path.lineTo(center.dx, center.dy + size);
      path.lineTo(center.dx - size * 0.3, center.dy + size * 0.3);
      path.lineTo(center.dx - size, center.dy);
      path.lineTo(center.dx - size * 0.3, center.dy - size * 0.3);
      path.close();
      
      canvas.drawPath(path, paint);
    }
    
    sparkles.removeWhere((s) => s.lifespan <= 0);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => true;
}

// Data classes
class Particle {
  final Offset position;
  final Offset velocity;
  final double size;
  final Color color;
  final double depth;

  Particle({
    required this.position,
    required this.velocity,
    required this.size,
    required this.color,
    required this.depth,
  });
}

class Sparkle {
  final Offset position;
  double lifespan;

  Sparkle({required this.position, required this.lifespan});
}

class ClothingItem {
  final String type;
  final IconData icon;
  final Offset position;
  final double rotation;
  final double delay;

  ClothingItem({
    required this.type,
    required this.icon,
    required this.position,
    required this.rotation,
    required this.delay,
  });
}