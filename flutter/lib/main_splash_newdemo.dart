import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'dart:math';
import 'dart:ui' as ui;
import 'dart:async';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu Splash New Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        brightness: Brightness.dark,
      ),
      debugShowCheckedModeBanner: false,
      home: const NewEnhancedSplashScreen(),
    );
  }
}

/// New stunning splash screen with verified door animations
class NewEnhancedSplashScreen extends StatefulWidget {
  const NewEnhancedSplashScreen({super.key});

  @override
  State<NewEnhancedSplashScreen> createState() => _NewEnhancedSplashScreenState();
}

class _NewEnhancedSplashScreenState extends State<NewEnhancedSplashScreen>
    with TickerProviderStateMixin {
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
  final Color _obsidian = const Color(0xFF1A1E37);  // Lighter background
  final Color _royalPurple = const Color(0xFF6B5B95);
  final Color _champagneGold = const Color(0xFFD4AF37);
  final Color _roseGold = const Color(0xFFE8B4B8);
  final Color _midnight = const Color(0xFF2929A0);  // Lighter midnight
  
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

    // IMPORTANT: Configure door animations - DOORS OPEN OUTWARD DRAMATICALLY
    _leftDoorAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: -120.0) // Open wide outward
            .chain(CurveTween(curve: Curves.easeInOutQuart)),
        weight: 70.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: -120.0, end: -100.0) // Settle back slightly
            .chain(CurveTween(curve: Curves.elasticOut)),
        weight: 30.0,
      ),
    ]).animate(_doorController);

    _rightDoorAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 120.0) // Open wide outward
            .chain(CurveTween(curve: Curves.easeInOutQuart)),
        weight: 70.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 120.0, end: 100.0) // Settle back slightly
            .chain(CurveTween(curve: Curves.elasticOut)),
        weight: 30.0,
      ),
    ]).animate(_doorController);

    // Door shadow intensity
    _doorShadowAnimation = Tween<double>(
      begin: 30.0,
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
        tween: Tween<double>(begin: 1.0, end: 0.6),
        weight: 50.0,
      ),
    ]).animate(_lightController);

    // Wardrobe shake before opening
    _shakeAnimation = TweenSequence<double>([
      TweenSequenceItem(
        tween: Tween<double>(begin: 0.0, end: 8.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 8.0, end: -8.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: -8.0, end: 4.0),
        weight: 25.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 4.0, end: 0.0),
        weight: 25.0,
      ),
    ]).animate(CurvedAnimation(
      parent: _doorController,
      curve: const Interval(0.0, 0.2, curve: Curves.elasticIn),
    ));

    // Clothing animations
    _clothingFallAnimation = Tween<double>(
      begin: -200.0,
      end: 50.0,
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
        tween: Tween<double>(begin: 0.0, end: 1.3),
        weight: 70.0,
      ),
      TweenSequenceItem(
        tween: Tween<double>(begin: 1.3, end: 1.0),
        weight: 30.0,
      ),
    ]).animate(CurvedAnimation(
      parent: _textController,
      curve: Curves.elasticOut,
    ));

    _logoRotationAnimation = Tween<double>(
      begin: -0.2,
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
    // Create enhanced particle system
    for (int i = 0; i < 150; i++) {
      _backgroundParticles.add(Particle(
        position: Offset(
          Random().nextDouble() * 400 - 200,
          Random().nextDouble() * 800 - 400,
        ),
        velocity: Offset(
          Random().nextDouble() * 3 - 1.5,
          Random().nextDouble() * 3 - 1.5,
        ),
        size: Random().nextDouble() * 4 + 1,
        color: [_champagneGold, _roseGold, _royalPurple][Random().nextInt(3)],
        depth: Random().nextDouble(),
      ));
    }

    // Initialize clothing items with better positioning
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
          -150 + i * 75.0,
          -250.0,
        ),
        rotation: Random().nextDouble() * 0.8 - 0.4,
        delay: i * 0.15,
      ));
    }
  }

  void _startAnimationSequence() async {
    // Start background particles immediately
    _particleController.forward();
    
    // Build anticipation with shake
    await Future.delayed(const Duration(milliseconds: 300));
    print('🎭 NEW DEMO: Starting wardrobe animation sequence...');
    _doorController.forward();
    
    // Monitor door animation
    _doorController.addListener(() {
      if (_doorController.value > 0.1 && _doorController.value < 0.9) {
        print('🚪 Door opening: Left=${_leftDoorAnimation.value.toStringAsFixed(1)}° Right=${_rightDoorAnimation.value.toStringAsFixed(1)}°');
      }
    });
    
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
    await Future.delayed(const Duration(milliseconds: 2500));
    if (mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const DemoHomeScreen()),
      );
    }
  }

  void _generateSparkles() {
    Timer.periodic(const Duration(milliseconds: 80), (timer) {
      if (!mounted || _sparkles.length > 60) {
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
                    radius: 2.0 * _spotlightAnimation.value + 0.3,
                    colors: [
                      _champagneGold.withOpacity(0.2 * _spotlightAnimation.value),
                      _midnight.withOpacity(0.5 * _spotlightAnimation.value),
                      _obsidian,
                      Colors.black,
                    ],
                    stops: const [0.0, 0.3, 0.7, 1.0],
                  ),
                ),
              );
            },
          ),

          // Enhanced particle system
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
                    parallaxFactor: 1.0 - (layer * 0.25),
                  ),
                );
              },
            );
          }),

          // Enhanced spotlight effect
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
                    width: size.width * 0.85,
                    height: size.height * 0.75,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        // Enhanced magical glow
                        _buildMagicalGlow(),
                        
                        // Logo and content
                        _buildLogoContent(),
                        
                        // Clothing items falling out
                        _buildClothingItems(),
                        
                        // Luxury wardrobe doors
                        _buildLuxuryDoors(size.width * 0.85, size.height * 0.75),
                        
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
          
          // Debug overlay
          Positioned(
            top: 40,
            left: 20,
            child: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.7),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Text(
                'NEW DEMO VERSION',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMagicalGlow() {
    return AnimatedBuilder(
      animation: _glowAnimation,
      builder: (context, child) {
        return Container(
          width: 350,
          height: 350,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: _champagneGold.withOpacity(0.4 * _glowAnimation.value),
                blurRadius: 120,
                spreadRadius: 60,
              ),
              BoxShadow(
                color: _royalPurple.withOpacity(0.3 * _glowAnimation.value),
                blurRadius: 180,
                spreadRadius: 90,
              ),
              BoxShadow(
                color: _roseGold.withOpacity(0.2 * _glowAnimation.value),
                blurRadius: 200,
                spreadRadius: 100,
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
              width: 220,
              height: 220,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    _champagneGold,
                    _champagneGold.withOpacity(0.8),
                    _roseGold,
                  ],
                ),
                boxShadow: [
                  BoxShadow(
                    color: _champagneGold.withOpacity(0.6),
                    blurRadius: 40,
                    spreadRadius: 15,
                  ),
                  BoxShadow(
                    color: _roseGold.withOpacity(0.4),
                    blurRadius: 60,
                    spreadRadius: 20,
                  ),
                ],
              ),
              child: const Icon(
                Icons.auto_awesome,
                size: 110,
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
                angle: item.rotation + _clothingController.value * 0.8,
                child: Opacity(
                  opacity: _clothingOpacityAnimation.value,
                  child: Container(
                    width: 70,
                    height: 70,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: RadialGradient(
                        colors: [
                          _roseGold,
                          _royalPurple.withOpacity(0.7),
                        ],
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: _royalPurple.withOpacity(0.5),
                          blurRadius: 25,
                          spreadRadius: 8,
                        ),
                      ],
                    ),
                    child: Icon(
                      item.icon,
                      size: 35,
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
        // Left door - OPENS OUTWARD TO THE LEFT
        Positioned(
          left: 0,
          child: AnimatedBuilder(
            animation: _leftDoorAnimation,
            builder: (context, child) {
              return Transform(
                alignment: Alignment.centerRight,
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.001) // Perspective
                  ..rotateY(_leftDoorAnimation.value * (math.pi / 180)), // Negative = opens left
                child: _buildLuxuryDoor(
                  width: width / 2,
                  height: height,
                  isLeft: true,
                ),
              );
            },
          ),
        ),
        
        // Right door - OPENS OUTWARD TO THE RIGHT
        Positioned(
          right: 0,
          child: AnimatedBuilder(
            animation: _rightDoorAnimation,
            builder: (context, child) {
              return Transform(
                alignment: Alignment.centerLeft,
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.001) // Perspective
                  ..rotateY(_rightDoorAnimation.value * (math.pi / 180)), // Positive = opens right
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
          // Base door with enhanced gradient - BRIGHT RED FOR VISIBILITY
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: isLeft ? Alignment.centerRight : Alignment.centerLeft,
                end: isLeft ? Alignment.centerLeft : Alignment.centerRight,
                colors: const [
                  Color(0xFFFF0000),  // Bright red
                  Color(0xFFCC0000),  // Darker red
                  Color(0xFF990000),  // Even darker red
                  Color(0xFF660000),  // Deep red
                ],
              ),
              borderRadius: BorderRadius.only(
                topLeft: isLeft ? const Radius.circular(20) : Radius.zero,
                topRight: !isLeft ? const Radius.circular(20) : Radius.zero,
                bottomLeft: isLeft ? const Radius.circular(20) : Radius.zero,
                bottomRight: !isLeft ? const Radius.circular(20) : Radius.zero,
              ),
              border: Border.all(
                color: Colors.white,
                width: 3,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.6),
                  blurRadius: _doorShadowAnimation.value,
                  offset: Offset(isLeft ? -15 : 15, 15),
                ),
                BoxShadow(
                  color: _royalPurple.withOpacity(0.3),
                  blurRadius: _doorShadowAnimation.value * 0.5,
                  offset: Offset(isLeft ? -5 : 5, 5),
                ),
              ],
            ),
          ),
          
          // Enhanced metallic trim
          CustomPaint(
            size: Size(width, height),
            painter: MetallicTrimPainter(
              isLeft: isLeft,
              color: _champagneGold,
            ),
          ),
          
          // Glass panel with enhanced reflection
          Positioned(
            top: 60,
            left: isLeft ? 35 : 25,
            right: isLeft ? 25 : 35,
            bottom: 60,
            child: Container(
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    Colors.white.withOpacity(0.15),
                    Colors.white.withOpacity(0.08),
                    Colors.transparent,
                  ],
                ),
                border: Border.all(
                  color: _champagneGold.withOpacity(0.6),
                  width: 2.5,
                ),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(10),
                child: BackdropFilter(
                  filter: ui.ImageFilter.blur(sigmaX: 15, sigmaY: 15),
                  child: Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [
                          Colors.white.withOpacity(0.05),
                          Colors.transparent,
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
          
          // Ornate handle with glow
          Positioned(
            top: height / 2 - 60,
            left: isLeft ? null : 35,
            right: isLeft ? 35 : null,
            child: Container(
              width: 18,
              height: 120,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    _champagneGold,
                    _champagneGold.withOpacity(0.9),
                    _roseGold,
                    _champagneGold.withOpacity(0.9),
                    _champagneGold,
                  ],
                ),
                borderRadius: BorderRadius.circular(9),
                boxShadow: [
                  BoxShadow(
                    color: _champagneGold.withOpacity(0.8),
                    blurRadius: 20,
                    spreadRadius: 3,
                  ),
                  BoxShadow(
                    color: Colors.black.withOpacity(0.4),
                    blurRadius: 15,
                    offset: const Offset(0, 8),
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
      bottom: 100,
      left: 0,
      right: 0,
      child: AnimatedBuilder(
        animation: _textRevealAnimation,
        builder: (context, child) {
          return Opacity(
            opacity: _textRevealAnimation.value,
            child: Column(
              children: [
                // Main title with enhanced shimmer
                ShaderMask(
                  shaderCallback: (bounds) {
                    return LinearGradient(
                      begin: Alignment(-1 + _shimmerAnimation.value, 0),
                      end: Alignment(1 + _shimmerAnimation.value, 0),
                      colors: [
                        _champagneGold.withOpacity(0.0),
                        _champagneGold,
                        Colors.white,
                        _roseGold,
                        _champagneGold,
                        _champagneGold.withOpacity(0.0),
                      ],
                      stops: const [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
                    ).createShader(bounds);
                  },
                  child: const Text(
                    'KOUTU',
                    style: TextStyle(
                      fontSize: 64,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 12,
                      color: Colors.white,
                    ),
                  ),
                ),
                
                const SizedBox(height: 12),
                
                // Animated line
                Transform.scale(
                  scaleX: _textRevealAnimation.value,
                  child: Container(
                    height: 2,
                    width: 250,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Colors.transparent,
                          _champagneGold,
                          _roseGold,
                          _champagneGold,
                          Colors.transparent,
                        ],
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: _champagneGold.withOpacity(0.5),
                          blurRadius: 10,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                  ),
                ),
                
                const SizedBox(height: 20),
                
                Text(
                  'LUXURY FASHION REIMAGINED',
                  style: TextStyle(
                    fontSize: 16,
                    letterSpacing: 5,
                    fontWeight: FontWeight.w300,
                    color: _champagneGold,
                    shadows: [
                      Shadow(
                        color: _champagneGold.withOpacity(0.5),
                        blurRadius: 10,
                      ),
                    ],
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

// Enhanced Custom Painters
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
        particle.velocity.dx * progress * 120 * parallaxFactor,
        particle.velocity.dy * progress * 120 * parallaxFactor,
      );
      
      final position = Offset(
        (particle.position.dx + parallaxOffset.dx + size.width) % size.width,
        (particle.position.dy + parallaxOffset.dy + size.height) % size.height,
      );
      
      final paint = Paint()
        ..color = particle.color.withOpacity(0.7 * particle.depth)
        ..style = PaintingStyle.fill
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, 3 * (1 - particle.depth));
      
      canvas.drawCircle(position, particle.size * (0.6 + particle.depth * 0.4), paint);
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
    final center = Offset(size.width / 2, size.height * 0.35);
    final radius = size.width * 0.7;
    
    final paint = Paint()
      ..shader = RadialGradient(
        colors: [
          color.withOpacity(0.4 * intensity * glowIntensity),
          color.withOpacity(0.2 * intensity),
          color.withOpacity(0.05 * intensity),
          Colors.transparent,
        ],
        stops: const [0.0, 0.3, 0.6, 1.0],
      ).createShader(Rect.fromCircle(center: center, radius: radius))
      ..maskFilter = MaskFilter.blur(BlurStyle.normal, 60);
    
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
      ..strokeWidth = 4
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [
          color,
          color.withOpacity(0.7),
          color,
          color.withOpacity(0.5),
          color,
        ],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));
    
    // Draw main trim
    final path = Path();
    
    if (isLeft) {
      path.moveTo(0, 0);
      path.lineTo(0, size.height);
    } else {
      path.moveTo(size.width, 0);
      path.lineTo(size.width, size.height);
    }
    
    canvas.drawPath(path, paint);
    
    // Inner decorative lines
    paint.strokeWidth = 1.5;
    paint.color = color.withOpacity(0.6);
    
    for (int i = 1; i <= 3; i++) {
      final inset = i * 12.0;
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
      sparkle.lifespan -= 0.015;
      if (sparkle.lifespan <= 0) continue;
      
      paint.color = Colors.white.withOpacity(sparkle.lifespan * 0.9);
      
      final path = Path();
      final center = sparkle.position;
      final size = 6 * sparkle.lifespan;
      
      // Draw an 8-pointed star
      for (int i = 0; i < 8; i++) {
        final angle = (i * math.pi / 4);
        final length = i % 2 == 0 ? size : size * 0.5;
        final x = center.dx + math.cos(angle) * length;
        final y = center.dy + math.sin(angle) * length;
        
        if (i == 0) {
          path.moveTo(x, y);
        } else {
          path.lineTo(x, y);
        }
      }
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

// Simple demo home screen
class DemoHomeScreen extends StatelessWidget {
  const DemoHomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E27),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.checkroom,
              size: 90,
              color: Colors.white.withOpacity(0.9),
            ),
            const SizedBox(height: 24),
            const Text(
              'Welcome to KOUTU',
              style: TextStyle(
                fontSize: 36,
                fontWeight: FontWeight.bold,
                color: Colors.white,
                letterSpacing: 3,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Your Digital Wardrobe',
              style: TextStyle(
                fontSize: 20,
                color: Colors.white.withOpacity(0.7),
                letterSpacing: 1.5,
              ),
            ),
            const SizedBox(height: 50),
            ElevatedButton(
              onPressed: () {
                Navigator.of(context).pushReplacement(
                  MaterialPageRoute(builder: (_) => const NewEnhancedSplashScreen()),
                );
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFD4AF37),
                padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 18),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(30),
                ),
              ),
              child: const Text(
                'View Splash Screen Again',
                style: TextStyle(
                  color: Colors.black,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}