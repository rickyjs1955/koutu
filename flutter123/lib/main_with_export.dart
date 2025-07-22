import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'native_video_exporter.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Hello App',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      debugShowCheckedModeBanner: false,
      home: const ExportableKoutuAnimation(),
    );
  }
}

class ExportableKoutuAnimation extends StatefulWidget {
  const ExportableKoutuAnimation({Key? key}) : super(key: key);

  @override
  State<ExportableKoutuAnimation> createState() => _ExportableKoutuAnimationState();
}

class _ExportableKoutuAnimationState extends State<ExportableKoutuAnimation> {
  final GlobalKey<HelloSplashScreenState> _splashKey = GlobalKey();

  void _restartAnimation() {
    _splashKey.currentState?.restartAnimation();
  }

  @override
  Widget build(BuildContext context) {
    return NativeVideoExporter(
      animationDuration: const Duration(seconds: 8),
      onAnimationComplete: _restartAnimation,
      child: HelloSplashScreen(key: _splashKey),
    );
  }
}

class HelloSplashScreen extends StatefulWidget {
  const HelloSplashScreen({Key? key}) : super(key: key);

  @override
  State<HelloSplashScreen> createState() => HelloSplashScreenState();
}

class HelloSplashScreenState extends State<HelloSplashScreen>
    with TickerProviderStateMixin {
  late AnimationController _doorController;
  late AnimationController _contentController;
  late AnimationController _particleController;
  late AnimationController _logoGlowController;
  
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  late Animation<double> _contentFadeAnimation;
  late Animation<double> _contentScaleAnimation;
  late Animation<double> _glowAnimation;
  late Animation<double> _lightBeamAnimation;
  late Animation<double> _logoGlowAnimation;
  
  bool _isLoading = true;
  bool _showContent = false;
  bool _preventNavigation = false;

  @override
  void initState() {
    super.initState();
    
    // Door opening animation controller
    _doorController = AnimationController(
      duration: const Duration(milliseconds: 2500),
      vsync: this,
    );
    
    // Content reveal animation controller
    _contentController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );
    
    // Particle effect controller - continuous
    _particleController = AnimationController(
      duration: const Duration(seconds: 4),
      vsync: this,
    )..repeat();
    
    // Logo glow controller - pulsing
    _logoGlowController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);
    
    // Door animations - opening outward (reversed direction)
    _leftDoorAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _doorController,
      curve: Curves.easeInOutCubic,
    ));
    
    _rightDoorAnimation = Tween<double>(
      begin: 0.0,
      end: -1.0,
    ).animate(CurvedAnimation(
      parent: _doorController,
      curve: Curves.easeInOutCubic,
    ));
    
    // Content animations
    _contentFadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _contentController,
      curve: const Interval(0.3, 1.0, curve: Curves.easeIn),
    ));
    
    _contentScaleAnimation = Tween<double>(
      begin: 0.8,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _contentController,
      curve: Curves.elasticOut,
    ));
    
    // Glow animation - intensifies as doors open
    _glowAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _doorController,
      curve: Curves.easeInOut,
    ));
    
    // Light beam animation - intensifies as doors open
    _lightBeamAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _doorController,
      curve: const Interval(0.3, 1.0, curve: Curves.easeIn),
    ));
    
    // Logo glow animation - pulsing effect
    _logoGlowAnimation = Tween<double>(
      begin: 0.3,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _logoGlowController,
      curve: Curves.easeInOut,
    ));
    
    // Start animation sequence
    _startAnimation();
  }

  void _startAnimation() {
    Future.delayed(const Duration(milliseconds: 500), () {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
        _doorController.forward().then((_) {
          setState(() {
            _showContent = true;
          });
          _contentController.forward().then((_) {
            if (!_preventNavigation) {
              Future.delayed(const Duration(seconds: 2), () {
                if (mounted && !_preventNavigation) {
                  Navigator.of(context).pushReplacement(
                    MaterialPageRoute(builder: (context) => const HomePage()),
                  );
                }
              });
            }
          });
        });
      }
    });
  }

  void restartAnimation() {
    setState(() {
      _preventNavigation = true;
      _isLoading = true;
      _showContent = false;
    });
    
    _doorController.reset();
    _contentController.reset();
    
    _startAnimation();
  }

  @override
  void dispose() {
    _doorController.dispose();
    _contentController.dispose();
    _particleController.dispose();
    _logoGlowController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final bool isMobile = size.width < 600;
    
    return Scaffold(
      body: Stack(
        children: [
          // Warm home background
          Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  Color(0xFFFFF8E1), // Warm cream
                  Color(0xFFFFE0B2), // Light peach
                ],
              ),
            ),
          ),
          
          // Particle effects - golden sparkles
          AnimatedBuilder(
            animation: _particleController,
            builder: (context, child) {
              return CustomPaint(
                painter: ParticlePainter(
                  progress: _particleController.value,
                  glowProgress: _doorController.value,
                ),
                size: size,
              );
            },
          ),
          
          // Main content
          Center(
            child: _isLoading
                ? const CircularProgressIndicator(
                    color: Color(0xFFFFD700),
                  )
                : Stack(
                    alignment: Alignment.center,
                    children: [
                      // Treasure light effect behind doors
                      AnimatedBuilder(
                        animation: _doorController,
                        builder: (context, child) {
                          return Opacity(
                            opacity: _lightBeamAnimation.value,
                            child: CustomPaint(
                              painter: TreasureLightPainter(
                                intensity: _lightBeamAnimation.value,
                                doorOpenProgress: _doorController.value,
                              ),
                              size: Size(
                                size.width * 0.85,
                                size.height * 0.55,
                              ),
                            ),
                          );
                        },
                      ),
                      
                      // Glow effect behind doors
                      AnimatedBuilder(
                        animation: _doorController,
                        builder: (context, child) {
                          return Container(
                            width: 455 * (isMobile ? 0.7 : 1.0), // 350 * 1.3
                            height: 585 * (isMobile ? 0.7 : 1.0), // 450 * 1.3
                            decoration: BoxDecoration(
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFFFFD700).withOpacity(
                                    _glowAnimation.value * 0.5,
                                  ),
                                  blurRadius: 50,
                                  spreadRadius: 20,
                                ),
                              ],
                            ),
                          );
                        },
                      ),
                      
                      // Wardrobe doors
                      SizedBox(
                        width: 455 * (isMobile ? 0.7 : 1.0), // 350 * 1.3
                        height: 585 * (isMobile ? 0.7 : 1.0), // 450 * 1.3
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                            // Wardrobe frame
                            Container(
                              decoration: BoxDecoration(
                                color: const Color(0xFF8B4513),
                                borderRadius: BorderRadius.circular(8),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withOpacity(0.3),
                                    blurRadius: 20,
                                    offset: const Offset(0, 10),
                                  ),
                                ],
                              ),
                            ),
                            
                            // Inside wardrobe content (revealed when doors open)
                            if (_showContent)
                              AnimatedBuilder(
                                animation: _contentController,
                                builder: (context, child) {
                                  return Opacity(
                                    opacity: _contentFadeAnimation.value,
                                    child: Transform.scale(
                                      scale: _contentScaleAnimation.value,
                                      child: Padding(
                                        padding: const EdgeInsets.all(20.0),
                                        child: Column(
                                          mainAxisAlignment: MainAxisAlignment.center,
                                          children: [
                                            // Wardrobe interior
                                            Container(
                                              height: 390 * (isMobile ? 0.7 : 1.0), // 300 * 1.3
                                              child: Stack(
                                                children: [
                                                  // Background
                                                  Container(
                                                    decoration: BoxDecoration(
                                                      color: const Color(0xFF4A3728),
                                                      borderRadius: BorderRadius.circular(4),
                                                    ),
                                                  ),
                                                  // Hanging clothes rod
                                                  Positioned(
                                                    top: 20,
                                                    left: 20,
                                                    right: 20,
                                                    child: Container(
                                                      height: 8,
                                                      decoration: BoxDecoration(
                                                        color: const Color(0xFF8B7355),
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
                                                  // Hanging clothes
                                                  Positioned(
                                                    top: 30,
                                                    left: 0,
                                                    right: 0,
                                                    height: 234 * (isMobile ? 0.7 : 1.0), // 180 * 1.3
                                                    child: CustomPaint(
                                                      painter: ClothingPainter(),
                                                      size: Size.infinite,
                                                    ),
                                                  ),
                                                  // Folded clothes piles at bottom
                                                  Positioned(
                                                    bottom: 0,
                                                    left: 0,
                                                    right: 0,
                                                    height: 104 * (isMobile ? 0.7 : 1.0), // 80 * 1.3
                                                    child: CustomPaint(
                                                      painter: FoldedClothesPainter(),
                                                      size: Size.infinite,
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
                                },
                              ),
                            
                            // Left door
                            AnimatedBuilder(
                              animation: _doorController,
                              builder: (context, child) {
                                return Positioned(
                                  left: 0,
                                  top: 0,
                                  child: Transform(
                                    alignment: Alignment.centerLeft,
                                    transform: Matrix4.identity()
                                      ..setEntry(3, 2, 0.001)
                                      ..rotateY(_leftDoorAnimation.value * math.pi / 2.2),
                                    child: Container(
                                      width: 227.5 * (isMobile ? 0.7 : 1.0), // 175 * 1.3
                                      height: 585 * (isMobile ? 0.7 : 1.0), // 450 * 1.3
                                      decoration: BoxDecoration(
                                        color: const Color(0xFF6D4C41),
                                        borderRadius: const BorderRadius.only(
                                          topLeft: Radius.circular(8),
                                          bottomLeft: Radius.circular(8),
                                        ),
                                        border: Border.all(
                                          color: const Color(0xFF5D4037),
                                          width: 2,
                                        ),
                                        boxShadow: [
                                          BoxShadow(
                                            color: Colors.black.withOpacity(0.2),
                                            blurRadius: 10,
                                            offset: const Offset(-5, 0),
                                          ),
                                        ],
                                      ),
                                      child: Center(
                                        child: Container(
                                          width: 39 * (isMobile ? 0.7 : 1.0), // 30 * 1.3
                                          height: 39 * (isMobile ? 0.7 : 1.0), // 30 * 1.3
                                          decoration: BoxDecoration(
                                            shape: BoxShape.circle,
                                            color: const Color(0xFFFFD700),
                                            boxShadow: [
                                              BoxShadow(
                                                color: const Color(0xFFFFD700).withOpacity(0.5),
                                                blurRadius: 10,
                                              ),
                                            ],
                                          ),
                                        ),
                                      ),
                                    ),
                                  ),
                                );
                              },
                            ),
                            
                            // Right door
                            AnimatedBuilder(
                              animation: _doorController,
                              builder: (context, child) {
                                return Positioned(
                                  right: 0,
                                  top: 0,
                                  child: Transform(
                                    alignment: Alignment.centerRight,
                                    transform: Matrix4.identity()
                                      ..setEntry(3, 2, 0.001)
                                      ..rotateY(_rightDoorAnimation.value * math.pi / 2.2),
                                    child: Container(
                                      width: 227.5 * (isMobile ? 0.7 : 1.0), // 175 * 1.3
                                      height: 585 * (isMobile ? 0.7 : 1.0), // 450 * 1.3
                                      decoration: BoxDecoration(
                                        color: const Color(0xFF6D4C41),
                                        borderRadius: const BorderRadius.only(
                                          topRight: Radius.circular(8),
                                          bottomRight: Radius.circular(8),
                                        ),
                                        border: Border.all(
                                          color: const Color(0xFF5D4037),
                                          width: 2,
                                        ),
                                        boxShadow: [
                                          BoxShadow(
                                            color: Colors.black.withOpacity(0.2),
                                            blurRadius: 10,
                                            offset: const Offset(5, 0),
                                          ),
                                        ],
                                      ),
                                      child: Center(
                                        child: Container(
                                          width: 39 * (isMobile ? 0.7 : 1.0), // 30 * 1.3
                                          height: 39 * (isMobile ? 0.7 : 1.0), // 30 * 1.3
                                          decoration: BoxDecoration(
                                            shape: BoxShape.circle,
                                            color: const Color(0xFFFFD700),
                                            boxShadow: [
                                              BoxShadow(
                                                color: const Color(0xFFFFD700).withOpacity(0.5),
                                                blurRadius: 10,
                                              ),
                                            ],
                                          ),
                                        ),
                                      ),
                                    ),
                                  ),
                                );
                              },
                            ),
                          ],
                        ),
                      ),
                      
                      // Logo and tagline below wardrobe
                      Positioned(
                        bottom: 50 * (isMobile ? 0.7 : 1.0),
                        child: AnimatedBuilder(
                          animation: _logoGlowController,
                          builder: (context, child) {
                            return Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                // KOUTU logo with lightning effect
                                Stack(
                                  alignment: Alignment.center,
                                  children: [
                                    // Lightning glow effect
                                    CustomPaint(
                                      painter: LightningGlowPainter(
                                        glowIntensity: _logoGlowAnimation.value,
                                      ),
                                      size: Size(250 * (isMobile ? 0.7 : 1.0), 100 * (isMobile ? 0.7 : 1.0)),
                                    ),
                                    // Main text
                                    ShaderMask(
                                      shaderCallback: (bounds) => LinearGradient(
                                        colors: [
                                          const Color(0xFFFFD700),
                                          const Color(0xFFFFA500),
                                          const Color(0xFFFFD700),
                                        ],
                                        stops: [
                                          0.0,
                                          _logoGlowAnimation.value,
                                          1.0,
                                        ],
                                      ).createShader(bounds),
                                      child: Text(
                                        'KOUTU',
                                        style: TextStyle(
                                          fontSize: 78 * (isMobile ? 0.7 : 1.0), // 60 * 1.3
                                          fontWeight: FontWeight.bold,
                                          color: Colors.white,
                                          letterSpacing: 8,
                                          shadows: [
                                            Shadow(
                                              color: const Color(0xFFFFD700).withOpacity(0.8),
                                              blurRadius: 20,
                                              offset: const Offset(0, 0),
                                            ),
                                          ],
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 10),
                                Text(
                                  'Your Digital Wardrobe',
                                  style: TextStyle(
                                    fontSize: 23.4 * (isMobile ? 0.7 : 1.0), // 18 * 1.3
                                    fontWeight: FontWeight.w300,
                                    color: const Color(0xFF6D4C41),
                                    letterSpacing: 2,
                                  ),
                                ),
                              ],
                            );
                          },
                        ),
                      ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

// Particle Painter for golden sparkles
class ParticlePainter extends CustomPainter {
  final double progress;
  final double glowProgress;
  
  ParticlePainter({required this.progress, required this.glowProgress});
  
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = const Color(0xFFFFD700).withOpacity(0.3 + glowProgress * 0.4)
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3);
    
    final random = math.Random(42);
    
    for (int i = 0; i < 50; i++) {
      final x = random.nextDouble() * size.width;
      final baseY = random.nextDouble() * size.height;
      final floatOffset = math.sin(progress * 2 * math.pi + i) * 20;
      final y = baseY + floatOffset;
      
      final particleSize = random.nextDouble() * 3 + 1;
      final opacity = (math.sin(progress * 2 * math.pi + i * 0.5) + 1) / 2;
      
      paint.color = const Color(0xFFFFD700).withOpacity(opacity * 0.6 * glowProgress);
      canvas.drawCircle(Offset(x, y), particleSize, paint);
    }
  }
  
  @override
  bool shouldRepaint(ParticlePainter oldDelegate) => true;
}

// Treasure light effect painter
class TreasureLightPainter extends CustomPainter {
  final double intensity;
  final double doorOpenProgress;
  
  TreasureLightPainter({required this.intensity, required this.doorOpenProgress});
  
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    
    // Create multiple light beams
    for (int i = 0; i < 12; i++) {
      final angle = (i * 30) * math.pi / 180;
      final beamLength = size.width * 0.8 * intensity;
      final beamWidth = 20.0 * (1 + math.sin(doorOpenProgress * math.pi)) * intensity;
      
      final paint = Paint()
        ..shader = RadialGradient(
          colors: [
            const Color(0xFFFFD700).withOpacity(0.8 * intensity),
            const Color(0xFFFFA500).withOpacity(0.4 * intensity),
            Colors.transparent,
          ],
          stops: const [0.0, 0.5, 1.0],
        ).createShader(Rect.fromCircle(center: center, radius: beamLength))
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, beamWidth);
      
      final path = Path()
        ..moveTo(center.dx, center.dy)
        ..lineTo(
          center.dx + math.cos(angle) * beamLength,
          center.dy + math.sin(angle) * beamLength,
        );
      
      canvas.drawPath(path, paint);
    }
    
    // Central glow
    final centralGlow = Paint()
      ..shader = RadialGradient(
        colors: [
          const Color(0xFFFFD700).withOpacity(intensity),
          const Color(0xFFFFA500).withOpacity(0.5 * intensity),
          Colors.transparent,
        ],
      ).createShader(Rect.fromCircle(center: center, radius: 100))
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 50);
    
    canvas.drawCircle(center, 100 * intensity, centralGlow);
  }
  
  @override
  bool shouldRepaint(TreasureLightPainter oldDelegate) => true;
}

// Clothing painter for hanging items
class ClothingPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..style = PaintingStyle.fill;
    
    // Clothing items data
    final items = [
      {'x': 0.15, 'color': const Color(0xFF1976D2), 'type': 'shirt'},     // Blue shirt
      {'x': 0.25, 'color': const Color(0xFF424242), 'type': 'suit'},      // Dark suit
      {'x': 0.35, 'color': const Color(0xFFE91E63), 'type': 'dress'},     // Pink dress
      {'x': 0.45, 'color': const Color(0xFF757575), 'type': 'jacket'},    // Gray jacket
      {'x': 0.55, 'color': const Color(0xFF4CAF50), 'type': 'shirt'},     // Green shirt
      {'x': 0.65, 'color': const Color(0xFF3F51B5), 'type': 'jeans'},     // Blue jeans
      {'x': 0.75, 'color': const Color(0xFFFF5722), 'type': 'dress'},     // Orange dress
      {'x': 0.85, 'color': const Color(0xFF795548), 'type': 'coat'},      // Brown coat
    ];
    
    for (final item in items) {
      final x = size.width * (item['x'] as double);
      paint.color = item['color'] as Color;
      
      // Draw hanger
      final hangerPaint = Paint()
        ..color = const Color(0xFF8B7355)
        ..strokeWidth = 2
        ..style = PaintingStyle.stroke;
      
      canvas.drawLine(
        Offset(x, 0),
        Offset(x, 10),
        hangerPaint,
      );
      
      // Draw clothing item based on type
      final type = item['type'] as String;
      
      if (type == 'shirt' || type == 'suit' || type == 'jacket' || type == 'coat') {
        // Draw upper body garment
        final path = Path()
          ..moveTo(x - 20, 10)
          ..lineTo(x - 15, 20)
          ..lineTo(x - 15, 80)
          ..lineTo(x + 15, 80)
          ..lineTo(x + 15, 20)
          ..lineTo(x + 20, 10)
          ..close();
        
        canvas.drawPath(path, paint);
        
        // Add collar detail
        paint.color = paint.color.withOpacity(0.8);
        canvas.drawRect(Rect.fromLTWH(x - 10, 10, 20, 8), paint);
      } else if (type == 'dress') {
        // Draw dress
        final path = Path()
          ..moveTo(x - 15, 10)
          ..lineTo(x - 12, 30)
          ..lineTo(x - 20, 100)
          ..lineTo(x + 20, 100)
          ..lineTo(x + 12, 30)
          ..lineTo(x + 15, 10)
          ..close();
        
        canvas.drawPath(path, paint);
      } else if (type == 'jeans') {
        // Draw pants
        final path = Path()
          ..moveTo(x - 12, 10)
          ..lineTo(x - 12, 50)
          ..lineTo(x - 15, 90)
          ..lineTo(x - 8, 90)
          ..lineTo(x, 50)
          ..lineTo(x + 8, 90)
          ..lineTo(x + 15, 90)
          ..lineTo(x + 12, 50)
          ..lineTo(x + 12, 10)
          ..close();
        
        canvas.drawPath(path, paint);
      }
      
      // Add shadow
      final shadowPaint = Paint()
        ..color = Colors.black.withOpacity(0.2)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3);
      
      canvas.drawRect(
        Rect.fromLTWH(x - 20, 20, 40, 80),
        shadowPaint,
      );
    }
  }
  
  @override
  bool shouldRepaint(ClothingPainter oldDelegate) => false;
}

// Folded clothes painter
class FoldedClothesPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..style = PaintingStyle.fill;
    
    // Different pile configurations
    final piles = [
      {'x': 0.2, 'height': 0.7, 'colors': [const Color(0xFF1565C0), const Color(0xFF42A5F5), const Color(0xFF90CAF9)]},
      {'x': 0.4, 'height': 0.5, 'colors': [const Color(0xFF2E7D32), const Color(0xFF66BB6A), const Color(0xFF4CAF50)]},
      {'x': 0.6, 'height': 0.8, 'colors': [const Color(0xFF6A1B9A), const Color(0xFF9C27B0), const Color(0xFFBA68C8)]},
      {'x': 0.8, 'height': 0.6, 'colors': [const Color(0xFFE65100), const Color(0xFFFF6F00), const Color(0xFFFFB74D)]},
    ];
    
    for (final pile in piles) {
      final x = size.width * (pile['x'] as double);
      final maxHeight = size.height * (pile['height'] as double);
      final colors = pile['colors'] as List<Color>;
      
      // Draw stacked folded clothes
      for (int i = 0; i < colors.length; i++) {
        final y = size.height - (i + 1) * (maxHeight / colors.length);
        final itemHeight = maxHeight / colors.length * 0.8;
        
        paint.color = colors[i];
        
        // Main folded item
        final rect = RRect.fromRectAndRadius(
          Rect.fromLTWH(x - 30, y, 60, itemHeight),
          const Radius.circular(4),
        );
        canvas.drawRRect(rect, paint);
        
        // Fold line
        final foldPaint = Paint()
          ..color = colors[i].withOpacity(0.7)
          ..strokeWidth = 1;
        canvas.drawLine(
          Offset(x - 30, y + itemHeight * 0.4),
          Offset(x + 30, y + itemHeight * 0.4),
          foldPaint,
        );
        
        // Shadow
        final shadowPaint = Paint()
          ..color = Colors.black.withOpacity(0.1)
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 2);
        canvas.drawRRect(
          rect.shift(const Offset(0, 2)),
          shadowPaint,
        );
      }
    }
  }
  
  @override
  bool shouldRepaint(FoldedClothesPainter oldDelegate) => false;
}

// Lightning glow painter for logo
class LightningGlowPainter extends CustomPainter {
  final double glowIntensity;
  
  LightningGlowPainter({required this.glowIntensity});
  
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final random = math.Random(42);
    
    // Draw lightning bolts around text
    for (int i = 0; i < 8; i++) {
      final angle = (i * 45 + random.nextDouble() * 20) * math.pi / 180;
      final startRadius = 40.0;
      final endRadius = 60.0 + random.nextDouble() * 20;
      
      final start = Offset(
        center.dx + math.cos(angle) * startRadius,
        center.dy + math.sin(angle) * startRadius,
      );
      
      final end = Offset(
        center.dx + math.cos(angle) * endRadius,
        center.dy + math.sin(angle) * endRadius,
      );
      
      // Lightning path with jagged pattern
      final path = Path()..moveTo(start.dx, start.dy);
      
      final segments = 3 + random.nextInt(2);
      for (int j = 1; j <= segments; j++) {
        final t = j / segments;
        final baseX = start.dx + (end.dx - start.dx) * t;
        final baseY = start.dy + (end.dy - start.dy) * t;
        
        final offset = (random.nextDouble() - 0.5) * 15;
        final perpAngle = angle + math.pi / 2;
        
        path.lineTo(
          baseX + math.cos(perpAngle) * offset,
          baseY + math.sin(perpAngle) * offset,
        );
      }
      
      // Draw lightning bolt
      final paint = Paint()
        ..color = const Color(0xFFFFD700).withOpacity(glowIntensity * 0.8)
        ..strokeWidth = 2
        ..style = PaintingStyle.stroke
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, 3 * glowIntensity);
      
      canvas.drawPath(path, paint);
      
      // Add glow
      final glowPaint = Paint()
        ..color = const Color(0xFFFFD700).withOpacity(glowIntensity * 0.3)
        ..strokeWidth = 6
        ..style = PaintingStyle.stroke
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, 8 * glowIntensity);
      
      canvas.drawPath(path, glowPaint);
    }
  }
  
  @override
  bool shouldRepaint(LightningGlowPainter oldDelegate) => true;
}

// Home page placeholder
class HomePage extends StatelessWidget {
  const HomePage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFFFFF8E1),
              Color(0xFFFFE0B2),
            ],
          ),
        ),
        child: const Center(
          child: Text(
            'Welcome Home',
            style: TextStyle(
              fontSize: 32,
              fontWeight: FontWeight.bold,
              color: Color(0xFF6D4C41),
            ),
          ),
        ),
      ),
    );
  }
}