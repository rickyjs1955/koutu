import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'wardrobe_page.dart';

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
      home: const HelloSplashScreen(),
    );
  }
}

class HelloSplashScreen extends StatefulWidget {
  const HelloSplashScreen({Key? key}) : super(key: key);

  @override
  State<HelloSplashScreen> createState() => _HelloSplashScreenState();
}

class _HelloSplashScreenState extends State<HelloSplashScreen>
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
    
    // Particle effect controller
    _particleController = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    )..repeat();
    
    // Logo glow animation controller
    _logoGlowController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);

    // Door animations - starts closed (0.0) opens outward (1.0)
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
    
    // Glow effect animation
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
            Future.delayed(const Duration(seconds: 2), () {
              if (mounted) {
                Navigator.of(context).pushReplacement(
                  MaterialPageRoute(builder: (context) => const WardrobePage()),
                );
              }
            });
          });
        });
      }
    });
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
          // Home interior background
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  const Color(0xFFF5E6D3), // Warm cream ceiling
                  const Color(0xFFE8D5C4), // Light beige wall
                  const Color(0xFFD4C4B0), // Darker beige floor area
                ],
                stops: const [0.0, 0.5, 1.0],
              ),
            ),
          ),
          
          // Wall texture and home elements
          CustomPaint(
            painter: HomeBackgroundPainter(),
            size: size,
          ),
          
          // Particle effects background
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
                    valueColor: AlwaysStoppedAnimation<Color>(Colors.white70),
                  )
                : Container(
                    padding: const EdgeInsets.symmetric(vertical: 20),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        // Wardrobe with clothes
                        Flexible(
                          child: ConstrainedBox(
                            constraints: BoxConstraints(
                              maxWidth: math.min(size.width * 0.95, 1300),
                              maxHeight: size.height * 0.78,
                            ),
                            child: AspectRatio(
                              aspectRatio: 1.5,
                              child: SizedBox(
                                width: double.infinity,
                                height: double.infinity,
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                        // Treasure light effect - golden light from inside
                        AnimatedBuilder(
                          animation: _lightBeamAnimation,
                          builder: (context, child) {
                            return CustomPaint(
                              painter: TreasureLightPainter(
                                intensity: _lightBeamAnimation.value,
                                doorOpenProgress: _doorController.value,
                              ),
                              child: Container(),
                            );
                          },
                        ),
                        
                        // Glow effect behind doors
                        AnimatedBuilder(
                          animation: _glowAnimation,
                          builder: (context, child) {
                            return Container(
                              width: double.infinity,
                              height: double.infinity,
                              decoration: BoxDecoration(
                                gradient: RadialGradient(
                                  colors: [
                                    const Color(0xFFFFD700).withOpacity(_glowAnimation.value * 0.4),
                                    const Color(0xFFFFA500).withOpacity(_glowAnimation.value * 0.2),
                                    Colors.transparent,
                                  ],
                                  radius: 1.5,
                                  center: Alignment.center,
                                ),
                              ),
                            );
                          },
                        ),
                        
                        // Clothing items behind doors (revealed when doors open)
                        if (_showContent)
                          AnimatedBuilder(
                            animation: _contentController,
                            builder: (context, child) {
                              return Opacity(
                                opacity: _contentFadeAnimation.value,
                                child: Transform.scale(
                                  scale: _contentScaleAnimation.value,
                                  child: CustomPaint(
                                    painter: ClothingPainter(
                                      revealProgress: _contentController.value,
                                    ),
                                    child: Container(),
                                  ),
                                ),
                              );
                            },
                          ),
                        
                        // Wardrobe doors
                        AnimatedBuilder(
                          animation: Listenable.merge([_leftDoorAnimation, _rightDoorAnimation]),
                          builder: (context, child) {
                            return LayoutBuilder(
                              builder: (context, constraints) {
                                final doorWidth = constraints.maxWidth * 0.5;
                                final doorHeight = constraints.maxHeight;
                                
                                return Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    // Left door
                                    ClipRect(
                                      child: Container(
                                        width: doorWidth,
                                        height: doorHeight,
                                        alignment: Alignment.centerRight,
                                        child: Transform(
                                          alignment: Alignment.centerLeft,
                                          transform: Matrix4.identity()
                                            ..setEntry(3, 2, 0.001)
                                            ..rotateY(_leftDoorAnimation.value * math.pi / 2.2),
                                          child: Container(
                                            width: doorWidth,
                                            height: doorHeight,
                                        decoration: BoxDecoration(
                                          gradient: LinearGradient(
                                            begin: Alignment.topLeft,
                                            end: Alignment.bottomRight,
                                            colors: [
                                              const Color(0xFF3E2723), // Dark brown
                                              const Color(0xFF2E1A17), // Darker brown
                                            ],
                                          ),
                                          border: Border(
                                            left: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                            top: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                            bottom: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                          ),
                                          boxShadow: [
                                            BoxShadow(
                                              color: Colors.black.withOpacity(0.5),
                                              blurRadius: 10,
                                              offset: const Offset(-5, 0),
                                            ),
                                          ],
                                        ),
                                        child: CustomPaint(
                                          painter: DoorDetailPainter(isLeft: true),
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                                
                                
                                // Right door
                                ClipRect(
                                  child: Container(
                                    width: doorWidth,
                                    height: doorHeight,
                                    alignment: Alignment.centerLeft,
                                    child: Transform(
                                      alignment: Alignment.centerRight,
                                      transform: Matrix4.identity()
                                        ..setEntry(3, 2, 0.001)
                                        ..rotateY(_rightDoorAnimation.value * math.pi / 2.2),
                                      child: Container(
                                        width: doorWidth,
                                        height: doorHeight,
                                        decoration: BoxDecoration(
                                          gradient: LinearGradient(
                                            begin: Alignment.topLeft,
                                            end: Alignment.bottomRight,
                                            colors: [
                                              const Color(0xFF3E2723), // Dark brown
                                              const Color(0xFF2E1A17), // Darker brown
                                            ],
                                          ),
                                          border: Border(
                                            right: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                            top: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                            bottom: BorderSide(color: Colors.black.withOpacity(0.3), width: 2),
                                          ),
                                          boxShadow: [
                                            BoxShadow(
                                              color: Colors.black.withOpacity(0.5),
                                              blurRadius: 10,
                                              offset: const Offset(5, 0),
                                            ),
                                          ],
                                        ),
                                        child: CustomPaint(
                                          painter: DoorDetailPainter(isLeft: false),
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                                  ],
                                );
                              },
                            );
                          },
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
                  
                        // Logo and tagline below wardrobe
                        const SizedBox(height: 20),
                        AnimatedBuilder(
                          animation: _logoGlowAnimation,
                          builder: (context, child) {
                            return Container(
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(10),
                                boxShadow: [
                                  // Lightning glow effect
                                  BoxShadow(
                                    color: const Color(0xFFFFD700).withOpacity(_logoGlowAnimation.value * 0.6),
                                    blurRadius: 20,
                                    spreadRadius: 5,
                                  ),
                                  BoxShadow(
                                    color: const Color(0xFFFFE57F).withOpacity(_logoGlowAnimation.value * 0.4),
                                    blurRadius: 30,
                                    spreadRadius: 10,
                                  ),
                                ],
                              ),
                              child: Text(
                                'KOUTU',
                                style: TextStyle(
                                  fontSize: isMobile ? 60 : 80,
                                  fontWeight: FontWeight.bold,
                                  color: const Color(0xFF8B6F47), // Rich brown
                                  letterSpacing: isMobile ? 6 : 8,
                                  shadows: [
                                    Shadow(
                                      color: Colors.black.withOpacity(0.3),
                                      blurRadius: 5,
                                      offset: const Offset(0, 3),
                                    ),
                                    // Golden glow shadow
                                    Shadow(
                                      color: const Color(0xFFFFD700).withOpacity(_logoGlowAnimation.value),
                                      blurRadius: 15,
                                      offset: Offset.zero,
                                    ),
                                    // Lightning effect shadows
                                    Shadow(
                                      color: Colors.white.withOpacity(_logoGlowAnimation.value * 0.7),
                                      blurRadius: 3,
                                      offset: const Offset(-1, -1),
                                    ),
                                    Shadow(
                                      color: const Color(0xFFFFE57F).withOpacity(_logoGlowAnimation.value * 0.5),
                                      blurRadius: 8,
                                      offset: const Offset(1, 1),
                                    ),
                                  ],
                                ),
                              ),
                            );
                          },
                        ),
                        const SizedBox(height: 5),
                        Text(
                          'Your Digital Wardrobe',
                          style: TextStyle(
                            fontSize: isMobile ? 20 : 26,
                            color: const Color(0xFF5D4037), // Dark brown
                            letterSpacing: isMobile ? 1 : 2,
                            shadows: [
                              Shadow(
                                color: Colors.black.withOpacity(0.2),
                                blurRadius: 3,
                                offset: const Offset(0, 2),
                              ),
                            ],
                          ),
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


// Custom painter for clothing items inside wardrobe
class ClothingPainter extends CustomPainter {
  final double revealProgress;
  
  ClothingPainter({required this.revealProgress});
  
  @override
  void paint(Canvas canvas, Size size) {
    if (revealProgress == 0) return;
    
    final paint = Paint()
      ..style = PaintingStyle.fill;
    
    // Draw hanging rod with metallic effect
    final rodPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [
          const Color(0xFF9E9E9E),
          const Color(0xFF616161),
          const Color(0xFF9E9E9E),
        ],
      ).createShader(Rect.fromLTWH(size.width * 0.1, size.height * 0.14, size.width * 0.8, 6));
    
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        Rect.fromLTWH(size.width * 0.1, size.height * 0.14, size.width * 0.8, 6),
        const Radius.circular(3),
      ),
      rodPaint,
    );
    
    // Draw organized hanging clothes with proper spacing
    final hangingItems = [
      {'x': 0.15, 'type': 'shirt', 'color': const Color(0xFF2196F3)},
      {'x': 0.25, 'type': 'tshirt', 'color': const Color(0xFF4CAF50)},
      {'x': 0.35, 'type': 'jacket', 'color': const Color(0xFF795548)},
      {'x': 0.45, 'type': 'hoodie', 'color': const Color(0xFF9C27B0)},
      {'x': 0.55, 'type': 'dress', 'color': const Color(0xFFE91E63)},
      {'x': 0.65, 'type': 'suit', 'color': const Color(0xFF37474F)},
      {'x': 0.75, 'type': 'shirt', 'color': Colors.white},
      {'x': 0.85, 'type': 'blazer', 'color': const Color(0xFF1A237E)},
    ];
    
    for (var item in hangingItems) {
      final x = size.width * (item['x'] as double);
      
      // Draw hanger with metallic look
      paint
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..color = const Color(0xFF9E9E9E).withOpacity(revealProgress);
      
      // Hanger hook
      canvas.drawArc(
        Rect.fromCircle(center: Offset(x, size.height * 0.13), radius: 4),
        math.pi * 0.2,
        math.pi * 0.6,
        false,
        paint,
      );
      
      // Hanger body
      canvas.drawLine(
        Offset(x, size.height * 0.15),
        Offset(x - 12, size.height * 0.18),
        paint,
      );
      canvas.drawLine(
        Offset(x, size.height * 0.15),
        Offset(x + 12, size.height * 0.18),
        paint,
      );
      
      // Draw clothes with consistent styling
      paint.style = PaintingStyle.fill;
      paint.color = (item['color'] as Color).withOpacity(revealProgress * 0.9);
      
      switch (item['type']) {
        case 'shirt':
          _drawShirt(canvas, x, size, paint, revealProgress);
          break;
        case 'tshirt':
          _drawTShirt(canvas, x, size, paint, revealProgress);
          break;
        case 'jacket':
          _drawJacket(canvas, x, size, paint, revealProgress);
          break;
        case 'hoodie':
          _drawHoodie(canvas, x, size, paint, revealProgress);
          break;
        case 'dress':
          _drawDress(canvas, x, size, paint, revealProgress);
          break;
        case 'suit':
          _drawSuit(canvas, x, size, paint, revealProgress);
          break;
        case 'blazer':
          _drawBlazer(canvas, x, size, paint, revealProgress);
          break;
      }
    }
    
    
    // Draw organized shelves at bottom
    _drawOrganizedShelves(canvas, size, paint, revealProgress);
  }
  
  @override
  bool shouldRepaint(covariant ClothingPainter oldDelegate) {
    return oldDelegate.revealProgress != revealProgress;
  }
  
  void _drawShirt(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final shirtPath = Path()
      ..moveTo(x - 20, size.height * 0.19)
      ..lineTo(x - 20, size.height * 0.38)
      ..lineTo(x + 20, size.height * 0.38)
      ..lineTo(x + 20, size.height * 0.19)
      ..close();
    canvas.drawPath(shirtPath, paint);
    
    // Collar
    paint
      ..style = PaintingStyle.stroke
      ..color = Colors.black.withOpacity(progress * 0.3)
      ..strokeWidth = 1;
    canvas.drawLine(
      Offset(x - 8, size.height * 0.19),
      Offset(x, size.height * 0.21),
      paint,
    );
    canvas.drawLine(
      Offset(x + 8, size.height * 0.19),
      Offset(x, size.height * 0.21),
      paint,
    );
  }
  
  void _drawTShirt(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final tshirtPath = Path()
      ..moveTo(x - 18, size.height * 0.19)
      ..lineTo(x - 18, size.height * 0.35)
      ..lineTo(x + 18, size.height * 0.35)
      ..lineTo(x + 18, size.height * 0.19)
      ..close();
    canvas.drawPath(tshirtPath, paint);
    
    // Sleeves
    final sleevePath = Path()
      ..moveTo(x - 18, size.height * 0.19)
      ..lineTo(x - 25, size.height * 0.24)
      ..lineTo(x - 20, size.height * 0.26)
      ..lineTo(x - 18, size.height * 0.23);
    canvas.drawPath(sleevePath, paint);
    
    final sleevePath2 = Path()
      ..moveTo(x + 18, size.height * 0.19)
      ..lineTo(x + 25, size.height * 0.24)
      ..lineTo(x + 20, size.height * 0.26)
      ..lineTo(x + 18, size.height * 0.23);
    canvas.drawPath(sleevePath2, paint);
  }
  
  void _drawJacket(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final jacketPath = Path()
      ..moveTo(x - 25, size.height * 0.19)
      ..lineTo(x - 25, size.height * 0.42)
      ..lineTo(x + 25, size.height * 0.42)
      ..lineTo(x + 25, size.height * 0.19)
      ..close();
    canvas.drawPath(jacketPath, paint);
    
    // Zipper line
    paint
      ..style = PaintingStyle.stroke
      ..color = Colors.black.withOpacity(progress * 0.4)
      ..strokeWidth = 1.5;
    canvas.drawLine(
      Offset(x, size.height * 0.19),
      Offset(x, size.height * 0.42),
      paint,
    );
  }
  
  void _drawHoodie(Canvas canvas, double x, Size size, Paint paint, double progress) {
    paint.style = PaintingStyle.fill;
    final hoodiePath = Path()
      ..moveTo(x - 26, size.height * 0.19)
      ..lineTo(x - 26, size.height * 0.44)
      ..lineTo(x + 26, size.height * 0.44)
      ..lineTo(x + 26, size.height * 0.19)
      ..close();
    canvas.drawPath(hoodiePath, paint);
    
    // Hood
    paint.color = paint.color.withOpacity(paint.color.opacity * 0.8);
    final hoodPath = Path()
      ..moveTo(x - 15, size.height * 0.19)
      ..quadraticBezierTo(x, size.height * 0.16, x + 15, size.height * 0.19);
    canvas.drawPath(hoodPath, paint);
    
    // Pocket
    paint
      ..style = PaintingStyle.stroke
      ..color = Colors.black.withOpacity(progress * 0.3)
      ..strokeWidth = 1;
    canvas.drawRect(
      Rect.fromLTWH(x - 10, size.height * 0.32, 20, 15),
      paint,
    );
  }
  
  void _drawDress(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final dressPath = Path()
      ..moveTo(x - 18, size.height * 0.19)
      ..lineTo(x - 28, size.height * 0.48)
      ..lineTo(x + 28, size.height * 0.48)
      ..lineTo(x + 18, size.height * 0.19)
      ..close();
    canvas.drawPath(dressPath, paint);
    
    // Waistline
    paint
      ..style = PaintingStyle.stroke
      ..color = Colors.black.withOpacity(progress * 0.2)
      ..strokeWidth = 1;
    canvas.drawLine(
      Offset(x - 20, size.height * 0.28),
      Offset(x + 20, size.height * 0.28),
      paint,
    );
  }
  
  void _drawSuit(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final suitPath = Path()
      ..moveTo(x - 28, size.height * 0.19)
      ..lineTo(x - 28, size.height * 0.44)
      ..lineTo(x - 10, size.height * 0.44)
      ..lineTo(x - 10, size.height * 0.38)
      ..lineTo(x + 10, size.height * 0.38)
      ..lineTo(x + 10, size.height * 0.44)
      ..lineTo(x + 28, size.height * 0.44)
      ..lineTo(x + 28, size.height * 0.19)
      ..close();
    canvas.drawPath(suitPath, paint);
    
    // Lapels
    paint
      ..style = PaintingStyle.stroke
      ..color = Colors.black.withOpacity(progress * 0.4)
      ..strokeWidth = 1.5;
    canvas.drawLine(
      Offset(x - 8, size.height * 0.19),
      Offset(x - 12, size.height * 0.26),
      paint,
    );
    canvas.drawLine(
      Offset(x + 8, size.height * 0.19),
      Offset(x + 12, size.height * 0.26),
      paint,
    );
  }
  
  void _drawBlazer(Canvas canvas, double x, Size size, Paint paint, double progress) {
    final blazerPath = Path()
      ..moveTo(x - 26, size.height * 0.19)
      ..lineTo(x - 26, size.height * 0.42)
      ..lineTo(x + 26, size.height * 0.42)
      ..lineTo(x + 26, size.height * 0.19)
      ..close();
    canvas.drawPath(blazerPath, paint);
    
    // Buttons
    paint.style = PaintingStyle.fill;
    paint.color = Colors.black.withOpacity(progress * 0.6);
    canvas.drawCircle(Offset(x - 8, size.height * 0.30), 2, paint);
    canvas.drawCircle(Offset(x - 8, size.height * 0.35), 2, paint);
  }
  
  void _drawOrganizedShelves(Canvas canvas, Size size, Paint paint, double progress) {
    // Draw shelf boards
    paint
      ..style = PaintingStyle.fill
      ..color = const Color(0xFF6D4C41).withOpacity(progress);
    
    // Top shelf
    canvas.drawRect(
      Rect.fromLTWH(size.width * 0.1, size.height * 0.65, size.width * 0.8, 4),
      paint,
    );
    
    // Bottom shelf
    canvas.drawRect(
      Rect.fromLTWH(size.width * 0.1, size.height * 0.85, size.width * 0.8, 4),
      paint,
    );
    
    // Draw organized folded items on shelves
    
    // Top shelf items
    final topShelfY = size.height * 0.65 - 35;
    
    // Stack of jeans
    for (int i = 0; i < 4; i++) {
      paint.color = Color.lerp(
        const Color(0xFF1565C0),
        const Color(0xFF0D47A1),
        i / 4,
      )!.withOpacity(progress * 0.9);
      
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            size.width * 0.15,
            topShelfY - (i * 8),
            60,
            30,
          ),
          const Radius.circular(3),
        ),
        paint,
      );
    }
    
    // Stack of t-shirts
    final tshirtColors = [
      const Color(0xFF43A047),
      const Color(0xFF1E88E5),
      const Color(0xFFE53935),
      const Color(0xFFFDD835),
    ];
    
    for (int i = 0; i < tshirtColors.length; i++) {
      paint.color = tshirtColors[i].withOpacity(progress * 0.9);
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            size.width * 0.35,
            topShelfY - (i * 7),
            55,
            25,
          ),
          const Radius.circular(3),
        ),
        paint,
      );
    }
    
    // Stack of sweaters
    final sweaterColors = [
      const Color(0xFF6D4C41),
      const Color(0xFF455A64),
      const Color(0xFF512DA8),
    ];
    
    for (int i = 0; i < sweaterColors.length; i++) {
      paint.color = sweaterColors[i].withOpacity(progress * 0.9);
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            size.width * 0.55,
            topShelfY - (i * 10),
            70,
            35,
          ),
          const Radius.circular(4),
        ),
        paint,
      );
    }
    
    // Accessories box
    paint.color = const Color(0xFF795548).withOpacity(progress * 0.9);
    canvas.drawRRect(
      RRect.fromRectAndRadius(
        Rect.fromLTWH(
          size.width * 0.75,
          topShelfY - 10,
          50,
          40,
        ),
        const Radius.circular(4),
      ),
      paint,
    );
    
    // Bottom shelf items
    final bottomShelfY = size.height * 0.85 - 30;
    
    // Shoe boxes
    final shoeBoxColors = [
      const Color(0xFF37474F),
      const Color(0xFF263238),
      const Color(0xFF212121),
    ];
    
    for (int i = 0; i < 3; i++) {
      paint.color = shoeBoxColors[i].withOpacity(progress * 0.9);
      canvas.drawRRect(
        RRect.fromRectAndRadius(
          Rect.fromLTWH(
            size.width * (0.15 + i * 0.25),
            bottomShelfY,
            size.width * 0.18,
            25,
          ),
          const Radius.circular(3),
        ),
        paint,
      );
      
      // Brand stripe
      paint.color = Colors.white.withOpacity(progress * 0.3);
      canvas.drawRect(
        Rect.fromLTWH(
          size.width * (0.15 + i * 0.25) + 5,
          bottomShelfY + 10,
          size.width * 0.18 - 10,
          3,
        ),
        paint,
      );
    }
  }
}

// Custom painter for home background elements
class HomeBackgroundPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint();
    
    // Draw floor line
    paint
      ..color = const Color(0xFFB89968).withOpacity(0.3)
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke;
    
    final floorY = size.height * 0.85;
    canvas.drawLine(
      Offset(0, floorY),
      Offset(size.width, floorY),
      paint,
    );
    
    // Draw baseboards
    paint
      ..color = const Color(0xFF8B6F47).withOpacity(0.2)
      ..style = PaintingStyle.fill;
    
    canvas.drawRect(
      Rect.fromLTWH(0, floorY, size.width, size.height * 0.05),
      paint,
    );
    
    // Draw subtle wall pattern/texture
    paint
      ..color = const Color(0xFFD4A574).withOpacity(0.05)
      ..strokeWidth = 1;
    
    // Vertical subtle lines for wallpaper effect
    for (int i = 0; i < size.width; i += 50) {
      canvas.drawLine(
        Offset(i.toDouble(), 0),
        Offset(i.toDouble(), floorY),
        paint,
      );
    }
    
    // Add crown molding at top
    paint
      ..color = const Color(0xFFE8D5C4).withOpacity(0.3)
      ..style = PaintingStyle.fill;
    
    final molding = Path()
      ..moveTo(0, 0)
      ..lineTo(size.width, 0)
      ..lineTo(size.width, size.height * 0.03)
      ..quadraticBezierTo(size.width, size.height * 0.05, size.width - 10, size.height * 0.05)
      ..lineTo(10, size.height * 0.05)
      ..quadraticBezierTo(0, size.height * 0.05, 0, size.height * 0.03)
      ..close();
    
    canvas.drawPath(molding, paint);
    
    // Add subtle shadows for depth
    paint
      ..color = Colors.black.withOpacity(0.05)
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10);
    
    // Shadow under crown molding
    canvas.drawRect(
      Rect.fromLTWH(0, size.height * 0.05, size.width, 5),
      paint,
    );
  }
  
  @override
  bool shouldRepaint(covariant HomeBackgroundPainter oldDelegate) => false;
}

// Custom painter for treasure light beams
class TreasureLightPainter extends CustomPainter {
  final double intensity;
  final double doorOpenProgress;
  
  TreasureLightPainter({required this.intensity, required this.doorOpenProgress});
  
  @override
  void paint(Canvas canvas, Size size) {
    if (intensity == 0) return;
    
    final center = Offset(size.width / 2, size.height / 2);
    
    // Create light beams effect
    final paint = Paint()
      ..style = PaintingStyle.fill
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 20);
    
    // Draw multiple light rays
    for (int i = 0; i < 12; i++) {
      final angle = (i * 30) * math.pi / 180;
      final startRadius = 20.0;
      final endRadius = size.width * 0.8;
      
      // Create gradient for each light beam
      final gradient = RadialGradient(
        center: Alignment.center,
        colors: [
          const Color(0xFFFFE57F).withOpacity(intensity * 0.6),
          const Color(0xFFFFD700).withOpacity(intensity * 0.3),
          Colors.transparent,
        ],
        stops: const [0.0, 0.3, 1.0],
      );
      
      // Draw light beam
      final path = Path();
      path.moveTo(
        center.dx + math.cos(angle - 0.1) * startRadius,
        center.dy + math.sin(angle - 0.1) * startRadius,
      );
      path.lineTo(
        center.dx + math.cos(angle - 0.05) * endRadius * doorOpenProgress,
        center.dy + math.sin(angle - 0.05) * endRadius * doorOpenProgress,
      );
      path.lineTo(
        center.dx + math.cos(angle + 0.05) * endRadius * doorOpenProgress,
        center.dy + math.sin(angle + 0.05) * endRadius * doorOpenProgress,
      );
      path.lineTo(
        center.dx + math.cos(angle + 0.1) * startRadius,
        center.dy + math.sin(angle + 0.1) * startRadius,
      );
      path.close();
      
      paint.shader = gradient.createShader(
        Rect.fromCenter(center: center, width: size.width, height: size.height),
      );
      canvas.drawPath(path, paint);
    }
    
    // Central bright spot
    final centerGradient = RadialGradient(
      colors: [
        Colors.white.withOpacity(intensity * 0.8),
        const Color(0xFFFFE57F).withOpacity(intensity * 0.5),
        Colors.transparent,
      ],
      stops: const [0.0, 0.2, 1.0],
    );
    
    paint
      ..shader = centerGradient.createShader(
        Rect.fromCenter(center: center, width: 100, height: 100),
      )
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10);
    
    canvas.drawCircle(center, 50 * intensity, paint);
  }
  
  @override
  bool shouldRepaint(covariant TreasureLightPainter oldDelegate) {
    return oldDelegate.intensity != intensity || oldDelegate.doorOpenProgress != doorOpenProgress;
  }
}

// Custom painter for particle effects
class ParticlePainter extends CustomPainter {
  final double progress;
  final double glowProgress;
  
  ParticlePainter({required this.progress, required this.glowProgress});
  
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.fill;
    
    // Draw multiple particles
    for (int i = 0; i < 50; i++) {
      final particleProgress = (progress + i / 50) % 1.0;
      final opacity = (1.0 - particleProgress) * glowProgress;
      
      if (opacity > 0) {
        paint.color = const Color(0xFFFFD700).withOpacity(opacity * 0.2); // Gold particles
        
        final x = size.width * (0.2 + 0.6 * _pseudoRandom(i, 0));
        final baseY = size.height * (0.3 + 0.4 * _pseudoRandom(i, 1));
        final y = baseY - (particleProgress * size.height * 0.3);
        final radius = 2 + 3 * _pseudoRandom(i, 2);
        
        canvas.drawCircle(Offset(x, y), radius, paint);
      }
    }
  }
  
  double _pseudoRandom(int seed, int offset) {
    return ((seed * 31 + offset * 17) % 100) / 100;
  }
  
  @override
  bool shouldRepaint(covariant ParticlePainter oldDelegate) {
    return oldDelegate.progress != progress || oldDelegate.glowProgress != glowProgress;
  }
}

// Custom painter for door details
class DoorDetailPainter extends CustomPainter {
  final bool isLeft;
  
  DoorDetailPainter({required this.isLeft});
  
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.5
      ..color = const Color(0xFF5D4037).withOpacity(0.3); // Medium brown for panels
    
    // Draw door panels with wood grain effect
    final panelRect = Rect.fromLTWH(
      size.width * 0.1,
      size.height * 0.1,
      size.width * 0.8,
      size.height * 0.35,
    );
    canvas.drawRect(panelRect, paint);
    
    final panelRect2 = Rect.fromLTWH(
      size.width * 0.1,
      size.height * 0.55,
      size.width * 0.8,
      size.height * 0.35,
    );
    canvas.drawRect(panelRect2, paint);
    
    // Add wood grain lines
    paint
      ..strokeWidth = 0.5
      ..color = const Color(0xFF4E342E).withOpacity(0.2);
    
    for (int i = 0; i < 5; i++) {
      final y = size.height * (0.2 + i * 0.15);
      canvas.drawLine(
        Offset(size.width * 0.15, y),
        Offset(size.width * 0.85, y),
        paint,
      );
    }
    
    // Draw door handle (on the inside edge where doors meet)
    paint
      ..style = PaintingStyle.fill
      ..color = const Color(0xFFB8860B).withOpacity(0.8); // Dark gold/brass
    
    final handleX = isLeft ? size.width * 0.9 : size.width * 0.1;
    final handleY = size.height * 0.5;
    
    canvas.drawCircle(Offset(handleX, handleY), 8, paint);
    
    // Handle shadow
    paint.color = Colors.black.withOpacity(0.3);
    canvas.drawCircle(Offset(handleX + 2, handleY + 2), 8, paint);
  }
  
  @override
  bool shouldRepaint(covariant DoorDetailPainter oldDelegate) {
    return false;
  }
}