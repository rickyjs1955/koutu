import 'package:flutter/material.dart';
import 'dart:math' as math;

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
  
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  late Animation<double> _contentFadeAnimation;
  late Animation<double> _contentScaleAnimation;
  late Animation<double> _glowAnimation;
  late Animation<double> _lightBeamAnimation;
  
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
                  MaterialPageRoute(builder: (context) => const HomePage()),
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
                : SizedBox(
                    width: size.width * 0.9,
                    height: size.height * 0.7,
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
                              size: Size(
                                size.width * 0.85,
                                size.height * 0.65,
                              ),
                            );
                          },
                        ),
                        
                        // Glow effect behind doors
                        AnimatedBuilder(
                          animation: _glowAnimation,
                          builder: (context, child) {
                            return Container(
                              width: size.width * 0.85,
                              height: size.height * 0.65,
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
                        
                        // Content behind doors (revealed when doors open)
                        if (_showContent)
                          AnimatedBuilder(
                            animation: _contentController,
                            builder: (context, child) {
                              return Opacity(
                                opacity: _contentFadeAnimation.value,
                                child: Transform.scale(
                                  scale: _contentScaleAnimation.value,
                                  child: Container(
                                    padding: EdgeInsets.all(isMobile ? 20 : 40),
                                    child: Column(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        Text(
                                          'KOUTU',
                                          style: TextStyle(
                                            fontSize: isMobile ? 55 : 80,
                                            fontWeight: FontWeight.bold,
                                            color: const Color(0xFF8B6F47), // Rich brown
                                            letterSpacing: isMobile ? 6 : 8,
                                            shadows: [
                                              Shadow(
                                                color: Colors.black.withOpacity(0.5),
                                                blurRadius: 10,
                                                offset: const Offset(0, 3),
                                              ),
                                              Shadow(
                                                color: const Color(0xFFFFD700).withOpacity(0.5),
                                                blurRadius: 20,
                                                offset: const Offset(0, 0),
                                              ),
                                            ],
                                          ),
                                        ),
                                        const SizedBox(height: 20),
                                        Text(
                                          'Your Digital Wardrobe',
                                          style: TextStyle(
                                            fontSize: isMobile ? 18 : 24,
                                            color: const Color(0xFF5D4037), // Dark brown
                                            letterSpacing: isMobile ? 1 : 2,
                                            shadows: [
                                              Shadow(
                                                color: Colors.black.withOpacity(0.7),
                                                blurRadius: 5,
                                                offset: const Offset(0, 2),
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
                        
                        // Wardrobe doors
                        AnimatedBuilder(
                          animation: Listenable.merge([_leftDoorAnimation, _rightDoorAnimation]),
                          builder: (context, child) {
                            return Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                // Left door
                                ClipRect(
                                  child: Container(
                                    width: size.width * 0.425,
                                    height: size.height * 0.65,
                                    alignment: Alignment.centerRight,
                                    child: Transform(
                                      alignment: Alignment.centerLeft,
                                      transform: Matrix4.identity()
                                        ..setEntry(3, 2, 0.001)
                                        ..rotateY(_leftDoorAnimation.value * math.pi / 2.2),
                                      child: Container(
                                        width: size.width * 0.425,
                                        height: size.height * 0.65,
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
                                    width: size.width * 0.425,
                                    height: size.height * 0.65,
                                    alignment: Alignment.centerLeft,
                                    child: Transform(
                                      alignment: Alignment.centerRight,
                                      transform: Matrix4.identity()
                                        ..setEntry(3, 2, 0.001)
                                        ..rotateY(_rightDoorAnimation.value * math.pi / 2.2),
                                      child: Container(
                                        width: size.width * 0.425,
                                        height: size.height * 0.65,
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

class HomePage extends StatelessWidget {
  const HomePage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Home'),
        backgroundColor: Colors.blue.shade700,
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.home,
              size: 100,
              color: Colors.blue.shade700,
            ),
            const SizedBox(height: 20),
            Text(
              'Welcome Home!',
              style: TextStyle(
                fontSize: 30,
                fontWeight: FontWeight.bold,
                color: Colors.blue.shade900,
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'The splash screen has completed',
              style: TextStyle(
                fontSize: 18,
                color: Colors.blue.shade600,
              ),
            ),
          ],
        ),
      ),
    );
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