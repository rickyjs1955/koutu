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
  
  bool _isLoading = true;
  bool _showContent = false;

  @override
  void initState() {
    super.initState();
    
    // Door opening animation controller
    _doorController = AnimationController(
      duration: const Duration(seconds: 2),
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
      backgroundColor: const Color(0xFF1a1a2e),
      body: Stack(
        children: [
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
                    width: isMobile ? size.width * 0.9 : size.width * 0.8,
                    height: isMobile ? size.height * 0.5 : size.height * 0.6,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        // Glow effect behind doors
                        AnimatedBuilder(
                          animation: _glowAnimation,
                          builder: (context, child) {
                            return Container(
                              width: isMobile ? size.width * 0.8 : size.width * 0.7,
                              height: isMobile ? size.height * 0.4 : size.height * 0.5,
                              decoration: BoxDecoration(
                                gradient: RadialGradient(
                                  colors: [
                                    Colors.blue.withOpacity(_glowAnimation.value * 0.3),
                                    Colors.transparent,
                                  ],
                                  radius: 2,
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
                                    decoration: BoxDecoration(
                                      color: Colors.white.withOpacity(0.9),
                                      borderRadius: BorderRadius.circular(20),
                                      boxShadow: [
                                        BoxShadow(
                                          color: Colors.blue.withOpacity(0.5),
                                          blurRadius: 30,
                                          spreadRadius: 10,
                                        ),
                                      ],
                                    ),
                                    child: Column(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        Text(
                                          'KOUTU',
                                          style: TextStyle(
                                            fontSize: isMobile ? 45 : 70,
                                            fontWeight: FontWeight.bold,
                                            color: Colors.blue.shade900,
                                            letterSpacing: isMobile ? 6 : 8,
                                            shadows: [
                                              Shadow(
                                                color: Colors.blue.withOpacity(0.3),
                                                blurRadius: 10,
                                                offset: const Offset(0, 5),
                                              ),
                                            ],
                                          ),
                                        ),
                                        const SizedBox(height: 20),
                                        Text(
                                          'Your Digital Wardrobe',
                                          style: TextStyle(
                                            fontSize: isMobile ? 16 : 20,
                                            color: Colors.blue.shade700,
                                            letterSpacing: isMobile ? 1 : 2,
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
                                    width: isMobile ? size.width * 0.4 : size.width * 0.35,
                                    height: isMobile ? size.height * 0.4 : size.height * 0.5,
                                    alignment: Alignment.centerRight,
                                    child: Transform(
                                      alignment: Alignment.centerLeft,
                                      transform: Matrix4.identity()
                                        ..setEntry(3, 2, 0.001)
                                        ..rotateY(-_leftDoorAnimation.value * math.pi / 3),
                                      child: Container(
                                        width: isMobile ? size.width * 0.4 : size.width * 0.35,
                                        height: isMobile ? size.height * 0.4 : size.height * 0.5,
                                        decoration: BoxDecoration(
                                          gradient: LinearGradient(
                                            begin: Alignment.topLeft,
                                            end: Alignment.bottomRight,
                                            colors: [
                                              const Color(0xFF2d3561),
                                              const Color(0xFF0f3460),
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
                                
                                // Gap between doors
                                Container(
                                  width: isMobile ? 2 : 4,
                                  height: isMobile ? size.height * 0.4 : size.height * 0.5,
                                  color: Colors.black.withOpacity(0.5),
                                ),
                                
                                // Right door
                                ClipRect(
                                  child: Container(
                                    width: isMobile ? size.width * 0.4 : size.width * 0.35,
                                    height: isMobile ? size.height * 0.4 : size.height * 0.5,
                                    alignment: Alignment.centerLeft,
                                    child: Transform(
                                      alignment: Alignment.centerRight,
                                      transform: Matrix4.identity()
                                        ..setEntry(3, 2, 0.001)
                                        ..rotateY(-_rightDoorAnimation.value * math.pi / 3),
                                      child: Container(
                                        width: isMobile ? size.width * 0.4 : size.width * 0.35,
                                        height: isMobile ? size.height * 0.4 : size.height * 0.5,
                                        decoration: BoxDecoration(
                                          gradient: LinearGradient(
                                            begin: Alignment.topLeft,
                                            end: Alignment.bottomRight,
                                            colors: [
                                              const Color(0xFF2d3561),
                                              const Color(0xFF0f3460),
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
        paint.color = Colors.blue.withOpacity(opacity * 0.3);
        
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
      ..strokeWidth = 2.0
      ..color = Colors.white.withOpacity(0.1);
    
    // Draw door panels
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
    
    // Draw door handle (on the inside edge where doors meet)
    paint
      ..style = PaintingStyle.fill
      ..color = Colors.amber.withOpacity(0.7);
    
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