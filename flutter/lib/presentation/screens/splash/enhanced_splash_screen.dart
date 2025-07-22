import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'dart:math';
import 'package:koutu/core/constants/app_colors.dart';

/// Splash screen featuring an animated wardrobe opening sequence
/// with particle effects and elegant typography
class EnhancedSplashScreen extends StatefulWidget {
  const EnhancedSplashScreen({super.key});

  @override
  State<EnhancedSplashScreen> createState() => _EnhancedSplashScreenState();
}

class _EnhancedSplashScreenState extends State<EnhancedSplashScreen>
    with SingleTickerProviderStateMixin {
  // Animation controller to orchestrate all animations
  late AnimationController _controller;
  
  // Wardrobe door animations
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;
  
  // Fade-in animation for text elements
  late Animation<double> _opacityAnimation;
  
  // Slide-up animation for title
  late Animation<Offset> _titleSlideAnimation;
  
  // Wardrobe scale animation
  late Animation<double> _wardrobeScaleAnimation;

  // Color palette constants
  final Color _ivory = const Color(0xFFF5EFE7);  // Primary light color
  final Color _navy = const Color(0xFF213555);   // Primary dark color
  final Color _goldAccent = const Color(0xFFD4AF37); // Accent color

  @override
  void initState() {
    super.initState();
    
    // Main animation controller (2200ms duration)
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    );

    // Configure animation curves for smooth easing
    final curvedAnimation = CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.0, 0.8, curve: Curves.easeOutQuint),
    );

    // Wardrobe scale animation
    _wardrobeScaleAnimation = Tween<double>(
      begin: 0.9,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.0, 0.4, curve: Curves.easeOut),
    ));

    // Left door opens with smooth rotation
    _leftDoorAnimation = Tween<double>(
      begin: 0.0,
      end: -85.0, // Degrees
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.2, 0.8, curve: Curves.easeInOut),
    ));

    // Right door opens with smooth rotation
    _rightDoorAnimation = Tween<double>(
      begin: 0.0,
      end: 85.0, // Degrees
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.2, 0.8, curve: Curves.easeInOut),
    ));

    // Text fade-in animation (delayed start)
    _opacityAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _controller,
        curve: const Interval(0.6, 1.0, curve: Curves.easeIn),
      ),
    );

    // Title slide-up animation from bottom
    _titleSlideAnimation = Tween<Offset>(
      begin: const Offset(0, 0.3),  // Start 30% down from final position
      end: Offset.zero,
    ).animate(curvedAnimation);

    // Start animation sequence and trigger navigation
    _controller.forward().then((_) async {
      await Future.delayed(const Duration(milliseconds: 500));
      if (mounted) {
        Navigator.of(context).pushReplacementNamed('/home');
      }
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final bool isDarkMode = Theme.of(context).brightness == Brightness.dark;
    final size = MediaQuery.of(context).size;

    return Scaffold(
      backgroundColor: isDarkMode ? _navy : _ivory,
      body: Stack(
        children: [
          // Background particle effect layer
          Positioned.fill(
            child: IgnorePointer(
              child: AnimatedBuilder(
                animation: _controller,
                builder: (context, child) {
                  return CustomPaint(
                    painter: _ParticlePainter(
                      color: _goldAccent.withOpacity(0.2),
                      animation: _controller,
                    ),
                  );
                },
              ),
            ),
          ),

          // Central wardrobe animation
          Center(
            child: AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return Transform.scale(
                  scale: _wardrobeScaleAnimation.value,
                  child: SizedBox(
                    width: size.width * 0.7,  // Responsive width
                    height: size.height * 0.5, // Responsive height
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        // Logo content behind doors
                        _buildLogoContent(isDarkMode),
                        
                        // Wardrobe doors
                        _buildWardrobeDoors(size.width * 0.7, size.height * 0.5),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),

          // Text content overlay (animated)
          Positioned.fill(
            child: AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return Opacity(
                  opacity: _opacityAnimation.value,
                  child: SlideTransition(
                    position: _titleSlideAnimation,
                    child: child!,
                  ),
                );
              },
              child: Column(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  // Main title with custom styling
                  Text(
                    'KOUTU',
                    style: TextStyle(
                      fontSize: 42,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 4,  // Increased letter spacing for elegance
                      color: isDarkMode ? _ivory : _navy,
                    ),
                  ),
                  
                  // Animated decorative line
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: AnimatedBuilder(
                      animation: _controller,
                      builder: (context, child) {
                        return CustomPaint(
                          painter: _LinePainter(
                            color: _goldAccent,
                            lengthFactor: _controller.value.clamp(0.7, 1.0),
                          ),
                          size: const Size(100, 1),
                        );
                      },
                    ),
                  ),
                  
                  // Subtitle with dynamic letter spacing
                  Padding(
                    padding: const EdgeInsets.only(bottom: 40),
                    child: AnimatedBuilder(
                      animation: _controller,
                      builder: (context, child) {
                        return Text(
                          'Your Digital Wardrobe',
                          style: TextStyle(
                            fontSize: 16,
                            letterSpacing: _controller.value * 2 + 1, // Animated spacing
                            color: isDarkMode ? _ivory.withOpacity(0.8) : _navy.withOpacity(0.8),
                          ),
                        );
                      },
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

  Widget _buildLogoContent(bool isDarkMode) {
    return FadeTransition(
      opacity: _opacityAnimation,
      child: Container(
        width: 180,
        height: 180,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(
            colors: [
              _goldAccent.withOpacity(0.3),
              _goldAccent.withOpacity(0.1),
              Colors.transparent,
            ],
          ),
        ),
        child: Center(
          child: Icon(
            Icons.checkroom,
            size: 80,
            color: isDarkMode ? _ivory : _navy,
          ),
        ),
      ),
    );
  }

  Widget _buildWardrobeDoors(double wardrobeWidth, double wardrobeHeight) {
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
                child: _buildElegantDoor(
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
                child: _buildElegantDoor(
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

  Widget _buildElegantDoor({
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
          colors: [
            const Color(0xFF3A2F2A),
            const Color(0xFF4A3F3A),
            const Color(0xFF5A4F4A),
          ],
        ),
        borderRadius: BorderRadius.only(
          topLeft: isLeft ? const Radius.circular(8) : Radius.zero,
          topRight: !isLeft ? const Radius.circular(8) : Radius.zero,
          bottomLeft: isLeft ? const Radius.circular(8) : Radius.zero,
          bottomRight: !isLeft ? const Radius.circular(8) : Radius.zero,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.3),
            blurRadius: 15,
            offset: Offset(isLeft ? -3 : 3, 3),
          ),
        ],
      ),
      child: Stack(
        children: [
          // Wood grain effect
          CustomPaint(
            size: Size(width, height),
            painter: _WoodGrainPainter(isLeft: isLeft),
          ),
          
          // Elegant panel design
          Padding(
            padding: const EdgeInsets.all(15),
            child: Container(
              decoration: BoxDecoration(
                border: Border.all(
                  color: _goldAccent.withOpacity(0.3),
                  width: 1,
                ),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Padding(
                padding: const EdgeInsets.all(10),
                child: Container(
                  decoration: BoxDecoration(
                    color: Colors.black.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
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
                gradient: const LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    Color(0xFFE4C441),
                    Color(0xFFB8963F),
                    Color(0xFFE4C441),
                  ],
                ),
                borderRadius: BorderRadius.circular(4),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.4),
                    blurRadius: 6,
                    offset: const Offset(0, 3),
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

/// Custom painter for background particle effects
class _ParticlePainter extends CustomPainter {
  final Color color;
  final Animation<double> animation;

  _ParticlePainter({required this.color, required this.animation}) : super(repaint: animation);

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..style = PaintingStyle.fill;

    // Dynamic particle count based on animation progress
    final progress = animation.value;
    final particleCount = (progress * 50).toInt();

    // Draw randomized particles
    for (int i = 0; i < particleCount; i++) {
      final offset = Offset(
        size.width * _noise(i, 0, progress),  // Randomized X position
        size.height * _noise(i, 1, progress), // Randomized Y position
      );
      final radius = 2 * _noise(i, 2, progress) + 0.5; // Randomized size
      canvas.drawCircle(offset, radius, paint);
    }
  }

  /// Pseudo-random number generator for particle positioning
  double _noise(int seed, int dimension, double progress) {
    final random = Random(seed * 1000 + dimension);
    return random.nextDouble() * progress;  // Progress affects visibility
  }

  @override
  bool shouldRepaint(covariant _ParticlePainter oldDelegate) {
    return oldDelegate.animation.value != animation.value;
  }
}

/// Custom painter for animated decorative line
class _LinePainter extends CustomPainter {
  final Color color;
  final double lengthFactor;  // Animation progress (0.0 to 1.0)

  _LinePainter({required this.color, required this.lengthFactor});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 0.8  // Hairline thickness
      ..strokeCap = StrokeCap.round;  // Rounded ends

    // Calculate line length based on animation
    final lineLength = size.width * lengthFactor;
    final startX = (size.width - lineLength) / 2;  // Centered

    canvas.drawLine(
      Offset(startX, size.height / 2),
      Offset(startX + lineLength, size.height / 2),
      paint,
    );
  }

  @override
  bool shouldRepaint(covariant _LinePainter oldDelegate) {
    return oldDelegate.lengthFactor != lengthFactor;
  }
}

/// Custom painter for wood grain effect
class _WoodGrainPainter extends CustomPainter {
  final bool isLeft;

  _WoodGrainPainter({required this.isLeft});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 0.3;

    // Draw subtle wood grain lines
    for (int i = 0; i < 15; i++) {
      paint.color = const Color(0xFF2A1F1A).withOpacity(0.2);
      final y = (size.height / 15) * i;
      
      final path = Path();
      path.moveTo(0, y);
      
      // Create wavy wood grain effect
      for (double x = 0; x <= size.width; x += 15) {
        final waveY = y + math.sin(x * 0.02) * 1.5;
        path.lineTo(x, waveY);
      }
      
      canvas.drawPath(path, paint);
    }
  }

  @override
  bool shouldRepaint(CustomPainter oldDelegate) => false;
}