import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:rive/rive.dart';

/// Splash screen featuring an animated wardrobe opening sequence
/// with particle effects and elegant typography
class KoutuSplashScreen extends StatefulWidget {
  final VoidCallback onAnimationComplete;

  const KoutuSplashScreen({super.key, required this.onAnimationComplete});

  @override
  State<KoutuSplashScreen> createState() => _KoutuSplashScreenState();
}

class _KoutuSplashScreenState extends State<KoutuSplashScreen> 
    with SingleTickerProviderStateMixin {
  // Animation controller to orchestrate all animations
  late AnimationController _controller;
  
  // Fade-in animation for text elements
  late Animation<double> _opacityAnimation;
  
  // Slide-up animation for title
  late Animation<Offset> _titleSlideAnimation;
  
  // Controller for Rive vector animations
  late RiveAnimationController _riveController;

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

    // Initialize Rive animation with 'Open' state
    _riveController = SimpleAnimation('Open');
    
    // Start animation sequence and trigger completion callback
    _controller.forward().then((_) {
      widget.onAnimationComplete();
    });

    // Preload heavy assets in background
    _preloadAssets();
  }

  /// Pre-caches images and animations to prevent frame drops
  Future<void> _preloadAssets() async {
    await precacheImage(const AssetImage('assets/images/wood_texture.png'), context);
  }

  @override
  void dispose() {
    _controller.dispose();
    _riveController.dispose();
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
              child: CustomPaint(
                painter: _ParticlePainter(
                  color: _goldAccent.withOpacity(0.2),
                  animation: _controller,
                ),
              ),
            ),
          ),

          // Central wardrobe animation
          Center(
            child: SizedBox(
              width: size.width * 0.7,  // Responsive width
              height: size.height * 0.5, // Responsive height
              child: RiveAnimation.asset(
                'assets/animations/wardrobe.riv',
                controllers: [_riveController],
                fit: BoxFit.contain,
                alignment: Alignment.bottomCenter,
              ),
            ),
          ),

          // Text content overlay (animated)
          Positioned.fill(
            child: AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return Opacity(
                  opacity: _opacityAnimation.value,
                  child: Transform.translate(
                    offset: _titleSlideAnimation.value * 50,
                    child: child,
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
                      fontFamily: 'AvenirNext',  // Custom premium font
                    ),
                  ),
                  
                  // Animated decorative line
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    child: CustomPaint(
                      painter: _LinePainter(
                        color: _goldAccent,
                        lengthFactor: _controller.value.clamp(0.7, 1.0),
                      ),
                      size: const Size(100, 1),
                    ),
                  ),
                  
                  // Subtitle with dynamic letter spacing
                  Padding(
                    padding: const EdgeInsets.only(bottom: 40),
                    child: Text(
                      'Your Digital Wardrobe',
                      style: TextStyle(
                        fontSize: 16,
                        letterSpacing: _controller.value * 2 + 1, // Animated spacing
                        color: isDarkMode ? _ivory.withOpacity(0.8) : _navy.withOpacity(0.8),
                        fontFamily: 'AvenirNext',
                      ),
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

/// Custom painter for background particle effects
class _ParticlePainter extends CustomPainter {
  final Color color;
  final Animation<double> animation;

  _ParticlePainter({required this.color, required this.animation});

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
      final radius = 2 * _noise(i, 2, progress); // Randomized size
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