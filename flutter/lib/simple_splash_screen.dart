import 'package:flutter/material.dart';

/// Simple splash screen without Rive animations
class SimpleSplashScreen extends StatefulWidget {
  final VoidCallback onAnimationComplete;

  const SimpleSplashScreen({super.key, required this.onAnimationComplete});

  @override
  State<SimpleSplashScreen> createState() => _SimpleSplashScreenState();
}

class _SimpleSplashScreenState extends State<SimpleSplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _fadeAnimation;

  @override
  void initState() {
    super.initState();
    
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );

    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: Curves.easeIn,
    ));

    _controller.forward().then((_) {
      widget.onAnimationComplete();
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFFF5EFE7),
      body: Center(
        child: AnimatedBuilder(
          animation: _fadeAnimation,
          builder: (context, child) {
            return Opacity(
              opacity: _fadeAnimation.value,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    'HELLO',
                    style: TextStyle(
                      fontSize: 72,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFF213555),
                      letterSpacing: 8,
                    ),
                  ),
                  const SizedBox(height: 20),
                  Text(
                    'Your Digital Wardrobe',
                    style: TextStyle(
                      fontSize: 18,
                      color: const Color(0xFF213555).withOpacity(0.7),
                      letterSpacing: 2,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ),
    );
  }
}