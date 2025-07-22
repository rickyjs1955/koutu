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
      title: 'KOUTU',
      theme: ThemeData(
        primarySwatch: Colors.brown,
        useMaterial3: true,
      ),
      debugShowCheckedModeBanner: false,
      home: const SimpleSplashScreen(),
    );
  }
}

class SimpleSplashScreen extends StatefulWidget {
  const SimpleSplashScreen({Key? key}) : super(key: key);

  @override
  State<SimpleSplashScreen> createState() => _SimpleSplashScreenState();
}

class _SimpleSplashScreenState extends State<SimpleSplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _doorAnimation;
  late Animation<double> _fadeAnimation;

  @override
  void initState() {
    super.initState();
    
    _controller = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    );

    _doorAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: Curves.easeInOut,
    ));

    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: const Interval(0.5, 1.0, curve: Curves.easeIn),
    ));

    // Start animation after a short delay
    Future.delayed(const Duration(milliseconds: 500), () {
      if (mounted) {
        _controller.forward();
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
    final size = MediaQuery.of(context).size;
    
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xFFF5E6D3),
              Color(0xFFE8D5C4),
              Color(0xFFD4C4B0),
            ],
          ),
        ),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Simple wardrobe animation
              SizedBox(
                width: 200,
                height: 300,
                child: Stack(
                  children: [
                    // Background glow
                    AnimatedBuilder(
                      animation: _fadeAnimation,
                      builder: (context, child) {
                        return Container(
                          decoration: BoxDecoration(
                            gradient: RadialGradient(
                              colors: [
                                Color(0xFFFFD700).withOpacity(_fadeAnimation.value * 0.3),
                                Colors.transparent,
                              ],
                            ),
                          ),
                        );
                      },
                    ),
                    // Wardrobe doors
                    AnimatedBuilder(
                      animation: _doorAnimation,
                      builder: (context, child) {
                        return Row(
                          children: [
                            // Left door
                            Expanded(
                              child: Transform(
                                alignment: Alignment.centerLeft,
                                transform: Matrix4.identity()
                                  ..setEntry(3, 2, 0.001)
                                  ..rotateY(-_doorAnimation.value * math.pi / 3),
                                child: Container(
                                  decoration: const BoxDecoration(
                                    color: Color(0xFF3E2723),
                                    border: Border(
                                      left: BorderSide(color: Colors.black26, width: 2),
                                      top: BorderSide(color: Colors.black26, width: 2),
                                      bottom: BorderSide(color: Colors.black26, width: 2),
                                    ),
                                  ),
                                ),
                              ),
                            ),
                            // Right door
                            Expanded(
                              child: Transform(
                                alignment: Alignment.centerRight,
                                transform: Matrix4.identity()
                                  ..setEntry(3, 2, 0.001)
                                  ..rotateY(_doorAnimation.value * math.pi / 3),
                                child: Container(
                                  decoration: const BoxDecoration(
                                    color: Color(0xFF3E2723),
                                    border: Border(
                                      right: BorderSide(color: Colors.black26, width: 2),
                                      top: BorderSide(color: Colors.black26, width: 2),
                                      bottom: BorderSide(color: Colors.black26, width: 2),
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
              const SizedBox(height: 40),
              // Logo
              AnimatedBuilder(
                animation: _fadeAnimation,
                builder: (context, child) {
                  return Opacity(
                    opacity: _fadeAnimation.value,
                    child: const Text(
                      'KOUTU',
                      style: TextStyle(
                        fontSize: 48,
                        fontWeight: FontWeight.bold,
                        color: Color(0xFF8B6F47),
                        letterSpacing: 8,
                      ),
                    ),
                  );
                },
              ),
              const SizedBox(height: 10),
              // Tagline
              AnimatedBuilder(
                animation: _fadeAnimation,
                builder: (context, child) {
                  return Opacity(
                    opacity: _fadeAnimation.value,
                    child: const Text(
                      'Your Digital Wardrobe',
                      style: TextStyle(
                        fontSize: 18,
                        color: Color(0xFF5D4037),
                        letterSpacing: 2,
                      ),
                    ),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}