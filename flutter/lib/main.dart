import 'package:flutter/material.dart';
import 'dart:math' as math;
import '../splash_screen_demo1.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Red Door Demo',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: HelloSplashScreen(onAnimationComplete: () {
        // Animation complete callback
      }),
    );
  }
}

class RedDoorSplash extends StatefulWidget {
  const RedDoorSplash({super.key});

  @override
  State<RedDoorSplash> createState() => _RedDoorSplashState();
}

class _RedDoorSplashState extends State<RedDoorSplash>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _leftDoorAnimation;
  late Animation<double> _rightDoorAnimation;

  @override
  void initState() {
    super.initState();
    
    _controller = AnimationController(
      duration: const Duration(seconds: 3),
      vsync: this,
    );

    // LEFT DOOR: Opens to -120 degrees (outward to the left)
    _leftDoorAnimation = Tween<double>(
      begin: 0.0,
      end: -120.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: Curves.easeInOutCubic,
    ));

    // RIGHT DOOR: Opens to +120 degrees (outward to the right)
    _rightDoorAnimation = Tween<double>(
      begin: 0.0,
      end: 120.0,
    ).animate(CurvedAnimation(
      parent: _controller,
      curve: Curves.easeInOutCubic,
    ));

    // Start animation immediately
    _controller.forward();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final doorWidth = size.width * 0.3;
    final doorHeight = size.height * 0.6;

    return Scaffold(
      backgroundColor: Colors.grey[300],
      body: Stack(
        children: [
          // Title at top
          const Positioned(
            top: 50,
            left: 0,
            right: 0,
            child: Text(
              'RED DOOR DEMO - OPENS OUTWARD',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Colors.black,
              ),
            ),
          ),
          
          // Center container for doors
          Center(
            child: Container(
              width: doorWidth * 2,
              height: doorHeight,
              color: Colors.yellow.withOpacity(0.3),
              child: Stack(
                children: [
                  // Left door
                  Positioned(
                    left: 0,
                    top: 0,
                    child: AnimatedBuilder(
                      animation: _leftDoorAnimation,
                      builder: (context, child) {
                        return Transform(
                          alignment: Alignment.centerRight,
                          transform: Matrix4.identity()
                            ..setEntry(3, 2, 0.001)
                            ..rotateY(_leftDoorAnimation.value * (math.pi / 180)),
                          child: Container(
                            width: doorWidth,
                            height: doorHeight,
                            decoration: BoxDecoration(
                              color: Colors.red,
                              border: Border.all(
                                color: Colors.white,
                                width: 5,
                              ),
                            ),
                            child: const Center(
                              child: Text(
                                'LEFT\nDOOR',
                                textAlign: TextAlign.center,
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 20,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                  
                  // Right door
                  Positioned(
                    right: 0,
                    top: 0,
                    child: AnimatedBuilder(
                      animation: _rightDoorAnimation,
                      builder: (context, child) {
                        return Transform(
                          alignment: Alignment.centerLeft,
                          transform: Matrix4.identity()
                            ..setEntry(3, 2, 0.001)
                            ..rotateY(_rightDoorAnimation.value * (math.pi / 180)),
                          child: Container(
                            width: doorWidth,
                            height: doorHeight,
                            decoration: BoxDecoration(
                              color: Colors.blue,
                              border: Border.all(
                                color: Colors.white,
                                width: 5,
                              ),
                            ),
                            child: const Center(
                              child: Text(
                                'RIGHT\nDOOR',
                                textAlign: TextAlign.center,
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 20,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),
          
          // Animation info at bottom
          Positioned(
            bottom: 50,
            left: 0,
            right: 0,
            child: AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return Column(
                  children: [
                    Text(
                      'Progress: ${(_controller.value * 100).toStringAsFixed(0)}%',
                      style: const TextStyle(fontSize: 18),
                    ),
                    Text(
                      'Left (Red): ${_leftDoorAnimation.value.toStringAsFixed(1)}°',
                      style: const TextStyle(fontSize: 18, color: Colors.red),
                    ),
                    Text(
                      'Right (Blue): ${_rightDoorAnimation.value.toStringAsFixed(1)}°',
                      style: const TextStyle(fontSize: 18, color: Colors.blue),
                    ),
                    const SizedBox(height: 20),
                    ElevatedButton(
                      onPressed: () {
                        _controller.reset();
                        _controller.forward();
                      },
                      child: const Text('REPLAY ANIMATION'),
                    ),
                  ],
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}