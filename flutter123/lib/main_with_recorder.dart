import 'package:flutter/material.dart';
import 'main.dart' as original_main;
import 'animation_recorder.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu Animation Recorder',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      debugShowCheckedModeBanner: false,
      home: const RecordableApp(),
    );
  }
}

class RecordableApp extends StatelessWidget {
  const RecordableApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return AnimationRecorder(
      duration: const Duration(seconds: 8),
      fps: 30,
      child: const original_main.HelloSplashScreen(),
    );
  }
}