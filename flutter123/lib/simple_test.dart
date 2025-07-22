import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu Test',
      home: Scaffold(
        backgroundColor: const Color(0xFFF5E6D3),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(10),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 10,
                      offset: const Offset(0, 5),
                    ),
                  ],
                ),
                child: Column(
                  children: const [
                    Text(
                      'KOUTU',
                      style: TextStyle(
                        fontSize: 48,
                        fontWeight: FontWeight.bold,
                        color: Color(0xFF8B6F47),
                        letterSpacing: 8,
                      ),
                    ),
                    SizedBox(height: 10),
                    Text(
                      'Your Digital Wardrobe',
                      style: TextStyle(
                        fontSize: 20,
                        color: Color(0xFF5D4037),
                      ),
                    ),
                    SizedBox(height: 20),
                    CircularProgressIndicator(
                      color: Color(0xFF8B6F47),
                    ),
                    SizedBox(height: 20),
                    Text(
                      'Simple Test Version',
                      style: TextStyle(
                        fontSize: 16,
                        color: Colors.grey,
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
  }
}