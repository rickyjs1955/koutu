import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'KOUTU Mobile Test',
      theme: ThemeData(
        primarySwatch: Colors.brown,
        useMaterial3: true,
      ),
      debugShowCheckedModeBanner: false,
      home: const DiagnosticScreen(),
    );
  }
}

class DiagnosticScreen extends StatefulWidget {
  const DiagnosticScreen({Key? key}) : super(key: key);

  @override
  State<DiagnosticScreen> createState() => _DiagnosticScreenState();
}

class _DiagnosticScreenState extends State<DiagnosticScreen> {
  String status = "Initializing...";
  List<String> logs = [];
  
  @override
  void initState() {
    super.initState();
    _runDiagnostics();
  }
  
  void _addLog(String message) {
    setState(() {
      logs.add("${DateTime.now().toString().substring(11, 19)}: $message");
    });
  }
  
  Future<void> _runDiagnostics() async {
    _addLog("App started");
    
    await Future.delayed(const Duration(milliseconds: 500));
    _addLog("Delay test passed");
    
    setState(() {
      status = "Loading animation...";
    });
    
    await Future.delayed(const Duration(seconds: 1));
    _addLog("Animation should start");
    
    setState(() {
      status = "Animation running";
    });
    
    // After 3 seconds, show completion
    await Future.delayed(const Duration(seconds: 3));
    _addLog("Animation complete");
    
    setState(() {
      status = "Ready to navigate";
    });
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    
    return Scaffold(
      backgroundColor: const Color(0xFFF5E6D3),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20.0),
          child: Column(
            children: [
              // Status display
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(8),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 4,
                      offset: const Offset(0, 2),
                    ),
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Mobile Diagnostic',
                      style: TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.brown[800],
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Status: $status',
                      style: TextStyle(
                        fontSize: 16,
                        color: Colors.brown[600],
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Screen: ${size.width.toInt()} x ${size.height.toInt()}',
                      style: TextStyle(
                        fontSize: 14,
                        color: Colors.brown[500],
                      ),
                    ),
                  ],
                ),
              ),
              
              const SizedBox(height: 20),
              
              // Simple visual test
              if (status == "Animation running")
                TweenAnimationBuilder<double>(
                  tween: Tween(begin: 0.0, end: 1.0),
                  duration: const Duration(seconds: 2),
                  builder: (context, value, child) {
                    return Container(
                      width: 200,
                      height: 200,
                      decoration: BoxDecoration(
                        color: Colors.brown.withOpacity(value),
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Center(
                        child: Text(
                          'KOUTU',
                          style: TextStyle(
                            fontSize: 40,
                            fontWeight: FontWeight.bold,
                            color: Colors.white.withOpacity(value),
                          ),
                        ),
                      ),
                    );
                  },
                ),
              
              const SizedBox(height: 20),
              
              // Logs
              Expanded(
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: ListView.builder(
                    itemCount: logs.length,
                    itemBuilder: (context, index) {
                      return Text(
                        logs[index],
                        style: const TextStyle(
                          color: Colors.green,
                          fontSize: 12,
                          fontFamily: 'monospace',
                        ),
                      );
                    },
                  ),
                ),
              ),
              
              const SizedBox(height: 20),
              
              // Test button
              ElevatedButton(
                onPressed: () {
                  _addLog("Button pressed!");
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Button works!'),
                      duration: Duration(seconds: 1),
                    ),
                  );
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.brown,
                  padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 16),
                ),
                child: const Text(
                  'Test Interaction',
                  style: TextStyle(color: Colors.white),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}