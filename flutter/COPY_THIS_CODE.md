# Create main_simple.dart

Since the files aren't syncing between WSL and Windows, please:

1. Create a new file: `C:\Users\monmo\koutu\flutter\lib\main_simple.dart`

2. Copy and paste this code:

```dart
import 'package:flutter/material.dart';

void main() {
  runApp(const SimpleKoutuApp());
}

class SimpleKoutuApp extends StatelessWidget {
  const SimpleKoutuApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu Fashion AI',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const SimpleHomeScreen(),
    );
  }
}

class SimpleHomeScreen extends StatelessWidget {
  const SimpleHomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Koutu Fashion AI'),
        backgroundColor: Colors.blue,
        foregroundColor: Colors.white,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Welcome Card
            Card(
              elevation: 4,
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.blue,
                      Colors.blue.withOpacity(0.8),
                    ],
                  ),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  children: [
                    const Icon(
                      Icons.auto_awesome,
                      size: 60,
                      color: Colors.white,
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'Welcome to Koutu AI',
                      style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Your AI-Powered Fashion Assistant',
                      style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                        color: Colors.white70,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            
            const SizedBox(height: 24),
            
            // Features
            Text(
              'Features',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 16),
            
            _buildFeatureCard(
              context,
              'Capture Garments',
              'Upload photos and draw polygons to identify garments',
              Icons.camera_alt,
              Colors.blue,
            ),
            const SizedBox(height: 12),
            _buildFeatureCard(
              context,
              'Digital Wardrobe', 
              'Organize and manage your clothing collection',
              Icons.checkroom,
              Colors.purple,
            ),
            const SizedBox(height: 12),
            _buildFeatureCard(
              context,
              'AI Outfit Builder',
              'Get personalized outfit recommendations',
              Icons.auto_awesome,
              Colors.orange,
            ),
            const SizedBox(height: 12),
            _buildFeatureCard(
              context,
              'Fashion Analytics',
              'Track your fashion habits and trends',
              Icons.analytics,
              Colors.green,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFeatureCard(
    BuildContext context,
    String title,
    String description,
    IconData icon,
    Color color,
  ) {
    return Card(
      child: InkWell(
        onTap: () {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('$title coming soon!'),
              backgroundColor: color,
            ),
          );
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(icon, color: color, size: 32),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      description,
                      style: TextStyle(
                        fontSize: 14,
                        color: Colors.grey[600],
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.arrow_forward_ios, size: 16),
            ],
          ),
        ),
      ),
    );
  }
}
```

3. Save the file

4. Run:
```powershell
flutter run -d chrome --web-port=5000 -t lib/main_simple.dart
```

This is a completely self-contained file with no dependencies on other files.