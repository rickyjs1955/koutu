import 'package:flutter/material.dart';
import 'package:koutu/presentation/screens/home/home_screen.dart';
import 'package:koutu/presentation/screens/garment/garment_capture_screen.dart';
import 'package:koutu/presentation/screens/wardrobe/digital_wardrobe_screen.dart';
import 'package:koutu/presentation/screens/outfit/ai_outfit_builder_screen.dart';
import 'package:koutu/presentation/screens/splash/simple_splash_screen.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/theme/app_theme.dart';

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
      theme: AppTheme.lightTheme,
      home: const SimpleSplashScreen(),
      routes: {
        '/home': (context) => const SimpleNavigationScreen(),
      },
    );
  }
}

// Simple navigation screen without dependency injection
class SimpleNavigationScreen extends StatefulWidget {
  const SimpleNavigationScreen({super.key});

  @override
  State<SimpleNavigationScreen> createState() => _SimpleNavigationScreenState();
}

class _SimpleNavigationScreenState extends State<SimpleNavigationScreen> {
  int _selectedIndex = 0;
  
  final List<Widget> _screens = [
    const SimpleHomeScreen(),
    const GarmentCaptureScreen(),
    const DigitalWardrobeScreen(),
    const AIOutfitBuilderScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: _screens[_selectedIndex],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (index) {
          setState(() {
            _selectedIndex = index;
          });
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.add_a_photo),
            label: 'Capture',
          ),
          NavigationDestination(
            icon: Icon(Icons.checkroom),
            label: 'Wardrobe',
          ),
          NavigationDestination(
            icon: Icon(Icons.auto_awesome),
            label: 'AI Outfit',
          ),
        ],
      ),
    );
  }
}

// Simplified home screen without auth
class SimpleHomeScreen extends StatelessWidget {
  const SimpleHomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.backgroundLight,
      appBar: AppBar(
        title: const Text('Koutu Fashion AI'),
        backgroundColor: AppColors.primary,
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
                      AppColors.primary,
                      AppColors.primary.withOpacity(0.8),
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
            
            // Quick Stats
            Row(
              children: [
                Expanded(
                  child: _buildStatCard(
                    context,
                    '12',
                    'Garments',
                    Icons.checkroom,
                    Colors.purple,
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: _buildStatCard(
                    context,
                    '5',
                    'Outfits',
                    Icons.style,
                    Colors.orange,
                  ),
                ),
              ],
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
          ],
        ),
      ),
    );
  }

  Widget _buildStatCard(
    BuildContext context,
    String value,
    String label,
    IconData icon,
    Color color,
  ) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Icon(icon, color: color, size: 32),
            const SizedBox(height: 8),
            Text(
              value,
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                color: color,
                fontWeight: FontWeight.bold,
              ),
            ),
            Text(
              label,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Colors.grey[600],
              ),
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
      child: ListTile(
        leading: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, color: color),
        ),
        title: Text(
          title,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        subtitle: Text(description),
        trailing: const Icon(Icons.arrow_forward_ios, size: 16),
      ),
    );
  }
}