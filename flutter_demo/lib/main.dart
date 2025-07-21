import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:math' as math;

void main() {
  runApp(const KoutuDemoApp());
}

class KoutuDemoApp extends StatelessWidget {
  const KoutuDemoApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Koutu - Beautiful Wardrobe Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: const DemoWardrobeShowcase(),
    );
  }
}

class DemoWardrobeShowcase extends StatefulWidget {
  const DemoWardrobeShowcase({Key? key}) : super(key: key);

  @override
  State<DemoWardrobeShowcase> createState() => _DemoWardrobeShowcaseState();
}

class _DemoWardrobeShowcaseState extends State<DemoWardrobeShowcase>
    with TickerProviderStateMixin {
  late AnimationController _fadeController;
  late AnimationController _slideController;
  late AnimationController _scaleController;
  late Animation<double> _fadeAnimation;
  late Animation<Offset> _slideAnimation;
  late Animation<double> _scaleAnimation;

  int _selectedCategory = 0;
  final List<String> _categories = ['All', 'Tops', 'Bottoms', 'Shoes', 'Accessories'];

  @override
  void initState() {
    super.initState();
    _fadeController = AnimationController(
      duration: const Duration(milliseconds: 1000),
      vsync: this,
    );
    _slideController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    );
    _scaleController = AnimationController(
      duration: const Duration(milliseconds: 600),
      vsync: this,
    );

    _fadeAnimation = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _fadeController,
      curve: Curves.easeIn,
    ));

    _slideAnimation = Tween<Offset>(
      begin: const Offset(0, 0.3),
      end: Offset.zero,
    ).animate(CurvedAnimation(
      parent: _slideController,
      curve: Curves.easeOutCubic,
    ));

    _scaleAnimation = Tween<double>(
      begin: 0.8,
      end: 1.0,
    ).animate(CurvedAnimation(
      parent: _scaleController,
      curve: Curves.elasticOut,
    ));

    _fadeController.forward();
    _slideController.forward();
    _scaleController.forward();
  }

  @override
  void dispose() {
    _fadeController.dispose();
    _slideController.dispose();
    _scaleController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              const Color(0xFF1E3C72),
              const Color(0xFF2A5298),
              const Color(0xFF7E8BA3),
            ],
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              _buildCategories(),
              Expanded(child: _buildWardrobeGrid()),
              _buildBottomBar(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return FadeTransition(
      opacity: _fadeAnimation,
      child: Container(
        padding: const EdgeInsets.all(20),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'My Wardrobe',
                  style: TextStyle(
                    fontSize: 32,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                    shadows: [
                      Shadow(
                        blurRadius: 10.0,
                        color: Colors.black.withOpacity(0.3),
                        offset: const Offset(2.0, 2.0),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  '${_getDemoItems().length} items • 4 outfits',
                  style: TextStyle(
                    fontSize: 16,
                    color: Colors.white.withOpacity(0.8),
                  ),
                ),
              ],
            ),
            Container(
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.2),
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.1),
                    blurRadius: 20,
                    offset: const Offset(0, 10),
                  ),
                ],
              ),
              child: Material(
                color: Colors.transparent,
                child: InkWell(
                  borderRadius: BorderRadius.circular(20),
                  onTap: () {
                    HapticFeedback.lightImpact();
                  },
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Icon(
                      Icons.add_rounded,
                      color: Colors.white,
                      size: 28,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCategories() {
    return SlideTransition(
      position: _slideAnimation,
      child: Container(
        height: 50,
        margin: const EdgeInsets.symmetric(vertical: 10),
        child: ListView.builder(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 20),
          itemCount: _categories.length,
          itemBuilder: (context, index) {
            bool isSelected = _selectedCategory == index;
            return GestureDetector(
              onTap: () {
                HapticFeedback.selectionClick();
                setState(() {
                  _selectedCategory = index;
                });
              },
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                margin: const EdgeInsets.only(right: 15),
                padding: const EdgeInsets.symmetric(horizontal: 25, vertical: 12),
                decoration: BoxDecoration(
                  color: isSelected
                      ? Colors.white
                      : Colors.white.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(25),
                  boxShadow: isSelected
                      ? [
                          BoxShadow(
                            color: Colors.white.withOpacity(0.3),
                            blurRadius: 20,
                            offset: const Offset(0, 5),
                          ),
                        ]
                      : [],
                ),
                child: Text(
                  _categories[index],
                  style: TextStyle(
                    color: isSelected
                        ? const Color(0xFF1E3C72)
                        : Colors.white,
                    fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                    fontSize: 16,
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildWardrobeGrid() {
    final items = _getDemoItems();
    return ScaleTransition(
      scale: _scaleAnimation,
      child: GridView.builder(
        padding: const EdgeInsets.all(20),
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 2,
          childAspectRatio: 0.75,
          crossAxisSpacing: 20,
          mainAxisSpacing: 20,
        ),
        itemCount: items.length,
        itemBuilder: (context, index) {
          return _buildWardrobeItem(items[index], index);
        },
      ),
    );
  }

  Widget _buildWardrobeItem(Map<String, dynamic> item, int index) {
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0.0, end: 1.0),
      duration: Duration(milliseconds: 600 + (index * 100)),
      curve: Curves.easeOutBack,
      builder: (context, value, child) {
        return Transform.scale(
          scale: value,
          child: Container(
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(25),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.2),
                  blurRadius: 20,
                  offset: const Offset(0, 10),
                ),
              ],
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(25),
              child: Stack(
                children: [
                  Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                        colors: [
                          item['color'].withOpacity(0.8),
                          item['color'],
                        ],
                      ),
                    ),
                  ),
                  Center(
                    child: Icon(
                      item['icon'],
                      size: 80,
                      color: Colors.white.withOpacity(0.9),
                    ),
                  ),
                  Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [
                          Colors.white.withOpacity(0.1),
                          Colors.white.withOpacity(0.0),
                        ],
                      ),
                    ),
                  ),
                  Positioned(
                    bottom: 0,
                    left: 0,
                    right: 0,
                    child: Container(
                      padding: const EdgeInsets.all(15),
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [
                            Colors.transparent,
                            Colors.black.withOpacity(0.6),
                          ],
                        ),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            item['name'],
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              Icon(
                                Icons.star_rounded,
                                color: Colors.amber,
                                size: 16,
                              ),
                              const SizedBox(width: 4),
                              Text(
                                item['rating'].toString(),
                                style: TextStyle(
                                  color: Colors.white.withOpacity(0.9),
                                  fontSize: 14,
                                ),
                              ),
                              const Spacer(),
                              Text(
                                item['wornCount'],
                                style: TextStyle(
                                  color: Colors.white.withOpacity(0.7),
                                  fontSize: 12,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                  Positioned(
                    top: 10,
                    right: 10,
                    child: Container(
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(15),
                      ),
                      child: Material(
                        color: Colors.transparent,
                        child: InkWell(
                          borderRadius: BorderRadius.circular(15),
                          onTap: () {
                            HapticFeedback.lightImpact();
                          },
                          child: Padding(
                            padding: const EdgeInsets.all(8),
                            child: Icon(
                              item['isFavorite']
                                  ? Icons.favorite_rounded
                                  : Icons.favorite_border_rounded,
                              color: Colors.white,
                              size: 20,
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildBottomBar() {
    return Container(
      height: 80,
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: const BorderRadius.only(
          topLeft: Radius.circular(30),
          topRight: Radius.circular(30),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _buildBottomBarItem(Icons.home_rounded, 'Home', true),
          _buildBottomBarItem(Icons.search_rounded, 'Search', false),
          _buildBottomBarItem(Icons.camera_alt_rounded, 'Scan', false),
          _buildBottomBarItem(Icons.person_rounded, 'Profile', false),
        ],
      ),
    );
  }

  Widget _buildBottomBarItem(IconData icon, String label, bool isSelected) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(20),
        onTap: () {
          HapticFeedback.selectionClick();
        },
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                icon,
                color: isSelected ? Colors.white : Colors.white.withOpacity(0.6),
                size: 28,
              ),
              const SizedBox(height: 4),
              Text(
                label,
                style: TextStyle(
                  color: isSelected ? Colors.white : Colors.white.withOpacity(0.6),
                  fontSize: 12,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  List<Map<String, dynamic>> _getDemoItems() {
    return [
      {
        'name': 'Summer Dress',
        'icon': Icons.checkroom_rounded,
        'color': const Color(0xFFFF6B6B),
        'rating': 4.8,
        'wornCount': 'Worn 12 times',
        'isFavorite': true,
      },
      {
        'name': 'Denim Jacket',
        'icon': Icons.checkroom_rounded,
        'color': const Color(0xFF4ECDC4),
        'rating': 4.5,
        'wornCount': 'Worn 8 times',
        'isFavorite': false,
      },
      {
        'name': 'Running Shoes',
        'icon': Icons.directions_run_rounded,
        'color': const Color(0xFF45B7D1),
        'rating': 5.0,
        'wornCount': 'Worn 25 times',
        'isFavorite': true,
      },
      {
        'name': 'Leather Bag',
        'icon': Icons.shopping_bag_rounded,
        'color': const Color(0xFFF7B731),
        'rating': 4.6,
        'wornCount': 'Worn 15 times',
        'isFavorite': false,
      },
      {
        'name': 'Sunglasses',
        'icon': Icons.wb_sunny_rounded,
        'color': const Color(0xFF5F27CD),
        'rating': 4.9,
        'wornCount': 'Worn 20 times',
        'isFavorite': true,
      },
      {
        'name': 'Watch',
        'icon': Icons.watch_rounded,
        'color': const Color(0xFF00D2D3),
        'rating': 4.7,
        'wornCount': 'Worn 30 times',
        'isFavorite': false,
      },
    ];
  }
}