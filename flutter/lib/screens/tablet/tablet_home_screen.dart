import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/screens/tablet/tablet_wardrobe_screen.dart';
import 'package:koutu/screens/tablet/tablet_outfits_screen.dart';
import 'package:koutu/screens/tablet/tablet_camera_screen.dart';
import 'package:koutu/screens/tablet/tablet_profile_screen.dart';
import 'package:koutu/widgets/tablet/tablet_navigation_rail.dart';
import 'package:koutu/widgets/tablet/tablet_app_bar.dart';
import 'package:koutu/widgets/tablet/split_screen_layout.dart';

/// iPad-specific home screen with split-screen support
class TabletHomeScreen extends ConsumerStatefulWidget {
  const TabletHomeScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<TabletHomeScreen> createState() => _TabletHomeScreenState();
}

class _TabletHomeScreenState extends ConsumerState<TabletHomeScreen> {
  int _selectedIndex = 0;
  bool _isSplitScreenEnabled = false;
  int? _secondaryIndex;

  final List<TabletScreenInfo> _screens = [
    TabletScreenInfo(
      title: 'Wardrobe',
      icon: Icons.checkroom_outlined,
      selectedIcon: Icons.checkroom,
      screen: const TabletWardrobeScreen(),
    ),
    TabletScreenInfo(
      title: 'Outfits',
      icon: Icons.style_outlined,
      selectedIcon: Icons.style,
      screen: const TabletOutfitsScreen(),
    ),
    TabletScreenInfo(
      title: 'Camera',
      icon: Icons.camera_alt_outlined,
      selectedIcon: Icons.camera_alt,
      screen: const TabletCameraScreen(),
    ),
    TabletScreenInfo(
      title: 'Profile',
      icon: Icons.person_outline,
      selectedIcon: Icons.person,
      screen: const TabletProfileScreen(),
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    final isLandscape = screenSize.width > screenSize.height;
    final canUseSplitScreen = screenSize.width > 1080; // iPad Pro size

    return Scaffold(
      body: Row(
        children: [
          // Navigation rail
          TabletNavigationRail(
            selectedIndex: _selectedIndex,
            onDestinationSelected: (index) {
              setState(() {
                _selectedIndex = index;
              });
            },
            screens: _screens,
            onSplitScreenToggle: canUseSplitScreen
                ? () {
                    setState(() {
                      _isSplitScreenEnabled = !_isSplitScreenEnabled;
                      if (_isSplitScreenEnabled && _secondaryIndex == null) {
                        _secondaryIndex = (_selectedIndex + 1) % _screens.length;
                      }
                    });
                  }
                : null,
            isSplitScreenEnabled: _isSplitScreenEnabled,
            secondaryIndex: _secondaryIndex,
            onSecondaryDestinationSelected: (index) {
              setState(() {
                _secondaryIndex = index;
              });
            },
          ),
          
          // Main content area
          Expanded(
            child: Column(
              children: [
                // App bar
                TabletAppBar(
                  title: _isSplitScreenEnabled
                      ? '${_screens[_selectedIndex].title} | ${_screens[_secondaryIndex!].title}'
                      : _screens[_selectedIndex].title,
                  actions: [
                    if (canUseSplitScreen)
                      IconButton(
                        icon: Icon(_isSplitScreenEnabled
                            ? Icons.view_column
                            : Icons.view_agenda),
                        onPressed: () {
                          setState(() {
                            _isSplitScreenEnabled = !_isSplitScreenEnabled;
                            if (_isSplitScreenEnabled && _secondaryIndex == null) {
                              _secondaryIndex = (_selectedIndex + 1) % _screens.length;
                            }
                          });
                        },
                        tooltip: _isSplitScreenEnabled
                            ? 'Exit Split Screen'
                            : 'Enter Split Screen',
                      ),
                    IconButton(
                      icon: const Icon(Icons.search),
                      onPressed: () {
                        // TODO: Implement search
                      },
                    ),
                    IconButton(
                      icon: const Icon(Icons.more_vert),
                      onPressed: () {
                        // TODO: Implement menu
                      },
                    ),
                  ],
                ),
                
                // Content area
                Expanded(
                  child: _isSplitScreenEnabled && _secondaryIndex != null
                      ? SplitScreenLayout(
                          primaryScreen: _screens[_selectedIndex].screen,
                          secondaryScreen: _screens[_secondaryIndex!].screen,
                          isVerticalSplit: !isLandscape,
                          splitRatio: 0.6,
                          onSplitRatioChanged: (ratio) {
                            // Handle split ratio changes
                          },
                        )
                      : _screens[_selectedIndex].screen,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class TabletScreenInfo {
  final String title;
  final IconData icon;
  final IconData selectedIcon;
  final Widget screen;

  const TabletScreenInfo({
    required this.title,
    required this.icon,
    required this.selectedIcon,
    required this.screen,
  });
}