import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/screens/desktop/desktop_wardrobe_screen.dart';
import 'package:koutu/screens/desktop/desktop_outfits_screen.dart';
import 'package:koutu/screens/desktop/desktop_analytics_screen.dart';
import 'package:koutu/screens/desktop/desktop_settings_screen.dart';
import 'package:koutu/widgets/desktop/desktop_sidebar.dart';
import 'package:koutu/widgets/desktop/desktop_title_bar.dart';
import 'package:koutu/widgets/desktop/desktop_status_bar.dart';

/// Desktop companion app home screen
class DesktopHomeScreen extends ConsumerStatefulWidget {
  const DesktopHomeScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<DesktopHomeScreen> createState() => _DesktopHomeScreenState();
}

class _DesktopHomeScreenState extends ConsumerState<DesktopHomeScreen> {
  int _selectedIndex = 0;
  bool _isSidebarExpanded = true;

  final List<DesktopScreenInfo> _screens = [
    DesktopScreenInfo(
      title: 'Wardrobe',
      icon: Icons.checkroom_outlined,
      selectedIcon: Icons.checkroom,
      screen: const DesktopWardrobeScreen(),
    ),
    DesktopScreenInfo(
      title: 'Outfits',
      icon: Icons.style_outlined,
      selectedIcon: Icons.style,
      screen: const DesktopOutfitsScreen(),
    ),
    DesktopScreenInfo(
      title: 'Analytics',
      icon: Icons.analytics_outlined,
      selectedIcon: Icons.analytics,
      screen: const DesktopAnalyticsScreen(),
    ),
    DesktopScreenInfo(
      title: 'Settings',
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings,
      screen: const DesktopSettingsScreen(),
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      body: Column(
        children: [
          // Title bar
          DesktopTitleBar(
            title: 'Koutu - ${_screens[_selectedIndex].title}',
            onMinimize: () {
              // TODO: Minimize window
            },
            onMaximize: () {
              // TODO: Maximize window
            },
            onClose: () {
              // TODO: Close window
            },
          ),
          
          // Main content
          Expanded(
            child: Row(
              children: [
                // Sidebar
                DesktopSidebar(
                  selectedIndex: _selectedIndex,
                  onDestinationSelected: (index) {
                    setState(() {
                      _selectedIndex = index;
                    });
                  },
                  screens: _screens,
                  isExpanded: _isSidebarExpanded,
                  onToggleExpanded: () {
                    setState(() {
                      _isSidebarExpanded = !_isSidebarExpanded;
                    });
                  },
                ),
                
                // Main content area
                Expanded(
                  child: Container(
                    decoration: BoxDecoration(
                      color: colorScheme.surface,
                      border: Border(
                        left: BorderSide(
                          color: colorScheme.outlineVariant,
                          width: 1,
                        ),
                      ),
                    ),
                    child: _screens[_selectedIndex].screen,
                  ),
                ),
              ],
            ),
          ),
          
          // Status bar
          const DesktopStatusBar(),
        ],
      ),
    );
  }
}

class DesktopScreenInfo {
  final String title;
  final IconData icon;
  final IconData selectedIcon;
  final Widget screen;

  const DesktopScreenInfo({
    required this.title,
    required this.icon,
    required this.selectedIcon,
    required this.screen,
  });
}