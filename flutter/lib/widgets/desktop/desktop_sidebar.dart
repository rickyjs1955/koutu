import 'package:flutter/material.dart';
import 'package:koutu/screens/desktop/desktop_home_screen.dart';

/// Desktop sidebar navigation
class DesktopSidebar extends StatelessWidget {
  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final List<DesktopScreenInfo> screens;
  final bool isExpanded;
  final VoidCallback onToggleExpanded;

  const DesktopSidebar({
    Key? key,
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.screens,
    required this.isExpanded,
    required this.onToggleExpanded,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      width: isExpanded ? 240 : 72,
      decoration: BoxDecoration(
        color: colorScheme.surfaceVariant.withOpacity(0.3),
        border: Border(
          right: BorderSide(
            color: colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // Logo and toggle
          Container(
            height: 72,
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Icon(
                  Icons.checkroom,
                  size: 32,
                  color: colorScheme.primary,
                ),
                if (isExpanded) ...[
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Koutu',
                      style: theme.textTheme.headlineSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                        color: colorScheme.primary,
                      ),
                    ),
                  ),
                ],
                IconButton(
                  icon: Icon(
                    isExpanded ? Icons.chevron_left : Icons.chevron_right,
                    color: colorScheme.onSurfaceVariant,
                  ),
                  onPressed: onToggleExpanded,
                ),
              ],
            ),
          ),
          
          const Divider(height: 1),
          
          // Navigation items
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: screens.length,
              itemBuilder: (context, index) {
                final screen = screens[index];
                final isSelected = index == selectedIndex;
                
                return Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Material(
                    color: Colors.transparent,
                    child: InkWell(
                      onTap: () => onDestinationSelected(index),
                      borderRadius: BorderRadius.circular(8),
                      child: Container(
                        height: 48,
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? colorScheme.primaryContainer
                              : Colors.transparent,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              isSelected ? screen.selectedIcon : screen.icon,
                              size: 24,
                              color: isSelected
                                  ? colorScheme.onPrimaryContainer
                                  : colorScheme.onSurfaceVariant,
                            ),
                            if (isExpanded) ...[
                              const SizedBox(width: 16),
                              Expanded(
                                child: Text(
                                  screen.title,
                                  style: theme.textTheme.bodyLarge?.copyWith(
                                    color: isSelected
                                        ? colorScheme.onPrimaryContainer
                                        : colorScheme.onSurfaceVariant,
                                    fontWeight: isSelected
                                        ? FontWeight.w600
                                        : FontWeight.w400,
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          
          const Divider(height: 1),
          
          // Bottom actions
          Container(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                if (isExpanded) ...[
                  // Sync status
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.green.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          Icons.sync,
                          size: 16,
                          color: Colors.green,
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Synced',
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: Colors.green,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              Text(
                                'Last sync: 2 min ago',
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: Colors.green.withOpacity(0.8),
                                  fontSize: 10,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                ],
                
                // User profile
                InkWell(
                  onTap: () {
                    // TODO: User profile
                  },
                  borderRadius: BorderRadius.circular(8),
                  child: Container(
                    padding: const EdgeInsets.all(8),
                    child: Row(
                      children: [
                        CircleAvatar(
                          radius: 16,
                          backgroundColor: colorScheme.primary,
                          child: Icon(
                            Icons.person,
                            size: 18,
                            color: colorScheme.onPrimary,
                          ),
                        ),
                        if (isExpanded) ...[
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Fashion Enthusiast',
                                  style: theme.textTheme.bodyMedium?.copyWith(
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                                Text(
                                  'Premium Member',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: colorScheme.onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}