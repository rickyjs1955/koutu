import 'package:flutter/material.dart';
import 'package:koutu/screens/tablet/tablet_home_screen.dart';

/// Custom navigation rail for iPad with split-screen support
class TabletNavigationRail extends StatelessWidget {
  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final List<TabletScreenInfo> screens;
  final VoidCallback? onSplitScreenToggle;
  final bool isSplitScreenEnabled;
  final int? secondaryIndex;
  final ValueChanged<int>? onSecondaryDestinationSelected;

  const TabletNavigationRail({
    Key? key,
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.screens,
    this.onSplitScreenToggle,
    this.isSplitScreenEnabled = false,
    this.secondaryIndex,
    this.onSecondaryDestinationSelected,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      width: 72,
      decoration: BoxDecoration(
        color: colorScheme.surface,
        border: Border(
          right: BorderSide(
            color: colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // Logo/Header
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Icon(
              Icons.checkroom,
              size: 32,
              color: colorScheme.primary,
            ),
          ),
          
          const SizedBox(height: 16),
          
          // Navigation destinations
          Expanded(
            child: ListView.builder(
              itemCount: screens.length,
              itemBuilder: (context, index) {
                final screen = screens[index];
                final isSelected = index == selectedIndex;
                final isSecondary = index == secondaryIndex;
                
                return Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8.0,
                    vertical: 4.0,
                  ),
                  child: GestureDetector(
                    onTap: () {
                      if (isSplitScreenEnabled && isSelected && onSecondaryDestinationSelected != null) {
                        // If split screen is enabled and this is the primary screen,
                        // allow selection of secondary screen
                        _showSecondaryScreenSelector(context, index);
                      } else {
                        onDestinationSelected(index);
                      }
                    },
                    child: Container(
                      width: 56,
                      height: 56,
                      decoration: BoxDecoration(
                        color: isSelected
                            ? colorScheme.primaryContainer
                            : isSecondary
                                ? colorScheme.secondaryContainer
                                : Colors.transparent,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Stack(
                        children: [
                          Center(
                            child: Icon(
                              isSelected ? screen.selectedIcon : screen.icon,
                              size: 24,
                              color: isSelected
                                  ? colorScheme.onPrimaryContainer
                                  : isSecondary
                                      ? colorScheme.onSecondaryContainer
                                      : colorScheme.onSurface,
                            ),
                          ),
                          if (isSecondary)
                            Positioned(
                              top: 4,
                              right: 4,
                              child: Container(
                                width: 8,
                                height: 8,
                                decoration: BoxDecoration(
                                  color: colorScheme.secondary,
                                  shape: BoxShape.circle,
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          
          // Split screen toggle
          if (onSplitScreenToggle != null)
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: GestureDetector(
                onTap: onSplitScreenToggle,
                child: Container(
                  width: 56,
                  height: 56,
                  decoration: BoxDecoration(
                    color: isSplitScreenEnabled
                        ? colorScheme.primaryContainer
                        : colorScheme.surfaceVariant,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Icon(
                    isSplitScreenEnabled
                        ? Icons.view_column
                        : Icons.view_agenda,
                    size: 24,
                    color: isSplitScreenEnabled
                        ? colorScheme.onPrimaryContainer
                        : colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  void _showSecondaryScreenSelector(BuildContext context, int primaryIndex) {
    showModalBottomSheet(
      context: context,
      builder: (context) {
        return Container(
          height: 200,
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Select Secondary Screen',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              Expanded(
                child: GridView.builder(
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 4,
                    mainAxisSpacing: 8,
                    crossAxisSpacing: 8,
                  ),
                  itemCount: screens.length,
                  itemBuilder: (context, index) {
                    if (index == primaryIndex) return const SizedBox();
                    
                    final screen = screens[index];
                    final isSelected = index == secondaryIndex;
                    
                    return GestureDetector(
                      onTap: () {
                        onSecondaryDestinationSelected?.call(index);
                        Navigator.pop(context);
                      },
                      child: Container(
                        decoration: BoxDecoration(
                          color: isSelected
                              ? Theme.of(context).colorScheme.primaryContainer
                              : Theme.of(context).colorScheme.surfaceVariant,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              screen.icon,
                              size: 24,
                              color: isSelected
                                  ? Theme.of(context).colorScheme.onPrimaryContainer
                                  : Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              screen.title,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: isSelected
                                    ? Theme.of(context).colorScheme.onPrimaryContainer
                                    : Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                              textAlign: TextAlign.center,
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}