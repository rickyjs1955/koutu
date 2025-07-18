import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/widgets/tablet/tablet_app_bar.dart';
import 'package:koutu/widgets/tablet/adaptive_grid.dart';
import 'package:koutu/widgets/tablet/tablet_filter_panel.dart';
import 'package:koutu/widgets/tablet/tablet_garment_card.dart';

/// iPad-specific wardrobe screen with enhanced layout
class TabletWardrobeScreen extends ConsumerStatefulWidget {
  const TabletWardrobeScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<TabletWardrobeScreen> createState() => _TabletWardrobeScreenState();
}

class _TabletWardrobeScreenState extends ConsumerState<TabletWardrobeScreen> {
  bool _isSearchActive = false;
  bool _isFilterPanelOpen = false;
  String _searchQuery = '';
  Set<String> _selectedFilters = {};

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: TabletSearchAppBar(
        title: 'Wardrobe',
        isSearchActive: _isSearchActive,
        onSearchToggle: () {
          setState(() {
            _isSearchActive = !_isSearchActive;
            if (!_isSearchActive) {
              _searchQuery = '';
            }
          });
        },
        onSearchChanged: (query) {
          setState(() {
            _searchQuery = query;
          });
        },
        actions: [
          IconButton(
            icon: Icon(
              _isFilterPanelOpen ? Icons.filter_list : Icons.filter_list_outlined,
              color: _isFilterPanelOpen ? colorScheme.primary : null,
            ),
            onPressed: () {
              setState(() {
                _isFilterPanelOpen = !_isFilterPanelOpen;
              });
            },
            tooltip: 'Filters',
          ),
          IconButton(
            icon: const Icon(Icons.view_module),
            onPressed: () {
              // TODO: Toggle view mode
            },
            tooltip: 'View options',
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_vert),
            onSelected: (value) {
              switch (value) {
                case 'sort':
                  _showSortOptions(context);
                  break;
                case 'export':
                  // TODO: Export wardrobe
                  break;
                case 'settings':
                  // TODO: Wardrobe settings
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'sort',
                child: Row(
                  children: [
                    Icon(Icons.sort),
                    SizedBox(width: 8),
                    Text('Sort'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'export',
                child: Row(
                  children: [
                    Icon(Icons.file_download),
                    SizedBox(width: 8),
                    Text('Export'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'settings',
                child: Row(
                  children: [
                    Icon(Icons.settings),
                    SizedBox(width: 8),
                    Text('Settings'),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: Row(
        children: [
          // Filter panel
          AnimatedContainer(
            duration: const Duration(milliseconds: 300),
            width: _isFilterPanelOpen ? 280 : 0,
            child: _isFilterPanelOpen
                ? TabletFilterPanel(
                    selectedFilters: _selectedFilters,
                    onFiltersChanged: (filters) {
                      setState(() {
                        _selectedFilters = filters;
                      });
                    },
                  )
                : null,
          ),
          
          // Main content
          Expanded(
            child: Column(
              children: [
                // Quick stats bar
                _buildQuickStatsBar(theme),
                
                // Garment grid
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: AdaptiveGrid(
                      itemCount: 50, // Placeholder count
                      itemBuilder: (context, index) {
                        return TabletGarmentCard(
                          garmentId: 'garment_$index',
                          name: 'Garment ${index + 1}',
                          category: 'Tops',
                          imageUrl: null,
                          onTap: () {
                            _showGarmentDetails(context, index);
                          },
                        );
                      },
                      minItemWidth: 200,
                      maxItemWidth: 300,
                      itemAspectRatio: 0.8,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () {
          // TODO: Add new garment
        },
        icon: const Icon(Icons.add),
        label: const Text('Add Garment'),
      ),
    );
  }

  Widget _buildQuickStatsBar(ThemeData theme) {
    return Container(
      height: 60,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceVariant.withOpacity(0.5),
        border: Border(
          bottom: BorderSide(
            color: theme.colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          _buildStatChip(
            icon: Icons.checkroom,
            label: 'Total',
            value: '142',
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 16),
          _buildStatChip(
            icon: Icons.favorite,
            label: 'Favorites',
            value: '23',
            color: theme.colorScheme.secondary,
          ),
          const SizedBox(width: 16),
          _buildStatChip(
            icon: Icons.new_releases,
            label: 'New',
            value: '5',
            color: theme.colorScheme.tertiary,
          ),
          const Spacer(),
          Text(
            'Last updated: 2 hours ago',
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withOpacity(0.6),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatChip({
    required IconData icon,
    required String label,
    required String value,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            icon,
            size: 16,
            color: color,
          ),
          const SizedBox(width: 6),
          Text(
            '$label: $value',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: color,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  void _showSortOptions(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Sort Options'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.sort_by_alpha),
                title: const Text('Name'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Sort by name
                },
              ),
              ListTile(
                leading: const Icon(Icons.date_range),
                title: const Text('Date Added'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Sort by date
                },
              ),
              ListTile(
                leading: const Icon(Icons.category),
                title: const Text('Category'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Sort by category
                },
              ),
              ListTile(
                leading: const Icon(Icons.star),
                title: const Text('Rating'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Sort by rating
                },
              ),
            ],
          ),
        );
      },
    );
  }

  void _showGarmentDetails(BuildContext context, int index) {
    showDialog(
      context: context,
      builder: (context) {
        return Dialog(
          child: Container(
            width: 600,
            height: 500,
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      'Garment ${index + 1}',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () => Navigator.pop(context),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Expanded(
                  child: Row(
                    children: [
                      // Image placeholder
                      Container(
                        width: 200,
                        height: 250,
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.surfaceVariant,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: const Icon(
                          Icons.image,
                          size: 64,
                        ),
                      ),
                      const SizedBox(width: 24),
                      // Details
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Category: Tops',
                              style: Theme.of(context).textTheme.bodyLarge,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Brand: Sample Brand',
                              style: Theme.of(context).textTheme.bodyLarge,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Size: M',
                              style: Theme.of(context).textTheme.bodyLarge,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Color: Blue',
                              style: Theme.of(context).textTheme.bodyLarge,
                            ),
                            const SizedBox(height: 16),
                            Row(
                              children: [
                                ElevatedButton(
                                  onPressed: () {
                                    // TODO: Edit garment
                                  },
                                  child: const Text('Edit'),
                                ),
                                const SizedBox(width: 8),
                                OutlinedButton(
                                  onPressed: () {
                                    // TODO: Delete garment
                                  },
                                  child: const Text('Delete'),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}