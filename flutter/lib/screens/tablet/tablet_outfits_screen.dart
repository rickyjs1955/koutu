import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/widgets/tablet/tablet_app_bar.dart';
import 'package:koutu/widgets/tablet/adaptive_grid.dart';
import 'package:koutu/widgets/tablet/tablet_outfit_card.dart';
import 'package:koutu/widgets/tablet/tablet_filter_panel.dart';

/// iPad-specific outfits screen
class TabletOutfitsScreen extends ConsumerStatefulWidget {
  const TabletOutfitsScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<TabletOutfitsScreen> createState() => _TabletOutfitsScreenState();
}

class _TabletOutfitsScreenState extends ConsumerState<TabletOutfitsScreen> {
  bool _isSearchActive = false;
  bool _isFilterPanelOpen = false;
  String _searchQuery = '';
  Set<String> _selectedFilters = {};
  String _selectedView = 'grid'; // grid, list, calendar

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: TabletSearchAppBar(
        title: 'Outfits',
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
          PopupMenuButton<String>(
            icon: Icon(
              _selectedView == 'grid' ? Icons.view_module :
              _selectedView == 'list' ? Icons.view_list :
              Icons.calendar_view_month,
            ),
            onSelected: (value) {
              setState(() {
                _selectedView = value;
              });
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                value: 'grid',
                child: Row(
                  children: [
                    Icon(Icons.view_module, color: _selectedView == 'grid' ? colorScheme.primary : null),
                    const SizedBox(width: 8),
                    const Text('Grid View'),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'list',
                child: Row(
                  children: [
                    Icon(Icons.view_list, color: _selectedView == 'list' ? colorScheme.primary : null),
                    const SizedBox(width: 8),
                    const Text('List View'),
                  ],
                ),
              ),
              PopupMenuItem(
                value: 'calendar',
                child: Row(
                  children: [
                    Icon(Icons.calendar_view_month, color: _selectedView == 'calendar' ? colorScheme.primary : null),
                    const SizedBox(width: 8),
                    const Text('Calendar View'),
                  ],
                ),
              ),
            ],
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_vert),
            onSelected: (value) {
              switch (value) {
                case 'create':
                  _showCreateOutfitDialog(context);
                  break;
                case 'import':
                  // TODO: Import outfits
                  break;
                case 'export':
                  // TODO: Export outfits
                  break;
                case 'settings':
                  // TODO: Outfit settings
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'create',
                child: Row(
                  children: [
                    Icon(Icons.add),
                    SizedBox(width: 8),
                    Text('Create Outfit'),
                  ],
                ),
              ),
              const PopupMenuItem(
                value: 'import',
                child: Row(
                  children: [
                    Icon(Icons.file_upload),
                    SizedBox(width: 8),
                    Text('Import'),
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
                // Quick actions bar
                _buildQuickActionsBar(theme),
                
                // Content based on selected view
                Expanded(
                  child: _buildContent(),
                ),
              ],
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () {
          _showCreateOutfitDialog(context);
        },
        icon: const Icon(Icons.add),
        label: const Text('Create Outfit'),
      ),
    );
  }

  Widget _buildQuickActionsBar(ThemeData theme) {
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
            icon: Icons.style,
            label: 'Total',
            value: '42',
            color: theme.colorScheme.primary,
          ),
          const SizedBox(width: 16),
          _buildStatChip(
            icon: Icons.today,
            label: 'Today',
            value: '3',
            color: theme.colorScheme.secondary,
          ),
          const SizedBox(width: 16),
          _buildStatChip(
            icon: Icons.star,
            label: 'Favorites',
            value: '12',
            color: theme.colorScheme.tertiary,
          ),
          const Spacer(),
          ElevatedButton.icon(
            onPressed: () {
              // TODO: Generate outfit suggestions
            },
            icon: const Icon(Icons.auto_fix_high),
            label: const Text('Generate Suggestions'),
            style: ElevatedButton.styleFrom(
              backgroundColor: theme.colorScheme.primaryContainer,
              foregroundColor: theme.colorScheme.onPrimaryContainer,
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

  Widget _buildContent() {
    switch (_selectedView) {
      case 'grid':
        return _buildGridView();
      case 'list':
        return _buildListView();
      case 'calendar':
        return _buildCalendarView();
      default:
        return _buildGridView();
    }
  }

  Widget _buildGridView() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: AdaptiveGrid(
        itemCount: 20, // Placeholder count
        itemBuilder: (context, index) {
          return TabletOutfitCard(
            outfitId: 'outfit_$index',
            name: 'Outfit ${index + 1}',
            description: 'A stylish outfit for any occasion',
            imageUrl: null,
            garmentCount: 4,
            tags: ['casual', 'summer'],
            isFavorite: index % 5 == 0,
            lastWorn: index % 3 == 0 ? DateTime.now().subtract(Duration(days: index)) : null,
            onTap: () {
              _showOutfitDetails(context, index);
            },
          );
        },
        minItemWidth: 250,
        maxItemWidth: 350,
        itemAspectRatio: 0.8,
      ),
    );
  }

  Widget _buildListView() {
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: 20,
      itemBuilder: (context, index) {
        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: Container(
              width: 60,
              height: 60,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceVariant,
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.style),
            ),
            title: Text('Outfit ${index + 1}'),
            subtitle: Text('4 items • Casual • Summer'),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (index % 5 == 0)
                  const Icon(Icons.favorite, color: Colors.red),
                const SizedBox(width: 8),
                const Icon(Icons.chevron_right),
              ],
            ),
            onTap: () {
              _showOutfitDetails(context, index);
            },
          ),
        );
      },
    );
  }

  Widget _buildCalendarView() {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          // Calendar header
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceVariant,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                IconButton(
                  icon: const Icon(Icons.chevron_left),
                  onPressed: () {
                    // TODO: Previous month
                  },
                ),
                Expanded(
                  child: Text(
                    'February 2024',
                    style: Theme.of(context).textTheme.titleLarge,
                    textAlign: TextAlign.center,
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.chevron_right),
                  onPressed: () {
                    // TODO: Next month
                  },
                ),
              ],
            ),
          ),
          
          const SizedBox(height: 16),
          
          // Calendar grid
          Expanded(
            child: GridView.builder(
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 7,
                mainAxisSpacing: 8,
                crossAxisSpacing: 8,
                childAspectRatio: 1.0,
              ),
              itemCount: 35, // 5 weeks
              itemBuilder: (context, index) {
                final day = index + 1;
                final hasOutfit = day % 3 == 0;
                
                return Container(
                  decoration: BoxDecoration(
                    color: hasOutfit
                        ? Theme.of(context).colorScheme.primaryContainer
                        : Theme.of(context).colorScheme.surface,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: Theme.of(context).colorScheme.outlineVariant,
                    ),
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        day.toString(),
                        style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                          fontWeight: FontWeight.w600,
                          color: hasOutfit
                              ? Theme.of(context).colorScheme.onPrimaryContainer
                              : Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                      if (hasOutfit)
                        Container(
                          margin: const EdgeInsets.only(top: 4),
                          width: 6,
                          height: 6,
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.primary,
                            shape: BoxShape.circle,
                          ),
                        ),
                    ],
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  void _showCreateOutfitDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Create New Outfit'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.auto_fix_high),
                title: const Text('Generate Suggestion'),
                subtitle: const Text('AI-powered outfit recommendation'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Generate outfit suggestion
                },
              ),
              ListTile(
                leading: const Icon(Icons.build),
                title: const Text('Create Manually'),
                subtitle: const Text('Select garments yourself'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Manual outfit creation
                },
              ),
              ListTile(
                leading: const Icon(Icons.camera_alt),
                title: const Text('From Photo'),
                subtitle: const Text('Create from existing photo'),
                onTap: () {
                  Navigator.pop(context);
                  // TODO: Create from photo
                },
              ),
            ],
          ),
        );
      },
    );
  }

  void _showOutfitDetails(BuildContext context, int index) {
    showDialog(
      context: context,
      builder: (context) {
        return Dialog(
          child: Container(
            width: 700,
            height: 600,
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      'Outfit ${index + 1}',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const Spacer(),
                    if (index % 5 == 0)
                      const Icon(Icons.favorite, color: Colors.red),
                    const SizedBox(width: 8),
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
                      // Outfit image
                      Container(
                        width: 300,
                        height: 400,
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.surfaceVariant,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: const Icon(
                          Icons.style,
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
                              'A stylish outfit for any occasion',
                              style: Theme.of(context).textTheme.bodyLarge,
                            ),
                            const SizedBox(height: 16),
                            Text(
                              'Garments (4)',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            const SizedBox(height: 8),
                            // Garment list
                            Expanded(
                              child: ListView.builder(
                                itemCount: 4,
                                itemBuilder: (context, garmentIndex) {
                                  return ListTile(
                                    leading: Container(
                                      width: 40,
                                      height: 40,
                                      decoration: BoxDecoration(
                                        color: Theme.of(context).colorScheme.surfaceVariant,
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                      child: const Icon(Icons.checkroom),
                                    ),
                                    title: Text('Garment ${garmentIndex + 1}'),
                                    subtitle: const Text('Category'),
                                  );
                                },
                              ),
                            ),
                            const SizedBox(height: 16),
                            Row(
                              children: [
                                ElevatedButton(
                                  onPressed: () {
                                    // TODO: Edit outfit
                                  },
                                  child: const Text('Edit'),
                                ),
                                const SizedBox(width: 8),
                                ElevatedButton(
                                  onPressed: () {
                                    // TODO: Wear outfit
                                  },
                                  child: const Text('Wear Today'),
                                ),
                                const SizedBox(width: 8),
                                OutlinedButton(
                                  onPressed: () {
                                    // TODO: Share outfit
                                  },
                                  child: const Text('Share'),
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