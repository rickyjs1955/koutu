import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/widgets/desktop/desktop_toolbar.dart';
import 'package:koutu/widgets/desktop/desktop_data_table.dart';
import 'package:koutu/widgets/desktop/desktop_filter_drawer.dart';

/// Desktop wardrobe management screen
class DesktopWardrobeScreen extends ConsumerStatefulWidget {
  const DesktopWardrobeScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<DesktopWardrobeScreen> createState() => _DesktopWardrobeScreenState();
}

class _DesktopWardrobeScreenState extends ConsumerState<DesktopWardrobeScreen> {
  bool _isFilterDrawerOpen = false;
  String _searchQuery = '';
  String _selectedView = 'table'; // table, grid, list
  Set<String> _selectedItems = {};
  String _sortBy = 'name';
  bool _sortAscending = true;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      body: Column(
        children: [
          // Toolbar
          DesktopToolbar(
            title: 'Wardrobe Management',
            searchQuery: _searchQuery,
            onSearchChanged: (query) {
              setState(() {
                _searchQuery = query;
              });
            },
            selectedView: _selectedView,
            onViewChanged: (view) {
              setState(() {
                _selectedView = view;
              });
            },
            onFilterToggle: () {
              setState(() {
                _isFilterDrawerOpen = !_isFilterDrawerOpen;
              });
            },
            isFilterOpen: _isFilterDrawerOpen,
            selectedItemsCount: _selectedItems.length,
            onBulkAction: (action) {
              _handleBulkAction(action);
            },
          ),
          
          // Main content
          Expanded(
            child: Row(
              children: [
                // Data view
                Expanded(
                  child: _buildDataView(),
                ),
                
                // Filter drawer
                if (_isFilterDrawerOpen)
                  DesktopFilterDrawer(
                    onClose: () {
                      setState(() {
                        _isFilterDrawerOpen = false;
                      });
                    },
                    onFiltersChanged: (filters) {
                      // TODO: Apply filters
                    },
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDataView() {
    switch (_selectedView) {
      case 'table':
        return _buildTableView();
      case 'grid':
        return _buildGridView();
      case 'list':
        return _buildListView();
      default:
        return _buildTableView();
    }
  }

  Widget _buildTableView() {
    return DesktopDataTable(
      columns: const [
        DataColumn(label: Text('Name')),
        DataColumn(label: Text('Category')),
        DataColumn(label: Text('Brand')),
        DataColumn(label: Text('Size')),
        DataColumn(label: Text('Color')),
        DataColumn(label: Text('Times Worn')),
        DataColumn(label: Text('Last Worn')),
        DataColumn(label: Text('Actions')),
      ],
      rows: List.generate(50, (index) {
        final isSelected = _selectedItems.contains('item_$index');
        
        return DataRow(
          selected: isSelected,
          onSelectChanged: (selected) {
            setState(() {
              if (selected == true) {
                _selectedItems.add('item_$index');
              } else {
                _selectedItems.remove('item_$index');
              }
            });
          },
          cells: [
            DataCell(
              Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surfaceVariant,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: const Icon(Icons.checkroom, size: 16),
                  ),
                  const SizedBox(width: 8),
                  Text('Garment ${index + 1}'),
                ],
              ),
            ),
            DataCell(Text(_getCategory(index))),
            DataCell(Text(_getBrand(index))),
            DataCell(Text(_getSize(index))),
            DataCell(
              Row(
                children: [
                  Container(
                    width: 16,
                    height: 16,
                    decoration: BoxDecoration(
                      color: _getColor(index),
                      shape: BoxShape.circle,
                      border: Border.all(color: Colors.grey),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(_getColorName(index)),
                ],
              ),
            ),
            DataCell(Text('${index + 1}')),
            DataCell(Text(_getLastWorn(index))),
            DataCell(
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    icon: const Icon(Icons.edit),
                    onPressed: () {
                      _editItem(index);
                    },
                    iconSize: 18,
                  ),
                  IconButton(
                    icon: const Icon(Icons.delete),
                    onPressed: () {
                      _deleteItem(index);
                    },
                    iconSize: 18,
                  ),
                ],
              ),
            ),
          ],
        );
      }),
      sortColumnIndex: _getSortColumnIndex(),
      sortAscending: _sortAscending,
      onSort: (columnIndex, ascending) {
        setState(() {
          _sortBy = _getColumnName(columnIndex);
          _sortAscending = ascending;
        });
      },
    );
  }

  Widget _buildGridView() {
    return GridView.builder(
      padding: const EdgeInsets.all(16),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 4,
        mainAxisSpacing: 16,
        crossAxisSpacing: 16,
        childAspectRatio: 0.8,
      ),
      itemCount: 50,
      itemBuilder: (context, index) {
        final isSelected = _selectedItems.contains('item_$index');
        
        return Card(
          elevation: isSelected ? 4 : 1,
          child: InkWell(
            onTap: () {
              setState(() {
                if (isSelected) {
                  _selectedItems.remove('item_$index');
                } else {
                  _selectedItems.add('item_$index');
                }
              });
            },
            child: Column(
              children: [
                Expanded(
                  child: Container(
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surfaceVariant,
                      borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                    ),
                    child: const Center(
                      child: Icon(Icons.checkroom, size: 48),
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(8),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Garment ${index + 1}',
                        style: Theme.of(context).textTheme.titleSmall,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        _getCategory(index),
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                      Text(
                        _getBrand(index),
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
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

  Widget _buildListView() {
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: 50,
      itemBuilder: (context, index) {
        final isSelected = _selectedItems.contains('item_$index');
        
        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: CheckboxListTile(
            value: isSelected,
            onChanged: (selected) {
              setState(() {
                if (selected == true) {
                  _selectedItems.add('item_$index');
                } else {
                  _selectedItems.remove('item_$index');
                }
              });
            },
            title: Text('Garment ${index + 1}'),
            subtitle: Text('${_getCategory(index)} • ${_getBrand(index)} • ${_getSize(index)}'),
            leading: Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceVariant,
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.checkroom),
            ),
            trailing: PopupMenuButton<String>(
              onSelected: (value) {
                switch (value) {
                  case 'edit':
                    _editItem(index);
                    break;
                  case 'delete':
                    _deleteItem(index);
                    break;
                }
              },
              itemBuilder: (context) => [
                const PopupMenuItem(
                  value: 'edit',
                  child: ListTile(
                    leading: Icon(Icons.edit),
                    title: Text('Edit'),
                    dense: true,
                  ),
                ),
                const PopupMenuItem(
                  value: 'delete',
                  child: ListTile(
                    leading: Icon(Icons.delete),
                    title: Text('Delete'),
                    dense: true,
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  void _handleBulkAction(String action) {
    switch (action) {
      case 'delete':
        // TODO: Bulk delete
        break;
      case 'export':
        // TODO: Bulk export
        break;
      case 'edit':
        // TODO: Bulk edit
        break;
    }
  }

  void _editItem(int index) {
    // TODO: Edit item
  }

  void _deleteItem(int index) {
    // TODO: Delete item
  }

  String _getCategory(int index) {
    final categories = ['Tops', 'Bottoms', 'Dresses', 'Outerwear', 'Shoes', 'Accessories'];
    return categories[index % categories.length];
  }

  String _getBrand(int index) {
    final brands = ['Nike', 'Adidas', 'Zara', 'H&M', 'Uniqlo', 'Other'];
    return brands[index % brands.length];
  }

  String _getSize(int index) {
    final sizes = ['XS', 'S', 'M', 'L', 'XL', 'XXL'];
    return sizes[index % sizes.length];
  }

  Color _getColor(int index) {
    final colors = [Colors.red, Colors.blue, Colors.green, Colors.yellow, Colors.purple, Colors.orange];
    return colors[index % colors.length];
  }

  String _getColorName(int index) {
    final colors = ['Red', 'Blue', 'Green', 'Yellow', 'Purple', 'Orange'];
    return colors[index % colors.length];
  }

  String _getLastWorn(int index) {
    final days = ['Today', '1 day ago', '3 days ago', '1 week ago', '2 weeks ago', '1 month ago'];
    return days[index % days.length];
  }

  int _getSortColumnIndex() {
    switch (_sortBy) {
      case 'name':
        return 0;
      case 'category':
        return 1;
      case 'brand':
        return 2;
      case 'size':
        return 3;
      case 'color':
        return 4;
      case 'times_worn':
        return 5;
      case 'last_worn':
        return 6;
      default:
        return 0;
    }
  }

  String _getColumnName(int index) {
    switch (index) {
      case 0:
        return 'name';
      case 1:
        return 'category';
      case 2:
        return 'brand';
      case 3:
        return 'size';
      case 4:
        return 'color';
      case 5:
        return 'times_worn';
      case 6:
        return 'last_worn';
      default:
        return 'name';
    }
  }
}