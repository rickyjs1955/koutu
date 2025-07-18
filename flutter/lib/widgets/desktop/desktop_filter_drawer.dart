import 'package:flutter/material.dart';

/// Desktop filter drawer
class DesktopFilterDrawer extends StatefulWidget {
  final VoidCallback onClose;
  final ValueChanged<Map<String, dynamic>> onFiltersChanged;

  const DesktopFilterDrawer({
    Key? key,
    required this.onClose,
    required this.onFiltersChanged,
  }) : super(key: key);

  @override
  State<DesktopFilterDrawer> createState() => _DesktopFilterDrawerState();
}

class _DesktopFilterDrawerState extends State<DesktopFilterDrawer> {
  final Map<String, dynamic> _filters = {};
  
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      width: 320,
      decoration: BoxDecoration(
        color: colorScheme.surface,
        border: Border(
          left: BorderSide(
            color: colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // Header
          Container(
            height: 64,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            decoration: BoxDecoration(
              color: colorScheme.surfaceVariant.withOpacity(0.5),
              border: Border(
                bottom: BorderSide(
                  color: colorScheme.outlineVariant,
                  width: 1,
                ),
              ),
            ),
            child: Row(
              children: [
                Text(
                  'Filters',
                  style: theme.textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Spacer(),
                TextButton(
                  onPressed: () {
                    setState(() {
                      _filters.clear();
                    });
                    widget.onFiltersChanged(_filters);
                  },
                  child: const Text('Clear All'),
                ),
                IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: widget.onClose,
                ),
              ],
            ),
          ),
          
          // Filter content
          Expanded(
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // Category filter
                _buildFilterSection(
                  title: 'Category',
                  items: ['Tops', 'Bottoms', 'Dresses', 'Outerwear', 'Shoes', 'Accessories'],
                  filterKey: 'category',
                ),
                
                const SizedBox(height: 24),
                
                // Brand filter
                _buildFilterSection(
                  title: 'Brand',
                  items: ['Nike', 'Adidas', 'Zara', 'H&M', 'Uniqlo', 'Other'],
                  filterKey: 'brand',
                ),
                
                const SizedBox(height: 24),
                
                // Size filter
                _buildFilterSection(
                  title: 'Size',
                  items: ['XS', 'S', 'M', 'L', 'XL', 'XXL'],
                  filterKey: 'size',
                ),
                
                const SizedBox(height: 24),
                
                // Color filter
                _buildColorFilterSection(),
                
                const SizedBox(height: 24),
                
                // Usage filter
                _buildFilterSection(
                  title: 'Usage',
                  items: ['Never worn', 'Rarely worn', 'Sometimes worn', 'Often worn'],
                  filterKey: 'usage',
                ),
                
                const SizedBox(height: 24),
                
                // Date range filter
                _buildDateRangeFilter(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterSection({
    required String title,
    required List<String> items,
    required String filterKey,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: items.map((item) {
            final isSelected = _filters[filterKey]?.contains(item) ?? false;
            
            return FilterChip(
              label: Text(item),
              selected: isSelected,
              onSelected: (selected) {
                setState(() {
                  if (_filters[filterKey] == null) {
                    _filters[filterKey] = <String>[];
                  }
                  
                  if (selected) {
                    _filters[filterKey].add(item);
                  } else {
                    _filters[filterKey].remove(item);
                  }
                  
                  if (_filters[filterKey].isEmpty) {
                    _filters.remove(filterKey);
                  }
                });
                widget.onFiltersChanged(_filters);
              },
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildColorFilterSection() {
    final colors = [
      {'name': 'Red', 'color': Colors.red},
      {'name': 'Blue', 'color': Colors.blue},
      {'name': 'Green', 'color': Colors.green},
      {'name': 'Yellow', 'color': Colors.yellow},
      {'name': 'Orange', 'color': Colors.orange},
      {'name': 'Purple', 'color': Colors.purple},
      {'name': 'Pink', 'color': Colors.pink},
      {'name': 'Brown', 'color': Colors.brown},
      {'name': 'Gray', 'color': Colors.grey},
      {'name': 'Black', 'color': Colors.black},
      {'name': 'White', 'color': Colors.white},
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Color',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: colors.map((colorInfo) {
            final colorName = colorInfo['name'] as String;
            final color = colorInfo['color'] as Color;
            final isSelected = _filters['color']?.contains(colorName) ?? false;
            
            return GestureDetector(
              onTap: () {
                setState(() {
                  if (_filters['color'] == null) {
                    _filters['color'] = <String>[];
                  }
                  
                  if (isSelected) {
                    _filters['color'].remove(colorName);
                  } else {
                    _filters['color'].add(colorName);
                  }
                  
                  if (_filters['color'].isEmpty) {
                    _filters.remove('color');
                  }
                });
                widget.onFiltersChanged(_filters);
              },
              child: Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: color,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected
                        ? Theme.of(context).colorScheme.primary
                        : Theme.of(context).colorScheme.outline,
                    width: isSelected ? 3 : 1,
                  ),
                ),
                child: isSelected
                    ? Icon(
                        Icons.check,
                        color: color == Colors.white ? Colors.black : Colors.white,
                        size: 20,
                      )
                    : null,
              ),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildDateRangeFilter() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Date Added',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: OutlinedButton(
                onPressed: () async {
                  final date = await showDatePicker(
                    context: context,
                    initialDate: DateTime.now(),
                    firstDate: DateTime(2020),
                    lastDate: DateTime.now(),
                  );
                  if (date != null) {
                    setState(() {
                      _filters['dateFrom'] = date;
                    });
                    widget.onFiltersChanged(_filters);
                  }
                },
                child: Text(_filters['dateFrom'] != null
                    ? '${_filters['dateFrom'].day}/${_filters['dateFrom'].month}/${_filters['dateFrom'].year}'
                    : 'From'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: OutlinedButton(
                onPressed: () async {
                  final date = await showDatePicker(
                    context: context,
                    initialDate: DateTime.now(),
                    firstDate: DateTime(2020),
                    lastDate: DateTime.now(),
                  );
                  if (date != null) {
                    setState(() {
                      _filters['dateTo'] = date;
                    });
                    widget.onFiltersChanged(_filters);
                  }
                },
                child: Text(_filters['dateTo'] != null
                    ? '${_filters['dateTo'].day}/${_filters['dateTo'].month}/${_filters['dateTo'].year}'
                    : 'To'),
              ),
            ),
          ],
        ),
      ],
    );
  }
}