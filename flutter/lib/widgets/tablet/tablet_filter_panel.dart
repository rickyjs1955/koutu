import 'package:flutter/material.dart';

/// Filter panel for tablet interface
class TabletFilterPanel extends StatefulWidget {
  final Set<String> selectedFilters;
  final ValueChanged<Set<String>> onFiltersChanged;
  final VoidCallback? onClose;

  const TabletFilterPanel({
    Key? key,
    required this.selectedFilters,
    required this.onFiltersChanged,
    this.onClose,
  }) : super(key: key);

  @override
  State<TabletFilterPanel> createState() => _TabletFilterPanelState();
}

class _TabletFilterPanelState extends State<TabletFilterPanel> {
  late Set<String> _selectedFilters;

  @override
  void initState() {
    super.initState();
    _selectedFilters = Set.from(widget.selectedFilters);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      width: 280,
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
        crossAxisAlignment: CrossAxisAlignment.start,
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
                if (_selectedFilters.isNotEmpty)
                  TextButton(
                    onPressed: () {
                      setState(() {
                        _selectedFilters.clear();
                      });
                      widget.onFiltersChanged(_selectedFilters);
                    },
                    child: const Text('Clear All'),
                  ),
                if (widget.onClose != null)
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: widget.onClose,
                  ),
              ],
            ),
          ),

          // Filter content
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Category filter
                  _buildFilterSection(
                    title: 'Category',
                    items: [
                      'Tops',
                      'Bottoms',
                      'Dresses',
                      'Outerwear',
                      'Shoes',
                      'Accessories',
                    ],
                    icon: Icons.category,
                  ),
                  
                  const SizedBox(height: 24),
                  
                  // Color filter
                  _buildColorFilterSection(),
                  
                  const SizedBox(height: 24),
                  
                  // Size filter
                  _buildFilterSection(
                    title: 'Size',
                    items: [
                      'XS',
                      'S',
                      'M',
                      'L',
                      'XL',
                      'XXL',
                    ],
                    icon: Icons.straighten,
                  ),
                  
                  const SizedBox(height: 24),
                  
                  // Brand filter
                  _buildFilterSection(
                    title: 'Brand',
                    items: [
                      'Nike',
                      'Adidas',
                      'Zara',
                      'H&M',
                      'Uniqlo',
                      'Other',
                    ],
                    icon: Icons.local_offer,
                  ),
                  
                  const SizedBox(height: 24),
                  
                  // Season filter
                  _buildFilterSection(
                    title: 'Season',
                    items: [
                      'Spring',
                      'Summer',
                      'Fall',
                      'Winter',
                      'All Season',
                    ],
                    icon: Icons.wb_sunny,
                  ),
                  
                  const SizedBox(height: 24),
                  
                  // Occasion filter
                  _buildFilterSection(
                    title: 'Occasion',
                    items: [
                      'Casual',
                      'Work',
                      'Formal',
                      'Party',
                      'Sport',
                      'Sleep',
                    ],
                    icon: Icons.event,
                  ),
                  
                  const SizedBox(height: 24),
                  
                  // Condition filter
                  _buildFilterSection(
                    title: 'Condition',
                    items: [
                      'New',
                      'Like New',
                      'Good',
                      'Fair',
                      'Needs Repair',
                    ],
                    icon: Icons.star,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterSection({
    required String title,
    required List<String> items,
    required IconData icon,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              icon,
              size: 20,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(width: 8),
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: items.map((item) {
            final filterKey = '${title.toLowerCase()}_${item.toLowerCase()}';
            final isSelected = _selectedFilters.contains(filterKey);
            
            return FilterChip(
              label: Text(item),
              selected: isSelected,
              onSelected: (selected) {
                setState(() {
                  if (selected) {
                    _selectedFilters.add(filterKey);
                  } else {
                    _selectedFilters.remove(filterKey);
                  }
                });
                widget.onFiltersChanged(_selectedFilters);
              },
              selectedColor: Theme.of(context).colorScheme.primaryContainer,
              checkmarkColor: Theme.of(context).colorScheme.onPrimaryContainer,
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
        Row(
          children: [
            Icon(
              Icons.palette,
              size: 20,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(width: 8),
            Text(
              'Color',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: colors.map((colorInfo) {
            final filterKey = 'color_${colorInfo['name'].toString().toLowerCase()}';
            final isSelected = _selectedFilters.contains(filterKey);
            
            return GestureDetector(
              onTap: () {
                setState(() {
                  if (isSelected) {
                    _selectedFilters.remove(filterKey);
                  } else {
                    _selectedFilters.add(filterKey);
                  }
                });
                widget.onFiltersChanged(_selectedFilters);
              },
              child: Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: colorInfo['color'] as Color,
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
                        color: (colorInfo['color'] as Color) == Colors.white
                            ? Colors.black
                            : Colors.white,
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
}

/// Quick filter bar for common filters
class QuickFilterBar extends StatelessWidget {
  final Set<String> selectedFilters;
  final ValueChanged<Set<String>> onFiltersChanged;

  const QuickFilterBar({
    Key? key,
    required this.selectedFilters,
    required this.onFiltersChanged,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final quickFilters = [
      {'key': 'favorites', 'label': 'Favorites', 'icon': Icons.favorite},
      {'key': 'new', 'label': 'New', 'icon': Icons.new_releases},
      {'key': 'formal', 'label': 'Formal', 'icon': Icons.business_center},
      {'key': 'casual', 'label': 'Casual', 'icon': Icons.weekend},
      {'key': 'winter', 'label': 'Winter', 'icon': Icons.ac_unit},
      {'key': 'summer', 'label': 'Summer', 'icon': Icons.wb_sunny},
    ];

    return Container(
      height: 56,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        itemCount: quickFilters.length,
        separatorBuilder: (context, index) => const SizedBox(width: 8),
        itemBuilder: (context, index) {
          final filter = quickFilters[index];
          final isSelected = selectedFilters.contains(filter['key']);
          
          return FilterChip(
            label: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  filter['icon'] as IconData,
                  size: 16,
                ),
                const SizedBox(width: 4),
                Text(filter['label'] as String),
              ],
            ),
            selected: isSelected,
            onSelected: (selected) {
              final newFilters = Set<String>.from(selectedFilters);
              if (selected) {
                newFilters.add(filter['key'] as String);
              } else {
                newFilters.remove(filter['key'] as String);
              }
              onFiltersChanged(newFilters);
            },
            selectedColor: Theme.of(context).colorScheme.primaryContainer,
            checkmarkColor: Theme.of(context).colorScheme.onPrimaryContainer,
          );
        },
      ),
    );
  }
}