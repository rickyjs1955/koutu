import 'package:flutter/material.dart';

/// Desktop toolbar with search and actions
class DesktopToolbar extends StatelessWidget {
  final String title;
  final String searchQuery;
  final ValueChanged<String> onSearchChanged;
  final String selectedView;
  final ValueChanged<String> onViewChanged;
  final VoidCallback onFilterToggle;
  final bool isFilterOpen;
  final int selectedItemsCount;
  final ValueChanged<String> onBulkAction;

  const DesktopToolbar({
    Key? key,
    required this.title,
    required this.searchQuery,
    required this.onSearchChanged,
    required this.selectedView,
    required this.onViewChanged,
    required this.onFilterToggle,
    required this.isFilterOpen,
    required this.selectedItemsCount,
    required this.onBulkAction,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      height: 64,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: colorScheme.surface,
        border: Border(
          bottom: BorderSide(
            color: colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Title
          Text(
            title,
            style: theme.textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          
          const SizedBox(width: 24),
          
          // Search
          Expanded(
            flex: 2,
            child: TextField(
              decoration: InputDecoration(
                hintText: 'Search garments...',
                prefixIcon: const Icon(Icons.search),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                isDense: true,
              ),
              onChanged: onSearchChanged,
            ),
          ),
          
          const SizedBox(width: 16),
          
          // Bulk actions
          if (selectedItemsCount > 0) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Text(
                '$selectedItemsCount selected',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: colorScheme.onPrimaryContainer,
                ),
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.edit),
              onPressed: () => onBulkAction('edit'),
              tooltip: 'Edit selected',
            ),
            IconButton(
              icon: const Icon(Icons.delete),
              onPressed: () => onBulkAction('delete'),
              tooltip: 'Delete selected',
            ),
            IconButton(
              icon: const Icon(Icons.file_download),
              onPressed: () => onBulkAction('export'),
              tooltip: 'Export selected',
            ),
            const SizedBox(width: 16),
          ],
          
          // View controls
          SegmentedButton<String>(
            segments: const [
              ButtonSegment(
                value: 'table',
                icon: Icon(Icons.table_rows),
                label: Text('Table'),
              ),
              ButtonSegment(
                value: 'grid',
                icon: Icon(Icons.view_module),
                label: Text('Grid'),
              ),
              ButtonSegment(
                value: 'list',
                icon: Icon(Icons.view_list),
                label: Text('List'),
              ),
            ],
            selected: {selectedView},
            onSelectionChanged: (selection) {
              onViewChanged(selection.first);
            },
          ),
          
          const SizedBox(width: 16),
          
          // Filter toggle
          IconButton(
            icon: Icon(
              isFilterOpen ? Icons.filter_list : Icons.filter_list_outlined,
              color: isFilterOpen ? colorScheme.primary : null,
            ),
            onPressed: onFilterToggle,
            tooltip: 'Filters',
          ),
          
          // More actions
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_vert),
            onSelected: (value) {
              switch (value) {
                case 'import':
                  // TODO: Import
                  break;
                case 'export_all':
                  // TODO: Export all
                  break;
                case 'settings':
                  // TODO: Settings
                  break;
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'import',
                child: ListTile(
                  leading: Icon(Icons.file_upload),
                  title: Text('Import'),
                  dense: true,
                ),
              ),
              const PopupMenuItem(
                value: 'export_all',
                child: ListTile(
                  leading: Icon(Icons.file_download),
                  title: Text('Export All'),
                  dense: true,
                ),
              ),
              const PopupMenuItem(
                value: 'settings',
                child: ListTile(
                  leading: Icon(Icons.settings),
                  title: Text('Settings'),
                  dense: true,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}