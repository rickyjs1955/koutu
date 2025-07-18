import 'package:flutter/material.dart';

/// Enhanced data table for desktop
class DesktopDataTable extends StatelessWidget {
  final List<DataColumn> columns;
  final List<DataRow> rows;
  final int? sortColumnIndex;
  final bool sortAscending;
  final Function(int, bool)? onSort;

  const DesktopDataTable({
    Key? key,
    required this.columns,
    required this.rows,
    this.sortColumnIndex,
    this.sortAscending = true,
    this.onSort,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      decoration: BoxDecoration(
        color: colorScheme.surface,
        border: Border.all(
          color: colorScheme.outlineVariant,
          width: 1,
        ),
        borderRadius: BorderRadius.circular(8),
      ),
      margin: const EdgeInsets.all(16),
      child: Column(
        children: [
          // Header
          Container(
            height: 48,
            decoration: BoxDecoration(
              color: colorScheme.surfaceVariant.withOpacity(0.5),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
            ),
            child: Row(
              children: [
                // Select all checkbox
                Container(
                  width: 48,
                  child: Checkbox(
                    value: false, // TODO: Implement select all
                    onChanged: (value) {
                      // TODO: Handle select all
                    },
                  ),
                ),
                // Column headers
                Expanded(
                  child: Row(
                    children: columns.asMap().entries.map((entry) {
                      final index = entry.key;
                      final column = entry.value;
                      final isSelected = sortColumnIndex == index;
                      
                      return Expanded(
                        child: InkWell(
                          onTap: () {
                            if (onSort != null) {
                              onSort!(index, isSelected ? !sortAscending : true);
                            }
                          },
                          child: Container(
                            height: 48,
                            padding: const EdgeInsets.symmetric(horizontal: 12),
                            alignment: Alignment.centerLeft,
                            child: Row(
                              children: [
                                Expanded(
                                  child: DefaultTextStyle(
                                    style: theme.textTheme.bodyMedium!.copyWith(
                                      fontWeight: FontWeight.w600,
                                      color: colorScheme.onSurfaceVariant,
                                    ),
                                    child: column.label,
                                  ),
                                ),
                                if (isSelected)
                                  Icon(
                                    sortAscending ? Icons.arrow_upward : Icons.arrow_downward,
                                    size: 16,
                                    color: colorScheme.primary,
                                  ),
                              ],
                            ),
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                ),
              ],
            ),
          ),
          
          // Data rows
          Expanded(
            child: ListView.builder(
              itemCount: rows.length,
              itemBuilder: (context, index) {
                final row = rows[index];
                final isEven = index % 2 == 0;
                
                return Container(
                  height: 56,
                  decoration: BoxDecoration(
                    color: row.selected == true
                        ? colorScheme.primaryContainer.withOpacity(0.3)
                        : isEven
                            ? colorScheme.surface
                            : colorScheme.surfaceVariant.withOpacity(0.3),
                  ),
                  child: InkWell(
                    onTap: () {
                      row.onSelectChanged?.call(!row.selected);
                    },
                    child: Row(
                      children: [
                        // Checkbox
                        Container(
                          width: 48,
                          child: Checkbox(
                            value: row.selected,
                            onChanged: row.onSelectChanged,
                          ),
                        ),
                        // Data cells
                        Expanded(
                          child: Row(
                            children: row.cells.map((cell) {
                              return Expanded(
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 12),
                                  alignment: Alignment.centerLeft,
                                  child: DefaultTextStyle(
                                    style: theme.textTheme.bodyMedium!.copyWith(
                                      color: colorScheme.onSurface,
                                    ),
                                    child: cell.child,
                                  ),
                                ),
                              );
                            }).toList(),
                          ),
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
  }
}