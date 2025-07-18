import 'package:flutter/material.dart';

/// Custom app bar for iPad with enhanced functionality
class TabletAppBar extends StatelessWidget implements PreferredSizeWidget {
  final String title;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;
  final double? elevation;
  final Color? backgroundColor;
  final PreferredSizeWidget? bottom;

  const TabletAppBar({
    Key? key,
    required this.title,
    this.actions,
    this.leading,
    this.centerTitle = false,
    this.elevation,
    this.backgroundColor,
    this.bottom,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return AppBar(
      title: Text(
        title,
        style: theme.textTheme.headlineSmall?.copyWith(
          fontWeight: FontWeight.w600,
          color: colorScheme.onSurface,
        ),
      ),
      centerTitle: centerTitle,
      elevation: elevation ?? 0,
      backgroundColor: backgroundColor ?? colorScheme.surface,
      surfaceTintColor: colorScheme.surfaceTint,
      leading: leading,
      actions: actions,
      bottom: bottom,
      toolbarHeight: 64,
      titleSpacing: 24,
      // Add shadow for better visual separation
      shadowColor: colorScheme.shadow.withOpacity(0.1),
    );
  }

  @override
  Size get preferredSize => Size.fromHeight(
    64 + (bottom?.preferredSize.height ?? 0),
  );
}

/// Enhanced app bar with search functionality
class TabletSearchAppBar extends StatefulWidget implements PreferredSizeWidget {
  final String title;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;
  final double? elevation;
  final Color? backgroundColor;
  final PreferredSizeWidget? bottom;
  final ValueChanged<String>? onSearchChanged;
  final VoidCallback? onSearchToggle;
  final bool isSearchActive;

  const TabletSearchAppBar({
    Key? key,
    required this.title,
    this.actions,
    this.leading,
    this.centerTitle = false,
    this.elevation,
    this.backgroundColor,
    this.bottom,
    this.onSearchChanged,
    this.onSearchToggle,
    this.isSearchActive = false,
  }) : super(key: key);

  @override
  State<TabletSearchAppBar> createState() => _TabletSearchAppBarState();

  @override
  Size get preferredSize => Size.fromHeight(
    64 + (bottom?.preferredSize.height ?? 0),
  );
}

class _TabletSearchAppBarState extends State<TabletSearchAppBar> {
  late TextEditingController _searchController;
  late FocusNode _searchFocusNode;

  @override
  void initState() {
    super.initState();
    _searchController = TextEditingController();
    _searchFocusNode = FocusNode();
  }

  @override
  void dispose() {
    _searchController.dispose();
    _searchFocusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return AppBar(
      title: widget.isSearchActive
          ? TextField(
              controller: _searchController,
              focusNode: _searchFocusNode,
              decoration: InputDecoration(
                hintText: 'Search...',
                hintStyle: theme.textTheme.bodyLarge?.copyWith(
                  color: colorScheme.onSurface.withOpacity(0.6),
                ),
                border: InputBorder.none,
                isDense: true,
              ),
              style: theme.textTheme.bodyLarge?.copyWith(
                color: colorScheme.onSurface,
              ),
              onChanged: widget.onSearchChanged,
              autofocus: true,
            )
          : Text(
              widget.title,
              style: theme.textTheme.headlineSmall?.copyWith(
                fontWeight: FontWeight.w600,
                color: colorScheme.onSurface,
              ),
            ),
      centerTitle: widget.centerTitle,
      elevation: widget.elevation ?? 0,
      backgroundColor: widget.backgroundColor ?? colorScheme.surface,
      surfaceTintColor: colorScheme.surfaceTint,
      leading: widget.leading,
      actions: [
        if (widget.isSearchActive)
          IconButton(
            icon: const Icon(Icons.clear),
            onPressed: () {
              _searchController.clear();
              widget.onSearchChanged?.call('');
              widget.onSearchToggle?.call();
            },
            tooltip: 'Clear search',
          )
        else
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: widget.onSearchToggle,
            tooltip: 'Search',
          ),
        if (widget.actions != null) ...widget.actions!,
      ],
      bottom: widget.bottom,
      toolbarHeight: 64,
      titleSpacing: 24,
      shadowColor: colorScheme.shadow.withOpacity(0.1),
    );
  }
}

/// App bar with breadcrumb navigation
class TabletBreadcrumbAppBar extends StatelessWidget implements PreferredSizeWidget {
  final List<BreadcrumbItem> breadcrumbs;
  final List<Widget>? actions;
  final Widget? leading;
  final double? elevation;
  final Color? backgroundColor;
  final PreferredSizeWidget? bottom;

  const TabletBreadcrumbAppBar({
    Key? key,
    required this.breadcrumbs,
    this.actions,
    this.leading,
    this.elevation,
    this.backgroundColor,
    this.bottom,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return AppBar(
      title: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            for (int i = 0; i < breadcrumbs.length; i++) ...[
              GestureDetector(
                onTap: breadcrumbs[i].onTap,
                child: Text(
                  breadcrumbs[i].title,
                  style: theme.textTheme.bodyLarge?.copyWith(
                    color: i == breadcrumbs.length - 1
                        ? colorScheme.onSurface
                        : colorScheme.onSurface.withOpacity(0.6),
                    fontWeight: i == breadcrumbs.length - 1
                        ? FontWeight.w600
                        : FontWeight.w400,
                  ),
                ),
              ),
              if (i < breadcrumbs.length - 1)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: Icon(
                    Icons.chevron_right,
                    size: 16,
                    color: colorScheme.onSurface.withOpacity(0.6),
                  ),
                ),
            ],
          ],
        ),
      ),
      centerTitle: false,
      elevation: elevation ?? 0,
      backgroundColor: backgroundColor ?? colorScheme.surface,
      surfaceTintColor: colorScheme.surfaceTint,
      leading: leading,
      actions: actions,
      bottom: bottom,
      toolbarHeight: 64,
      titleSpacing: 24,
      shadowColor: colorScheme.shadow.withOpacity(0.1),
    );
  }

  @override
  Size get preferredSize => Size.fromHeight(
    64 + (bottom?.preferredSize.height ?? 0),
  );
}

class BreadcrumbItem {
  final String title;
  final VoidCallback? onTap;

  const BreadcrumbItem({
    required this.title,
    this.onTap,
  });
}