import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

class AppCustomAppBar extends StatelessWidget implements PreferredSizeWidget {
  final String? title;
  final Widget? titleWidget;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;
  final bool showBackButton;
  final VoidCallback? onBackPressed;
  final Color? backgroundColor;
  final Color? foregroundColor;
  final double? elevation;
  final SystemUiOverlayStyle? systemOverlayStyle;
  final PreferredSizeWidget? bottom;
  final double? toolbarHeight;
  final TextStyle? titleTextStyle;
  final double? leadingWidth;
  final bool automaticallyImplyLeading;

  const AppCustomAppBar({
    super.key,
    this.title,
    this.titleWidget,
    this.actions,
    this.leading,
    this.centerTitle = true,
    this.showBackButton = true,
    this.onBackPressed,
    this.backgroundColor,
    this.foregroundColor,
    this.elevation,
    this.systemOverlayStyle,
    this.bottom,
    this.toolbarHeight,
    this.titleTextStyle,
    this.leadingWidth,
    this.automaticallyImplyLeading = true,
  });

  @override
  Size get preferredSize => Size.fromHeight(
        (toolbarHeight ?? kToolbarHeight) + (bottom?.preferredSize.height ?? 0),
      );

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final canPop = Navigator.of(context).canPop();

    return AppBar(
      title: titleWidget ??
          (title != null
              ? Text(
                  title!,
                  style: titleTextStyle ?? AppTextStyles.h3,
                )
              : null),
      centerTitle: centerTitle,
      backgroundColor: backgroundColor ?? theme.scaffoldBackgroundColor,
      foregroundColor: foregroundColor ?? theme.colorScheme.onSurface,
      elevation: elevation ?? 0,
      systemOverlayStyle: systemOverlayStyle ??
          (theme.brightness == Brightness.light
              ? SystemUiOverlayStyle.dark
              : SystemUiOverlayStyle.light),
      leading: leading ??
          (showBackButton && canPop && automaticallyImplyLeading
              ? IconButton(
                  icon: const Icon(Icons.arrow_back_ios),
                  onPressed: onBackPressed ?? () => Navigator.of(context).pop(),
                )
              : null),
      automaticallyImplyLeading: automaticallyImplyLeading,
      actions: actions,
      bottom: bottom,
      toolbarHeight: toolbarHeight,
      leadingWidth: leadingWidth,
    );
  }
}

class AppSliverAppBar extends StatelessWidget {
  final String? title;
  final Widget? titleWidget;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;
  final bool floating;
  final bool pinned;
  final bool snap;
  final double expandedHeight;
  final Widget? flexibleSpace;
  final Color? backgroundColor;
  final Color? foregroundColor;
  final double? elevation;
  final SystemUiOverlayStyle? systemOverlayStyle;
  final VoidCallback? onBackPressed;
  final bool showBackButton;
  final PreferredSizeWidget? bottom;
  final bool automaticallyImplyLeading;
  final double? collapsedHeight;
  final double? toolbarHeight;

  const AppSliverAppBar({
    super.key,
    this.title,
    this.titleWidget,
    this.actions,
    this.leading,
    this.centerTitle = true,
    this.floating = false,
    this.pinned = true,
    this.snap = false,
    this.expandedHeight = 200.0,
    this.flexibleSpace,
    this.backgroundColor,
    this.foregroundColor,
    this.elevation,
    this.systemOverlayStyle,
    this.onBackPressed,
    this.showBackButton = true,
    this.bottom,
    this.automaticallyImplyLeading = true,
    this.collapsedHeight,
    this.toolbarHeight,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final canPop = Navigator.of(context).canPop();

    return SliverAppBar(
      title: titleWidget ??
          (title != null
              ? Text(
                  title!,
                  style: AppTextStyles.h3,
                )
              : null),
      centerTitle: centerTitle,
      floating: floating,
      pinned: pinned,
      snap: snap,
      expandedHeight: expandedHeight,
      collapsedHeight: collapsedHeight,
      toolbarHeight: toolbarHeight,
      flexibleSpace: flexibleSpace,
      backgroundColor: backgroundColor ?? theme.scaffoldBackgroundColor,
      foregroundColor: foregroundColor ?? theme.colorScheme.onSurface,
      elevation: elevation ?? 0,
      systemOverlayStyle: systemOverlayStyle ??
          (theme.brightness == Brightness.light
              ? SystemUiOverlayStyle.dark
              : SystemUiOverlayStyle.light),
      leading: leading ??
          (showBackButton && canPop && automaticallyImplyLeading
              ? IconButton(
                  icon: const Icon(Icons.arrow_back_ios),
                  onPressed: onBackPressed ?? () => Navigator.of(context).pop(),
                )
              : null),
      automaticallyImplyLeading: automaticallyImplyLeading,
      actions: actions,
      bottom: bottom,
    );
  }
}

class AppSearchAppBar extends StatefulWidget implements PreferredSizeWidget {
  final String hint;
  final ValueChanged<String> onChanged;
  final VoidCallback? onClear;
  final VoidCallback? onSubmit;
  final TextEditingController? controller;
  final List<Widget>? actions;
  final bool autofocus;
  final Color? backgroundColor;
  final Color? foregroundColor;
  final Widget? leading;
  final bool showBackButton;
  final VoidCallback? onBackPressed;

  const AppSearchAppBar({
    super.key,
    this.hint = 'Search...',
    required this.onChanged,
    this.onClear,
    this.onSubmit,
    this.controller,
    this.actions,
    this.autofocus = true,
    this.backgroundColor,
    this.foregroundColor,
    this.leading,
    this.showBackButton = true,
    this.onBackPressed,
  });

  @override
  Size get preferredSize => const Size.fromHeight(kToolbarHeight);

  @override
  State<AppSearchAppBar> createState() => _AppSearchAppBarState();
}

class _AppSearchAppBarState extends State<AppSearchAppBar> {
  late TextEditingController _controller;
  bool _showClear = false;

  @override
  void initState() {
    super.initState();
    _controller = widget.controller ?? TextEditingController();
    _controller.addListener(_onTextChanged);
    _showClear = _controller.text.isNotEmpty;
  }

  @override
  void dispose() {
    if (widget.controller == null) {
      _controller.dispose();
    }
    super.dispose();
  }

  void _onTextChanged() {
    setState(() {
      _showClear = _controller.text.isNotEmpty;
    });
    widget.onChanged(_controller.text);
  }

  void _clearSearch() {
    _controller.clear();
    widget.onClear?.call();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final canPop = Navigator.of(context).canPop();

    return AppBar(
      backgroundColor: widget.backgroundColor ?? theme.scaffoldBackgroundColor,
      foregroundColor: widget.foregroundColor ?? theme.colorScheme.onSurface,
      elevation: 0,
      leading: widget.leading ??
          (widget.showBackButton && canPop
              ? IconButton(
                  icon: const Icon(Icons.arrow_back_ios),
                  onPressed:
                      widget.onBackPressed ?? () => Navigator.of(context).pop(),
                )
              : null),
      title: TextField(
        controller: _controller,
        autofocus: widget.autofocus,
        decoration: InputDecoration(
          hintText: widget.hint,
          hintStyle: AppTextStyles.bodyLarge.copyWith(
            color: AppColors.textTertiary,
          ),
          border: InputBorder.none,
          contentPadding: EdgeInsets.zero,
        ),
        style: AppTextStyles.bodyLarge,
        onSubmitted: (_) => widget.onSubmit?.call(),
      ),
      actions: [
        if (_showClear)
          IconButton(
            icon: const Icon(Icons.clear),
            onPressed: _clearSearch,
          ),
        ...?widget.actions,
      ],
    );
  }
}