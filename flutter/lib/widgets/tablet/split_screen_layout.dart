import 'package:flutter/material.dart';

/// Split screen layout widget for iPad multitasking
class SplitScreenLayout extends StatefulWidget {
  final Widget primaryScreen;
  final Widget secondaryScreen;
  final bool isVerticalSplit;
  final double splitRatio;
  final ValueChanged<double>? onSplitRatioChanged;
  final double minPrimaryRatio;
  final double maxPrimaryRatio;
  final bool showDivider;
  final Color? dividerColor;
  final double dividerWidth;

  const SplitScreenLayout({
    Key? key,
    required this.primaryScreen,
    required this.secondaryScreen,
    this.isVerticalSplit = false,
    this.splitRatio = 0.5,
    this.onSplitRatioChanged,
    this.minPrimaryRatio = 0.2,
    this.maxPrimaryRatio = 0.8,
    this.showDivider = true,
    this.dividerColor,
    this.dividerWidth = 1.0,
  }) : super(key: key);

  @override
  State<SplitScreenLayout> createState() => _SplitScreenLayoutState();
}

class _SplitScreenLayoutState extends State<SplitScreenLayout> {
  late double _currentRatio;
  bool _isDragging = false;

  @override
  void initState() {
    super.initState();
    _currentRatio = widget.splitRatio;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return LayoutBuilder(
      builder: (context, constraints) {
        final totalSize = widget.isVerticalSplit
            ? constraints.maxHeight
            : constraints.maxWidth;
        final primarySize = totalSize * _currentRatio;
        final secondarySize = totalSize * (1 - _currentRatio);

        return widget.isVerticalSplit
            ? _buildVerticalSplit(primarySize, secondarySize, colorScheme)
            : _buildHorizontalSplit(primarySize, secondarySize, colorScheme);
      },
    );
  }

  Widget _buildHorizontalSplit(double primarySize, double secondarySize, ColorScheme colorScheme) {
    return Row(
      children: [
        // Primary screen
        SizedBox(
          width: primarySize,
          child: widget.primaryScreen,
        ),
        
        // Divider
        if (widget.showDivider)
          _buildDivider(colorScheme, isVertical: true),
        
        // Secondary screen
        SizedBox(
          width: secondarySize,
          child: widget.secondaryScreen,
        ),
      ],
    );
  }

  Widget _buildVerticalSplit(double primarySize, double secondarySize, ColorScheme colorScheme) {
    return Column(
      children: [
        // Primary screen
        SizedBox(
          height: primarySize,
          child: widget.primaryScreen,
        ),
        
        // Divider
        if (widget.showDivider)
          _buildDivider(colorScheme, isVertical: false),
        
        // Secondary screen
        SizedBox(
          height: secondarySize,
          child: widget.secondaryScreen,
        ),
      ],
    );
  }

  Widget _buildDivider(ColorScheme colorScheme, {required bool isVertical}) {
    return GestureDetector(
      onPanStart: (details) {
        _isDragging = true;
      },
      onPanUpdate: (details) {
        if (!_isDragging) return;

        setState(() {
          double newRatio;
          if (isVertical) {
            newRatio = _currentRatio + (details.delta.dx / context.size!.width);
          } else {
            newRatio = _currentRatio + (details.delta.dy / context.size!.height);
          }
          
          _currentRatio = newRatio.clamp(widget.minPrimaryRatio, widget.maxPrimaryRatio);
          widget.onSplitRatioChanged?.call(_currentRatio);
        });
      },
      onPanEnd: (details) {
        _isDragging = false;
      },
      child: MouseRegion(
        cursor: isVertical ? SystemMouseCursors.resizeColumn : SystemMouseCursors.resizeRow,
        child: Container(
          width: isVertical ? 8 : double.infinity,
          height: isVertical ? double.infinity : 8,
          color: Colors.transparent,
          child: Center(
            child: Container(
              width: isVertical ? widget.dividerWidth : double.infinity,
              height: isVertical ? double.infinity : widget.dividerWidth,
              color: widget.dividerColor ?? colorScheme.outlineVariant,
            ),
          ),
        ),
      ),
    );
  }
}

/// Split screen container with animated transitions
class AnimatedSplitScreenLayout extends StatefulWidget {
  final Widget primaryScreen;
  final Widget secondaryScreen;
  final bool isVerticalSplit;
  final double splitRatio;
  final ValueChanged<double>? onSplitRatioChanged;
  final Duration animationDuration;
  final Curve animationCurve;
  final bool showDivider;
  final Color? dividerColor;
  final double dividerWidth;

  const AnimatedSplitScreenLayout({
    Key? key,
    required this.primaryScreen,
    required this.secondaryScreen,
    this.isVerticalSplit = false,
    this.splitRatio = 0.5,
    this.onSplitRatioChanged,
    this.animationDuration = const Duration(milliseconds: 300),
    this.animationCurve = Curves.easeInOut,
    this.showDivider = true,
    this.dividerColor,
    this.dividerWidth = 1.0,
  }) : super(key: key);

  @override
  State<AnimatedSplitScreenLayout> createState() => _AnimatedSplitScreenLayoutState();
}

class _AnimatedSplitScreenLayoutState extends State<AnimatedSplitScreenLayout>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _animation;
  late double _currentRatio;

  @override
  void initState() {
    super.initState();
    _currentRatio = widget.splitRatio;
    _animationController = AnimationController(
      duration: widget.animationDuration,
      vsync: this,
    );
    _animation = Tween<double>(
      begin: _currentRatio,
      end: _currentRatio,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: widget.animationCurve,
    ));
  }

  @override
  void didUpdateWidget(AnimatedSplitScreenLayout oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.splitRatio != widget.splitRatio) {
      _animateToRatio(widget.splitRatio);
    }
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }

  void _animateToRatio(double newRatio) {
    _animation = Tween<double>(
      begin: _currentRatio,
      end: newRatio,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: widget.animationCurve,
    ));
    
    _animationController.forward(from: 0);
    _currentRatio = newRatio;
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        return SplitScreenLayout(
          primaryScreen: widget.primaryScreen,
          secondaryScreen: widget.secondaryScreen,
          isVerticalSplit: widget.isVerticalSplit,
          splitRatio: _animation.value,
          onSplitRatioChanged: (ratio) {
            _currentRatio = ratio;
            widget.onSplitRatioChanged?.call(ratio);
          },
          showDivider: widget.showDivider,
          dividerColor: widget.dividerColor,
          dividerWidth: widget.dividerWidth,
        );
      },
    );
  }
}

/// Preset split screen layouts for common use cases
class SplitScreenPresets {
  static const double primaryDominant = 0.7;
  static const double secondaryDominant = 0.3;
  static const double equal = 0.5;
  static const double primaryFocused = 0.8;
  static const double secondaryFocused = 0.2;

  static Widget masterDetail({
    required Widget master,
    required Widget detail,
    bool isVerticalSplit = false,
    double splitRatio = primaryDominant,
    ValueChanged<double>? onSplitRatioChanged,
  }) {
    return SplitScreenLayout(
      primaryScreen: master,
      secondaryScreen: detail,
      isVerticalSplit: isVerticalSplit,
      splitRatio: splitRatio,
      onSplitRatioChanged: onSplitRatioChanged,
      minPrimaryRatio: 0.3,
      maxPrimaryRatio: 0.8,
    );
  }

  static Widget sidebarContent({
    required Widget sidebar,
    required Widget content,
    bool isVerticalSplit = false,
    double splitRatio = secondaryDominant,
    ValueChanged<double>? onSplitRatioChanged,
  }) {
    return SplitScreenLayout(
      primaryScreen: sidebar,
      secondaryScreen: content,
      isVerticalSplit: isVerticalSplit,
      splitRatio: splitRatio,
      onSplitRatioChanged: onSplitRatioChanged,
      minPrimaryRatio: 0.2,
      maxPrimaryRatio: 0.5,
    );
  }

  static Widget comparison({
    required Widget left,
    required Widget right,
    bool isVerticalSplit = false,
    double splitRatio = equal,
    ValueChanged<double>? onSplitRatioChanged,
  }) {
    return SplitScreenLayout(
      primaryScreen: left,
      secondaryScreen: right,
      isVerticalSplit: isVerticalSplit,
      splitRatio: splitRatio,
      onSplitRatioChanged: onSplitRatioChanged,
      minPrimaryRatio: 0.2,
      maxPrimaryRatio: 0.8,
    );
  }
}