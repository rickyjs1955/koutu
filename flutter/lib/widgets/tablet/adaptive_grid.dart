import 'package:flutter/material.dart';

/// Adaptive grid that adjusts columns based on screen size and item constraints
class AdaptiveGrid extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final double minItemWidth;
  final double maxItemWidth;
  final double itemAspectRatio;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final EdgeInsets padding;
  final bool shrinkWrap;
  final ScrollPhysics? physics;

  const AdaptiveGrid({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    this.minItemWidth = 200,
    this.maxItemWidth = 300,
    this.itemAspectRatio = 1.0,
    this.mainAxisSpacing = 16,
    this.crossAxisSpacing = 16,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final availableWidth = constraints.maxWidth - padding.horizontal;
        final crossAxisCount = _calculateCrossAxisCount(availableWidth);
        final itemWidth = (availableWidth - (crossAxisCount - 1) * crossAxisSpacing) / crossAxisCount;

        return GridView.builder(
          padding: padding,
          shrinkWrap: shrinkWrap,
          physics: physics,
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: crossAxisCount,
            mainAxisSpacing: mainAxisSpacing,
            crossAxisSpacing: crossAxisSpacing,
            childAspectRatio: itemAspectRatio,
          ),
          itemCount: itemCount,
          itemBuilder: itemBuilder,
        );
      },
    );
  }

  int _calculateCrossAxisCount(double availableWidth) {
    // Calculate the maximum number of columns that can fit
    int maxColumns = (availableWidth / minItemWidth).floor();
    
    // Calculate the minimum number of columns needed to stay within maxItemWidth
    int minColumns = (availableWidth / maxItemWidth).ceil();
    
    // Ensure at least 1 column and use the appropriate count
    return (maxColumns < minColumns) ? minColumns : maxColumns.clamp(1, double.infinity).toInt();
  }
}

/// Staggered grid with variable item heights
class AdaptiveStaggeredGrid extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final double Function(int index) itemHeightBuilder;
  final double minItemWidth;
  final double maxItemWidth;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final EdgeInsets padding;
  final bool shrinkWrap;
  final ScrollPhysics? physics;

  const AdaptiveStaggeredGrid({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    required this.itemHeightBuilder,
    this.minItemWidth = 200,
    this.maxItemWidth = 300,
    this.mainAxisSpacing = 16,
    this.crossAxisSpacing = 16,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final availableWidth = constraints.maxWidth - padding.horizontal;
        final crossAxisCount = _calculateCrossAxisCount(availableWidth);
        final itemWidth = (availableWidth - (crossAxisCount - 1) * crossAxisSpacing) / crossAxisCount;

        return CustomScrollView(
          physics: physics,
          shrinkWrap: shrinkWrap,
          slivers: [
            SliverPadding(
              padding: padding,
              sliver: SliverGrid(
                delegate: SliverChildBuilderDelegate(
                  (context, index) {
                    return SizedBox(
                      height: itemHeightBuilder(index),
                      child: itemBuilder(context, index),
                    );
                  },
                  childCount: itemCount,
                ),
                gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: crossAxisCount,
                  mainAxisSpacing: mainAxisSpacing,
                  crossAxisSpacing: crossAxisSpacing,
                  childAspectRatio: itemWidth / 200, // Default height
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  int _calculateCrossAxisCount(double availableWidth) {
    int maxColumns = (availableWidth / minItemWidth).floor();
    int minColumns = (availableWidth / maxItemWidth).ceil();
    return (maxColumns < minColumns) ? minColumns : maxColumns.clamp(1, double.infinity).toInt();
  }
}

/// Masonry-style grid layout for items with varying heights
class AdaptiveMasonryGrid extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final double minItemWidth;
  final double maxItemWidth;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final EdgeInsets padding;
  final bool shrinkWrap;
  final ScrollPhysics? physics;

  const AdaptiveMasonryGrid({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    this.minItemWidth = 200,
    this.maxItemWidth = 300,
    this.mainAxisSpacing = 16,
    this.crossAxisSpacing = 16,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final availableWidth = constraints.maxWidth - padding.horizontal;
        final crossAxisCount = _calculateCrossAxisCount(availableWidth);
        final itemWidth = (availableWidth - (crossAxisCount - 1) * crossAxisSpacing) / crossAxisCount;

        return MasonryGridView.count(
          crossAxisCount: crossAxisCount,
          mainAxisSpacing: mainAxisSpacing,
          crossAxisSpacing: crossAxisSpacing,
          itemCount: itemCount,
          itemBuilder: itemBuilder,
          padding: padding,
          shrinkWrap: shrinkWrap,
          physics: physics,
        );
      },
    );
  }

  int _calculateCrossAxisCount(double availableWidth) {
    int maxColumns = (availableWidth / minItemWidth).floor();
    int minColumns = (availableWidth / maxItemWidth).ceil();
    return (maxColumns < minColumns) ? minColumns : maxColumns.clamp(1, double.infinity).toInt();
  }
}

/// Simple masonry grid view implementation
class MasonryGridView extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final int crossAxisCount;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final EdgeInsets padding;
  final bool shrinkWrap;
  final ScrollPhysics? physics;

  const MasonryGridView({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    required this.crossAxisCount,
    this.mainAxisSpacing = 8,
    this.crossAxisSpacing = 8,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  const MasonryGridView.count({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    required this.crossAxisCount,
    this.mainAxisSpacing = 8,
    this.crossAxisSpacing = 8,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      physics: physics,
      padding: padding,
      child: LayoutBuilder(
        builder: (context, constraints) {
          final itemWidth = (constraints.maxWidth - (crossAxisCount - 1) * crossAxisSpacing) / crossAxisCount;
          
          return Wrap(
            spacing: crossAxisSpacing,
            runSpacing: mainAxisSpacing,
            children: List.generate(itemCount, (index) {
              return SizedBox(
                width: itemWidth,
                child: itemBuilder(context, index),
              );
            }),
          );
        },
      ),
    );
  }
}

/// Responsive grid with breakpoints
class ResponsiveGrid extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext context, int index) itemBuilder;
  final Map<double, GridConfiguration> breakpoints;
  final double mainAxisSpacing;
  final double crossAxisSpacing;
  final EdgeInsets padding;
  final bool shrinkWrap;
  final ScrollPhysics? physics;

  const ResponsiveGrid({
    Key? key,
    required this.itemCount,
    required this.itemBuilder,
    required this.breakpoints,
    this.mainAxisSpacing = 16,
    this.crossAxisSpacing = 16,
    this.padding = EdgeInsets.zero,
    this.shrinkWrap = false,
    this.physics,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final config = _getConfigForWidth(constraints.maxWidth);
        
        return GridView.builder(
          padding: padding,
          shrinkWrap: shrinkWrap,
          physics: physics,
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: config.crossAxisCount,
            mainAxisSpacing: mainAxisSpacing,
            crossAxisSpacing: crossAxisSpacing,
            childAspectRatio: config.childAspectRatio,
          ),
          itemCount: itemCount,
          itemBuilder: itemBuilder,
        );
      },
    );
  }

  GridConfiguration _getConfigForWidth(double width) {
    GridConfiguration? config;
    double? matchedBreakpoint;

    for (final entry in breakpoints.entries) {
      if (width >= entry.key) {
        if (matchedBreakpoint == null || entry.key > matchedBreakpoint) {
          matchedBreakpoint = entry.key;
          config = entry.value;
        }
      }
    }

    return config ?? breakpoints.values.first;
  }
}

class GridConfiguration {
  final int crossAxisCount;
  final double childAspectRatio;

  const GridConfiguration({
    required this.crossAxisCount,
    this.childAspectRatio = 1.0,
  });
}

/// Predefined responsive breakpoints for common use cases
class ResponsiveBreakpoints {
  static const double mobile = 0;
  static const double tablet = 600;
  static const double desktop = 1200;
  static const double largeDesktop = 1920;

  static Map<double, GridConfiguration> get defaultBreakpoints => {
    mobile: const GridConfiguration(crossAxisCount: 2, childAspectRatio: 0.8),
    tablet: const GridConfiguration(crossAxisCount: 3, childAspectRatio: 0.9),
    desktop: const GridConfiguration(crossAxisCount: 4, childAspectRatio: 1.0),
    largeDesktop: const GridConfiguration(crossAxisCount: 6, childAspectRatio: 1.0),
  };

  static Map<double, GridConfiguration> get cardBreakpoints => {
    mobile: const GridConfiguration(crossAxisCount: 1, childAspectRatio: 2.0),
    tablet: const GridConfiguration(crossAxisCount: 2, childAspectRatio: 1.5),
    desktop: const GridConfiguration(crossAxisCount: 3, childAspectRatio: 1.2),
    largeDesktop: const GridConfiguration(crossAxisCount: 4, childAspectRatio: 1.2),
  };

  static Map<double, GridConfiguration> get galleryBreakpoints => {
    mobile: const GridConfiguration(crossAxisCount: 2, childAspectRatio: 1.0),
    tablet: const GridConfiguration(crossAxisCount: 4, childAspectRatio: 1.0),
    desktop: const GridConfiguration(crossAxisCount: 6, childAspectRatio: 1.0),
    largeDesktop: const GridConfiguration(crossAxisCount: 8, childAspectRatio: 1.0),
  };
}