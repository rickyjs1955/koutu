import 'package:flutter/material.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

class AppSkeletonLoader extends StatelessWidget {
  final int itemCount;
  final Widget Function(BuildContext, int) itemBuilder;
  final Widget? separator;
  final EdgeInsetsGeometry? padding;
  final ScrollPhysics? physics;
  final bool shrinkWrap;
  final Axis scrollDirection;

  const AppSkeletonLoader({
    super.key,
    this.itemCount = 5,
    required this.itemBuilder,
    this.separator,
    this.padding,
    this.physics,
    this.shrinkWrap = false,
    this.scrollDirection = Axis.vertical,
  });

  @override
  Widget build(BuildContext context) {
    return ListView.separated(
      padding: padding,
      physics: physics ?? const NeverScrollableScrollPhysics(),
      shrinkWrap: shrinkWrap,
      scrollDirection: scrollDirection,
      itemCount: itemCount,
      separatorBuilder: (context, index) =>
          separator ?? const SizedBox(height: AppDimensions.paddingM),
      itemBuilder: itemBuilder,
    );
  }
}

class AppListItemSkeleton extends StatelessWidget {
  final double? height;
  final bool showAvatar;
  final bool showSubtitle;
  final bool showTrailing;

  const AppListItemSkeleton({
    super.key,
    this.height,
    this.showAvatar = true,
    this.showSubtitle = true,
    this.showTrailing = false,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      height: height ?? (showSubtitle ? 72.0 : 56.0),
      padding: const EdgeInsets.symmetric(
        horizontal: AppDimensions.paddingM,
        vertical: AppDimensions.paddingS,
      ),
      child: Row(
        children: [
          if (showAvatar) ...[
            const AppShimmerLoading(
              width: 40,
              height: 40,
              borderRadius: BorderRadius.all(Radius.circular(20)),
            ),
            const SizedBox(width: AppDimensions.paddingM),
          ],
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const AppShimmerLoading(
                  width: double.infinity,
                  height: 16,
                ),
                if (showSubtitle) ...[
                  const SizedBox(height: AppDimensions.paddingXS),
                  const AppShimmerLoading(
                    width: 150,
                    height: 14,
                  ),
                ],
              ],
            ),
          ),
          if (showTrailing) ...[
            const SizedBox(width: AppDimensions.paddingM),
            const AppShimmerLoading(
              width: 60,
              height: 32,
            ),
          ],
        ],
      ),
    );
  }
}

class AppCardSkeleton extends StatelessWidget {
  final double? width;
  final double? height;
  final double imageHeight;
  final bool showTitle;
  final bool showSubtitle;
  final bool showActions;

  const AppCardSkeleton({
    super.key,
    this.width,
    this.height,
    this.imageHeight = 200,
    this.showTitle = true,
    this.showSubtitle = true,
    this.showActions = false,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        borderRadius: AppDimensions.radiusL,
        border: Border.all(color: Colors.grey.withOpacity(0.1)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          AppShimmerLoading(
            width: double.infinity,
            height: imageHeight,
            borderRadius: const BorderRadius.only(
              topLeft: AppDimensions.radiusLValue,
              topRight: AppDimensions.radiusLValue,
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (showTitle) ...[
                  const AppShimmerLoading(
                    width: double.infinity,
                    height: 18,
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                ],
                if (showSubtitle) ...[
                  const AppShimmerLoading(
                    width: 200,
                    height: 14,
                  ),
                  const SizedBox(height: AppDimensions.paddingXS),
                  const AppShimmerLoading(
                    width: 150,
                    height: 14,
                  ),
                ],
                if (showActions) ...[
                  const SizedBox(height: AppDimensions.paddingM),
                  Row(
                    children: [
                      const AppShimmerLoading(
                        width: 80,
                        height: 36,
                      ),
                      const SizedBox(width: AppDimensions.paddingS),
                      const AppShimmerLoading(
                        width: 80,
                        height: 36,
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class AppGridSkeleton extends StatelessWidget {
  final int itemCount;
  final int crossAxisCount;
  final double childAspectRatio;
  final double crossAxisSpacing;
  final double mainAxisSpacing;
  final EdgeInsetsGeometry? padding;
  final Widget Function(BuildContext, int) itemBuilder;

  const AppGridSkeleton({
    super.key,
    this.itemCount = 6,
    this.crossAxisCount = 2,
    this.childAspectRatio = 0.75,
    this.crossAxisSpacing = AppDimensions.paddingM,
    this.mainAxisSpacing = AppDimensions.paddingM,
    this.padding,
    required this.itemBuilder,
  });

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      padding: padding,
      physics: const NeverScrollableScrollPhysics(),
      shrinkWrap: true,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        childAspectRatio: childAspectRatio,
        crossAxisSpacing: crossAxisSpacing,
        mainAxisSpacing: mainAxisSpacing,
      ),
      itemCount: itemCount,
      itemBuilder: itemBuilder,
    );
  }
}