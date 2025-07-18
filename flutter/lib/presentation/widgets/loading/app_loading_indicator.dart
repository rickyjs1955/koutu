import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

enum LoadingIndicatorSize { small, medium, large }

class AppLoadingIndicator extends StatelessWidget {
  final LoadingIndicatorSize size;
  final Color? color;
  final double? strokeWidth;
  final String? message;
  final Widget? child;
  final bool showOverlay;
  final Color? overlayColor;

  const AppLoadingIndicator({
    super.key,
    this.size = LoadingIndicatorSize.medium,
    this.color,
    this.strokeWidth,
    this.message,
    this.child,
    this.showOverlay = false,
    this.overlayColor,
  });

  static const _sizes = {
    LoadingIndicatorSize.small: 16.0,
    LoadingIndicatorSize.medium: 24.0,
    LoadingIndicatorSize.large: 48.0,
  };

  static const _strokeWidths = {
    LoadingIndicatorSize.small: 2.0,
    LoadingIndicatorSize.medium: 3.0,
    LoadingIndicatorSize.large: 4.0,
  };

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final indicatorSize = _sizes[size]!;
    final indicatorStrokeWidth = strokeWidth ?? _strokeWidths[size]!;
    final indicatorColor = color ?? theme.colorScheme.primary;

    final indicator = SizedBox(
      width: indicatorSize,
      height: indicatorSize,
      child: CircularProgressIndicator(
        strokeWidth: indicatorStrokeWidth,
        valueColor: AlwaysStoppedAnimation<Color>(indicatorColor),
      ),
    );

    Widget content = indicator;

    if (message != null) {
      content = Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          indicator,
          const SizedBox(height: AppDimensions.paddingM),
          Text(
            message!,
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      );
    }

    if (child != null) {
      content = Stack(
        alignment: Alignment.center,
        children: [
          child!,
          Container(
            color: overlayColor ?? theme.colorScheme.surface.withOpacity(0.8),
            child: Center(child: content),
          ),
        ],
      );
    }

    if (showOverlay) {
      return Material(
        color: Colors.transparent,
        child: Container(
          color: overlayColor ?? Colors.black.withOpacity(0.3),
          child: Center(child: content),
        ),
      );
    }

    return content;
  }
}

class AppLoadingOverlay extends StatelessWidget {
  final bool isLoading;
  final Widget child;
  final String? message;
  final Color? overlayColor;
  final Color? indicatorColor;

  const AppLoadingOverlay({
    super.key,
    required this.isLoading,
    required this.child,
    this.message,
    this.overlayColor,
    this.indicatorColor,
  });

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        child,
        if (isLoading)
          Positioned.fill(
            child: AppLoadingIndicator(
              showOverlay: true,
              overlayColor: overlayColor,
              color: indicatorColor,
              message: message,
            ),
          ),
      ],
    );
  }
}

class AppShimmerLoading extends StatelessWidget {
  final double width;
  final double height;
  final BorderRadius? borderRadius;
  final EdgeInsetsGeometry? margin;
  final Color? baseColor;
  final Color? highlightColor;

  const AppShimmerLoading({
    super.key,
    required this.width,
    required this.height,
    this.borderRadius,
    this.margin,
    this.baseColor,
    this.highlightColor,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final defaultBaseColor = theme.brightness == Brightness.dark
        ? AppColors.backgroundSecondary
        : AppColors.backgroundTertiary;
    final defaultHighlightColor = theme.brightness == Brightness.dark
        ? AppColors.backgroundTertiary
        : AppColors.backgroundSecondary;

    return Container(
      width: width,
      height: height,
      margin: margin,
      decoration: BoxDecoration(
        color: baseColor ?? defaultBaseColor,
        borderRadius: borderRadius ?? AppDimensions.radiusM,
      ),
    )
        .animate(
          onPlay: (controller) => controller.repeat(),
        )
        .shimmer(
          duration: const Duration(milliseconds: 1200),
          color: highlightColor ?? defaultHighlightColor,
        );
  }
}