import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

enum AppBadgeType { primary, secondary, success, warning, error, info }

enum AppBadgeSize { small, medium, large }

class AppBadge extends StatelessWidget {
  final String? text;
  final Widget? child;
  final AppBadgeType type;
  final AppBadgeSize size;
  final Color? backgroundColor;
  final Color? textColor;
  final BorderRadius? borderRadius;
  final EdgeInsetsGeometry? padding;
  final bool showDot;
  final double? dotSize;

  const AppBadge({
    super.key,
    this.text,
    this.child,
    this.type = AppBadgeType.primary,
    this.size = AppBadgeSize.medium,
    this.backgroundColor,
    this.textColor,
    this.borderRadius,
    this.padding,
    this.showDot = false,
    this.dotSize,
  }) : assert(text != null || child != null || showDot,
            'Either text, child, or showDot must be provided');

  static const _typeColors = {
    AppBadgeType.primary: AppColors.primary,
    AppBadgeType.secondary: AppColors.secondary,
    AppBadgeType.success: AppColors.success,
    AppBadgeType.warning: AppColors.warning,
    AppBadgeType.error: AppColors.error,
    AppBadgeType.info: AppColors.info,
  };

  static const _typeTextColors = {
    AppBadgeType.primary: AppColors.onPrimary,
    AppBadgeType.secondary: AppColors.onSecondary,
    AppBadgeType.success: AppColors.onSuccess,
    AppBadgeType.warning: AppColors.onWarning,
    AppBadgeType.error: AppColors.onError,
    AppBadgeType.info: AppColors.onInfo,
  };

  static const _sizePadding = {
    AppBadgeSize.small: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
    AppBadgeSize.medium: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
    AppBadgeSize.large: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
  };

  static const _sizeTextStyle = {
    AppBadgeSize.small: AppTextStyles.caption,
    AppBadgeSize.medium: AppTextStyles.labelSmall,
    AppBadgeSize.large: AppTextStyles.labelMedium,
  };

  static const _sizeDotSize = {
    AppBadgeSize.small: 6.0,
    AppBadgeSize.medium: 8.0,
    AppBadgeSize.large: 10.0,
  };

  @override
  Widget build(BuildContext context) {
    final badgeBackgroundColor = backgroundColor ?? _typeColors[type]!;
    final badgeTextColor = textColor ?? _typeTextColors[type]!;
    final badgePadding = showDot ? EdgeInsets.zero : (padding ?? _sizePadding[size]!);
    final badgeBorderRadius = borderRadius ?? AppDimensions.radiusS;
    final badgeDotSize = dotSize ?? _sizeDotSize[size]!;

    if (showDot) {
      return Container(
        width: badgeDotSize,
        height: badgeDotSize,
        decoration: BoxDecoration(
          color: badgeBackgroundColor,
          shape: BoxShape.circle,
        ),
      );
    }

    return Container(
      padding: badgePadding,
      decoration: BoxDecoration(
        color: badgeBackgroundColor,
        borderRadius: badgeBorderRadius,
      ),
      child: child ??
          Text(
            text!,
            style: _sizeTextStyle[size]!.copyWith(
              color: badgeTextColor,
              fontWeight: FontWeight.w600,
            ),
          ),
    );
  }
}

class AppBadgeWrapper extends StatelessWidget {
  final Widget child;
  final Widget? badge;
  final String? badgeText;
  final bool showBadge;
  final AppBadgeType badgeType;
  final AppBadgeSize badgeSize;
  final AlignmentGeometry alignment;
  final EdgeInsetsGeometry? badgePadding;
  final bool showDot;

  const AppBadgeWrapper({
    super.key,
    required this.child,
    this.badge,
    this.badgeText,
    this.showBadge = true,
    this.badgeType = AppBadgeType.error,
    this.badgeSize = AppBadgeSize.small,
    this.alignment = Alignment.topRight,
    this.badgePadding,
    this.showDot = false,
  });

  @override
  Widget build(BuildContext context) {
    if (!showBadge && badgeText == null && badge == null) {
      return child;
    }

    return Stack(
      clipBehavior: Clip.none,
      children: [
        child,
        Positioned.fill(
          child: Align(
            alignment: alignment,
            child: FractionalTranslation(
              translation: const Offset(0.3, -0.3),
              child: badge ??
                  AppBadge(
                    text: badgeText,
                    type: badgeType,
                    size: badgeSize,
                    showDot: showDot || badgeText == null,
                  ),
            ),
          ),
        ),
      ],
    );
  }
}