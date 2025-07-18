import 'package:flutter/material.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';
import 'package:koutu/presentation/widgets/common/loading_indicator.dart';

enum AppButtonType {
  primary,
  secondary,
  outline,
  text,
  danger,
}

enum AppButtonSize {
  small,
  medium,
  large,
}

class AppButton extends StatelessWidget {
  final String text;
  final VoidCallback? onPressed;
  final AppButtonType type;
  final AppButtonSize size;
  final bool isLoading;
  final bool isFullWidth;
  final IconData? icon;
  final IconData? suffixIcon;
  final EdgeInsetsGeometry? padding;

  const AppButton({
    super.key,
    required this.text,
    required this.onPressed,
    this.type = AppButtonType.primary,
    this.size = AppButtonSize.large,
    this.isLoading = false,
    this.isFullWidth = true,
    this.icon,
    this.suffixIcon,
    this.padding,
  });

  @override
  Widget build(BuildContext context) {
    final buttonChild = _buildButtonChild();
    final buttonStyle = _getButtonStyle();
    final minimumSize = _getMinimumSize();

    Widget button;

    switch (type) {
      case AppButtonType.primary:
      case AppButtonType.danger:
        button = ElevatedButton(
          onPressed: isLoading ? null : onPressed,
          style: buttonStyle.copyWith(
            minimumSize: MaterialStateProperty.all(minimumSize),
          ),
          child: buttonChild,
        );
        break;
      case AppButtonType.secondary:
      case AppButtonType.outline:
        button = OutlinedButton(
          onPressed: isLoading ? null : onPressed,
          style: buttonStyle.copyWith(
            minimumSize: MaterialStateProperty.all(minimumSize),
          ),
          child: buttonChild,
        );
        break;
      case AppButtonType.text:
        button = TextButton(
          onPressed: isLoading ? null : onPressed,
          style: buttonStyle.copyWith(
            minimumSize: MaterialStateProperty.all(minimumSize),
          ),
          child: buttonChild,
        );
        break;
    }

    if (isFullWidth) {
      return SizedBox(
        width: double.infinity,
        child: button,
      );
    }

    return button;
  }

  Widget _buildButtonChild() {
    if (isLoading) {
      return LoadingIndicator(
        size: _getLoadingSize(),
        color: _getLoadingColor(),
      );
    }

    final textWidget = Text(
      text,
      style: _getTextStyle(),
    );

    if (icon != null && suffixIcon != null) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: _getIconSize()),
          const SizedBox(width: AppDimensions.spacingSmall),
          textWidget,
          const SizedBox(width: AppDimensions.spacingSmall),
          Icon(suffixIcon, size: _getIconSize()),
        ],
      );
    } else if (icon != null) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: _getIconSize()),
          const SizedBox(width: AppDimensions.spacingSmall),
          textWidget,
        ],
      );
    } else if (suffixIcon != null) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          textWidget,
          const SizedBox(width: AppDimensions.spacingSmall),
          Icon(suffixIcon, size: _getIconSize()),
        ],
      );
    }

    return textWidget;
  }

  ButtonStyle _getButtonStyle() {
    switch (type) {
      case AppButtonType.primary:
        return ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          disabledBackgroundColor: AppColors.divider,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
          ),
          padding: padding ?? _getPadding(),
          elevation: 0,
        );
      case AppButtonType.secondary:
        return OutlinedButton.styleFrom(
          backgroundColor: AppColors.secondary.withOpacity(0.1),
          foregroundColor: AppColors.secondary,
          side: const BorderSide(color: AppColors.secondary, width: 1.5),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
          ),
          padding: padding ?? _getPadding(),
        );
      case AppButtonType.outline:
        return OutlinedButton.styleFrom(
          foregroundColor: AppColors.textPrimary,
          side: const BorderSide(color: AppColors.divider, width: 1),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
          ),
          padding: padding ?? _getPadding(),
        );
      case AppButtonType.text:
        return TextButton.styleFrom(
          foregroundColor: AppColors.primary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
          ),
          padding: padding ?? _getPadding(),
        );
      case AppButtonType.danger:
        return ElevatedButton.styleFrom(
          backgroundColor: AppColors.error,
          foregroundColor: Colors.white,
          disabledBackgroundColor: AppColors.divider,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
          ),
          padding: padding ?? _getPadding(),
          elevation: 0,
        );
    }
  }

  Size _getMinimumSize() {
    switch (size) {
      case AppButtonSize.small:
        return const Size(0, AppDimensions.buttonHeightSmall);
      case AppButtonSize.medium:
        return const Size(0, AppDimensions.buttonHeightMedium);
      case AppButtonSize.large:
        return const Size(0, AppDimensions.buttonHeightLarge);
    }
  }

  EdgeInsetsGeometry _getPadding() {
    switch (size) {
      case AppButtonSize.small:
        return const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingMedium,
          vertical: AppDimensions.paddingSmall,
        );
      case AppButtonSize.medium:
        return const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingLarge,
          vertical: AppDimensions.paddingSmall,
        );
      case AppButtonSize.large:
        return const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingLarge,
          vertical: AppDimensions.paddingMedium,
        );
    }
  }

  TextStyle _getTextStyle() {
    switch (size) {
      case AppButtonSize.small:
        return AppTextStyles.caption.copyWith(
          fontWeight: FontWeight.w600,
        );
      case AppButtonSize.medium:
        return AppTextStyles.body2.copyWith(
          fontWeight: FontWeight.w600,
        );
      case AppButtonSize.large:
        return AppTextStyles.button;
    }
  }

  double _getIconSize() {
    switch (size) {
      case AppButtonSize.small:
        return AppDimensions.iconSizeSmall;
      case AppButtonSize.medium:
        return AppDimensions.iconSizeMedium;
      case AppButtonSize.large:
        return AppDimensions.iconSizeLarge;
    }
  }

  double _getLoadingSize() {
    switch (size) {
      case AppButtonSize.small:
        return 16;
      case AppButtonSize.medium:
        return 20;
      case AppButtonSize.large:
        return 24;
    }
  }

  Color _getLoadingColor() {
    switch (type) {
      case AppButtonType.primary:
      case AppButtonType.danger:
        return Colors.white;
      case AppButtonType.secondary:
        return AppColors.secondary;
      case AppButtonType.outline:
        return AppColors.textPrimary;
      case AppButtonType.text:
        return AppColors.primary;
    }
  }
}