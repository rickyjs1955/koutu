import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';

enum ErrorType {
  network,
  server,
  notFound,
  permission,
  generic,
  empty,
}

class AppErrorWidget extends StatelessWidget {
  final ErrorType errorType;
  final String? title;
  final String? message;
  final String? buttonText;
  final VoidCallback? onRetry;
  final Widget? icon;
  final Widget? customAction;
  final bool showIcon;
  final bool showButton;
  final EdgeInsetsGeometry? padding;

  const AppErrorWidget({
    super.key,
    this.errorType = ErrorType.generic,
    this.title,
    this.message,
    this.buttonText,
    this.onRetry,
    this.icon,
    this.customAction,
    this.showIcon = true,
    this.showButton = true,
    this.padding,
  });

  static const _defaultData = {
    ErrorType.network: (
      icon: Icons.wifi_off,
      title: 'No Internet Connection',
      message: 'Please check your internet connection and try again.',
      buttonText: 'Retry',
    ),
    ErrorType.server: (
      icon: Icons.cloud_off,
      title: 'Server Error',
      message: 'Something went wrong on our end. Please try again later.',
      buttonText: 'Retry',
    ),
    ErrorType.notFound: (
      icon: Icons.search_off,
      title: 'Not Found',
      message: 'We couldn\'t find what you\'re looking for.',
      buttonText: 'Go Back',
    ),
    ErrorType.permission: (
      icon: Icons.lock_outline,
      title: 'Access Denied',
      message: 'You don\'t have permission to access this content.',
      buttonText: 'Go Back',
    ),
    ErrorType.generic: (
      icon: Icons.error_outline,
      title: 'Something Went Wrong',
      message: 'An unexpected error occurred. Please try again.',
      buttonText: 'Retry',
    ),
    ErrorType.empty: (
      icon: Icons.inbox,
      title: 'No Data Found',
      message: 'There\'s nothing to show here yet.',
      buttonText: 'Refresh',
    ),
  };

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final defaultData = _defaultData[errorType]!;

    return Center(
      child: Padding(
        padding: padding ??
            const EdgeInsets.symmetric(
              horizontal: AppDimensions.paddingXL,
              vertical: AppDimensions.paddingXL,
            ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (showIcon) ...[
              icon ??
                  Icon(
                    defaultData.icon,
                    size: 64,
                    color: AppColors.textTertiary,
                  ),
              const SizedBox(height: AppDimensions.paddingL),
            ],
            Text(
              title ?? defaultData.title,
              style: AppTextStyles.h3,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: AppDimensions.paddingS),
            Text(
              message ?? defaultData.message,
              style: AppTextStyles.bodyLarge.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: AppDimensions.paddingXL),
            if (showButton && onRetry != null) ...[
              customAction ??
                  AppButton(
                    text: buttonText ?? defaultData.buttonText,
                    onPressed: onRetry,
                    type: AppButtonType.primary,
                  ),
            ] else if (customAction != null) ...[
              customAction!,
            ],
          ],
        ),
      ),
    );
  }
}

class AppErrorBanner extends StatelessWidget {
  final String message;
  final ErrorType errorType;
  final VoidCallback? onDismiss;
  final VoidCallback? onAction;
  final String? actionText;
  final bool showIcon;
  final Duration? autoDismissDuration;

  const AppErrorBanner({
    super.key,
    required this.message,
    this.errorType = ErrorType.generic,
    this.onDismiss,
    this.onAction,
    this.actionText,
    this.showIcon = true,
    this.autoDismissDuration,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final backgroundColor = errorType == ErrorType.network
        ? AppColors.warning
        : theme.colorScheme.error;
    final foregroundColor = errorType == ErrorType.network
        ? AppColors.onWarning
        : theme.colorScheme.onError;

    return Material(
      color: backgroundColor,
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          child: Row(
            children: [
              if (showIcon) ...[
                Icon(
                  _getIconForType(errorType),
                  color: foregroundColor,
                  size: 20,
                ),
                const SizedBox(width: AppDimensions.paddingM),
              ],
              Expanded(
                child: Text(
                  message,
                  style: AppTextStyles.bodyMedium.copyWith(
                    color: foregroundColor,
                  ),
                ),
              ),
              if (actionText != null && onAction != null) ...[
                const SizedBox(width: AppDimensions.paddingM),
                TextButton(
                  onPressed: onAction,
                  style: TextButton.styleFrom(
                    foregroundColor: foregroundColor,
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingM,
                    ),
                  ),
                  child: Text(
                    actionText!,
                    style: AppTextStyles.labelMedium,
                  ),
                ),
              ],
              if (onDismiss != null) ...[
                IconButton(
                  icon: Icon(
                    Icons.close,
                    color: foregroundColor,
                    size: 20,
                  ),
                  onPressed: onDismiss,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints.tightFor(
                    width: 32,
                    height: 32,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  IconData _getIconForType(ErrorType type) {
    switch (type) {
      case ErrorType.network:
        return Icons.wifi_off;
      case ErrorType.server:
        return Icons.cloud_off;
      case ErrorType.notFound:
        return Icons.search_off;
      case ErrorType.permission:
        return Icons.lock_outline;
      case ErrorType.empty:
        return Icons.inbox;
      case ErrorType.generic:
        return Icons.error_outline;
    }
  }
}