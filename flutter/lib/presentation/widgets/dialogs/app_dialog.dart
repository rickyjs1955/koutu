import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';

class AppDialog extends StatelessWidget {
  final String? title;
  final String? message;
  final Widget? content;
  final String? confirmText;
  final String? cancelText;
  final VoidCallback? onConfirm;
  final VoidCallback? onCancel;
  final bool showCancel;
  final bool barrierDismissible;
  final AppButtonType confirmButtonType;
  final IconData? icon;
  final Color? iconColor;

  const AppDialog({
    super.key,
    this.title,
    this.message,
    this.content,
    this.confirmText,
    this.cancelText,
    this.onConfirm,
    this.onCancel,
    this.showCancel = true,
    this.barrierDismissible = true,
    this.confirmButtonType = AppButtonType.primary,
    this.icon,
    this.iconColor,
  });

  static Future<bool?> show(
    BuildContext context, {
    String? title,
    String? message,
    Widget? content,
    String? confirmText,
    String? cancelText,
    VoidCallback? onConfirm,
    VoidCallback? onCancel,
    bool showCancel = true,
    bool barrierDismissible = true,
    AppButtonType confirmButtonType = AppButtonType.primary,
    IconData? icon,
    Color? iconColor,
  }) {
    return showDialog<bool>(
      context: context,
      barrierDismissible: barrierDismissible,
      builder: (context) => AppDialog(
        title: title,
        message: message,
        content: content,
        confirmText: confirmText,
        cancelText: cancelText,
        onConfirm: onConfirm,
        onCancel: onCancel,
        showCancel: showCancel,
        barrierDismissible: barrierDismissible,
        confirmButtonType: confirmButtonType,
        icon: icon,
        iconColor: iconColor,
      ),
    );
  }

  static Future<bool?> confirm(
    BuildContext context, {
    required String title,
    required String message,
    String confirmText = 'Confirm',
    String cancelText = 'Cancel',
    AppButtonType confirmButtonType = AppButtonType.primary,
  }) {
    return show(
      context,
      title: title,
      message: message,
      confirmText: confirmText,
      cancelText: cancelText,
      confirmButtonType: confirmButtonType,
      onConfirm: () => Navigator.of(context).pop(true),
      onCancel: () => Navigator.of(context).pop(false),
    );
  }

  static Future<void> alert(
    BuildContext context, {
    required String title,
    required String message,
    String confirmText = 'OK',
    IconData? icon,
    Color? iconColor,
  }) {
    return show(
      context,
      title: title,
      message: message,
      confirmText: confirmText,
      showCancel: false,
      icon: icon,
      iconColor: iconColor,
      onConfirm: () => Navigator.of(context).pop(),
    );
  }

  static Future<void> error(
    BuildContext context, {
    String title = 'Error',
    required String message,
    String confirmText = 'OK',
  }) {
    return alert(
      context,
      title: title,
      message: message,
      confirmText: confirmText,
      icon: Icons.error_outline,
      iconColor: Theme.of(context).colorScheme.error,
    );
  }

  static Future<void> success(
    BuildContext context, {
    String title = 'Success',
    required String message,
    String confirmText = 'OK',
  }) {
    return alert(
      context,
      title: title,
      message: message,
      confirmText: confirmText,
      icon: Icons.check_circle_outline,
      iconColor: AppColors.success,
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Dialog(
      shape: RoundedRectangleBorder(
        borderRadius: AppDimensions.radiusXL,
      ),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 400),
        padding: const EdgeInsets.all(AppDimensions.paddingL),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (icon != null) ...[
              Icon(
                icon,
                size: 48,
                color: iconColor ?? theme.colorScheme.primary,
              ),
              const SizedBox(height: AppDimensions.paddingM),
            ],
            if (title != null) ...[
              Text(
                title!,
                style: AppTextStyles.h3,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: AppDimensions.paddingM),
            ],
            if (message != null) ...[
              Text(
                message!,
                style: AppTextStyles.bodyLarge.copyWith(
                  color: AppColors.textSecondary,
                ),
                textAlign: TextAlign.center,
              ),
            ],
            if (content != null) ...[
              if (message != null) const SizedBox(height: AppDimensions.paddingM),
              content!,
            ],
            const SizedBox(height: AppDimensions.paddingL),
            Row(
              children: [
                if (showCancel) ...[
                  Expanded(
                    child: AppButton(
                      text: cancelText ?? 'Cancel',
                      onPressed: () {
                        onCancel?.call();
                        Navigator.of(context).pop(false);
                      },
                      type: AppButtonType.secondary,
                      size: AppButtonSize.medium,
                    ),
                  ),
                  const SizedBox(width: AppDimensions.paddingM),
                ],
                Expanded(
                  child: AppButton(
                    text: confirmText ?? 'OK',
                    onPressed: () {
                      onConfirm?.call();
                      if (!showCancel) {
                        Navigator.of(context).pop();
                      }
                    },
                    type: confirmButtonType,
                    size: AppButtonSize.medium,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}