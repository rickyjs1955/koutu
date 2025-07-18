import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

class AppCheckboxField extends StatelessWidget {
  final bool value;
  final void Function(bool?)? onChanged;
  final String label;
  final String? subtitle;
  final bool enabled;
  final Color? activeColor;
  final Color? checkColor;
  final Widget? leading;
  final EdgeInsetsGeometry? padding;
  final MainAxisAlignment mainAxisAlignment;
  final CrossAxisAlignment crossAxisAlignment;

  const AppCheckboxField({
    super.key,
    required this.value,
    required this.onChanged,
    required this.label,
    this.subtitle,
    this.enabled = true,
    this.activeColor,
    this.checkColor,
    this.leading,
    this.padding,
    this.mainAxisAlignment = MainAxisAlignment.start,
    this.crossAxisAlignment = CrossAxisAlignment.center,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return InkWell(
      onTap: enabled
          ? () {
              onChanged?.call(!value);
            }
          : null,
      borderRadius: AppDimensions.radiusM,
      child: Padding(
        padding: padding ?? EdgeInsets.zero,
        child: Row(
          mainAxisAlignment: mainAxisAlignment,
          crossAxisAlignment: crossAxisAlignment,
          children: [
            if (leading != null) ...[
              leading!,
              const SizedBox(width: AppDimensions.paddingS),
            ],
            SizedBox(
              width: 24,
              height: 24,
              child: Checkbox(
                value: value,
                onChanged: enabled ? onChanged : null,
                activeColor: activeColor ?? theme.colorScheme.primary,
                checkColor: checkColor ?? theme.colorScheme.onPrimary,
                materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
            ),
            const SizedBox(width: AppDimensions.paddingS),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    label,
                    style: AppTextStyles.bodyLarge.copyWith(
                      color: enabled ? null : AppColors.textTertiary,
                    ),
                  ),
                  if (subtitle != null) ...[
                    const SizedBox(height: 2),
                    Text(
                      subtitle!,
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class AppCheckboxListTile extends StatelessWidget {
  final bool value;
  final void Function(bool?)? onChanged;
  final String title;
  final String? subtitle;
  final bool enabled;
  final Color? activeColor;
  final Color? checkColor;
  final Widget? leading;
  final Widget? secondary;
  final bool dense;
  final ListTileControlAffinity controlAffinity;
  final EdgeInsetsGeometry? contentPadding;
  final ShapeBorder? shape;

  const AppCheckboxListTile({
    super.key,
    required this.value,
    required this.onChanged,
    required this.title,
    this.subtitle,
    this.enabled = true,
    this.activeColor,
    this.checkColor,
    this.leading,
    this.secondary,
    this.dense = false,
    this.controlAffinity = ListTileControlAffinity.platform,
    this.contentPadding,
    this.shape,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return CheckboxListTile(
      value: value,
      onChanged: enabled ? onChanged : null,
      title: Text(
        title,
        style: AppTextStyles.bodyLarge.copyWith(
          color: enabled ? null : AppColors.textTertiary,
        ),
      ),
      subtitle: subtitle != null
          ? Text(
              subtitle!,
              style: AppTextStyles.caption.copyWith(
                color: AppColors.textSecondary,
              ),
            )
          : null,
      activeColor: activeColor ?? theme.colorScheme.primary,
      checkColor: checkColor ?? theme.colorScheme.onPrimary,
      secondary: secondary,
      dense: dense,
      controlAffinity: controlAffinity,
      contentPadding: contentPadding,
      shape: shape ??
          RoundedRectangleBorder(
            borderRadius: AppDimensions.radiusM,
          ),
    );
  }
}