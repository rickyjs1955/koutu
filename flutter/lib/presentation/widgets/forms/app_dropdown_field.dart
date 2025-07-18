import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';

class AppDropdownField<T> extends StatelessWidget {
  final String? label;
  final String? hint;
  final T? value;
  final List<DropdownMenuItem<T>> items;
  final void Function(T?)? onChanged;
  final String? Function(T?)? validator;
  final bool enabled;
  final Widget? prefixIcon;
  final String? errorText;
  final Color? fillColor;
  final BorderRadius? borderRadius;
  final EdgeInsetsGeometry? contentPadding;

  const AppDropdownField({
    super.key,
    this.label,
    this.hint,
    this.value,
    required this.items,
    this.onChanged,
    this.validator,
    this.enabled = true,
    this.prefixIcon,
    this.errorText,
    this.fillColor,
    this.borderRadius,
    this.contentPadding,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final hasError = errorText != null && errorText!.isNotEmpty;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (label != null) ...[
          Text(
            label!,
            style: AppTextStyles.labelMedium.copyWith(
              color: hasError ? theme.colorScheme.error : AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingXS),
        ],
        DropdownButtonFormField<T>(
          value: value,
          items: items,
          onChanged: enabled ? onChanged : null,
          validator: validator,
          style: AppTextStyles.bodyLarge,
          icon: const Icon(Icons.arrow_drop_down),
          iconSize: 24,
          isExpanded: true,
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: AppTextStyles.bodyLarge.copyWith(
              color: AppColors.textTertiary,
            ),
            errorText: errorText,
            errorStyle: AppTextStyles.caption,
            errorMaxLines: 2,
            prefixIcon: prefixIcon,
            filled: true,
            fillColor: fillColor ??
                (enabled
                    ? theme.colorScheme.surface
                    : AppColors.backgroundSecondary),
            contentPadding: contentPadding ??
                const EdgeInsets.symmetric(
                  horizontal: AppDimensions.paddingM,
                  vertical: AppDimensions.paddingM,
                ),
            border: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: const BorderSide(color: AppColors.border),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: BorderSide(
                color: hasError ? theme.colorScheme.error : AppColors.border,
              ),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: BorderSide(
                color: hasError
                    ? theme.colorScheme.error
                    : theme.colorScheme.primary,
                width: 2,
              ),
            ),
            errorBorder: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: BorderSide(
                color: theme.colorScheme.error,
              ),
            ),
            focusedErrorBorder: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: BorderSide(
                color: theme.colorScheme.error,
                width: 2,
              ),
            ),
            disabledBorder: OutlineInputBorder(
              borderRadius: borderRadius ?? AppDimensions.radiusM,
              borderSide: BorderSide(
                color: AppColors.border.withOpacity(0.5),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// Helper class for creating dropdown items
class AppDropdownItem<T> {
  final T value;
  final String label;
  final Widget? icon;

  const AppDropdownItem({
    required this.value,
    required this.label,
    this.icon,
  });

  DropdownMenuItem<T> toMenuItem() {
    return DropdownMenuItem<T>(
      value: value,
      child: Row(
        children: [
          if (icon != null) ...[
            icon!,
            const SizedBox(width: AppDimensions.paddingS),
          ],
          Expanded(
            child: Text(
              label,
              style: AppTextStyles.bodyLarge,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  static List<DropdownMenuItem<T>> fromList<T>(
    List<AppDropdownItem<T>> items,
  ) {
    return items.map((item) => item.toMenuItem()).toList();
  }
}