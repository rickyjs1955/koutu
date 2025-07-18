import 'dart:io';
import 'package:flutter/material.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';

class BiometricLoginButton extends StatelessWidget {
  final VoidCallback? onPressed;
  final bool isLoading;

  const BiometricLoginButton({
    super.key,
    required this.onPressed,
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    final icon = Platform.isIOS
        ? Icons.face_rounded
        : Icons.fingerprint_rounded;
    
    final text = Platform.isIOS
        ? 'Sign in with Face ID'
        : 'Sign in with Fingerprint';

    return OutlinedButton.icon(
      onPressed: onPressed,
      icon: Icon(
        icon,
        size: AppDimensions.iconSizeLarge,
      ),
      label: Text(
        text,
        style: AppTextStyles.button,
      ),
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.primary,
        side: const BorderSide(
          color: AppColors.primary,
          width: 1.5,
        ),
        minimumSize: const Size(
          double.infinity,
          AppDimensions.buttonHeightLarge,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
        ),
      ),
    );
  }
}