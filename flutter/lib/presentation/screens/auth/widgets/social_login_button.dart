import 'package:flutter/material.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';

enum SocialProvider {
  google,
  apple,
  facebook,
}

class SocialLoginButton extends StatelessWidget {
  final SocialProvider provider;
  final VoidCallback? onPressed;

  const SocialLoginButton({
    super.key,
    required this.provider,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    final config = _getProviderConfig();
    
    return OutlinedButton(
      onPressed: onPressed,
      style: OutlinedButton.styleFrom(
        foregroundColor: config.textColor,
        backgroundColor: config.backgroundColor,
        side: BorderSide(
          color: config.borderColor,
          width: 1,
        ),
        minimumSize: const Size(
          double.infinity,
          AppDimensions.buttonHeightLarge,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(AppDimensions.radiusLarge),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            config.icon,
            size: AppDimensions.iconSizeLarge,
            color: config.iconColor,
          ),
          const SizedBox(width: AppDimensions.spacingSmall),
          Text(
            config.text,
            style: AppTextStyles.button.copyWith(
              color: config.textColor,
            ),
          ),
        ],
      ),
    );
  }

  _ProviderConfig _getProviderConfig() {
    switch (provider) {
      case SocialProvider.google:
        return _ProviderConfig(
          icon: Icons.g_mobiledata_rounded,
          text: 'Continue with Google',
          backgroundColor: Colors.white,
          textColor: AppColors.textPrimary,
          iconColor: AppColors.textPrimary,
          borderColor: AppColors.divider,
        );
      case SocialProvider.apple:
        return _ProviderConfig(
          icon: Icons.apple_rounded,
          text: 'Continue with Apple',
          backgroundColor: Colors.black,
          textColor: Colors.white,
          iconColor: Colors.white,
          borderColor: Colors.black,
        );
      case SocialProvider.facebook:
        return _ProviderConfig(
          icon: Icons.facebook_rounded,
          text: 'Continue with Facebook',
          backgroundColor: const Color(0xFF1877F2),
          textColor: Colors.white,
          iconColor: Colors.white,
          borderColor: const Color(0xFF1877F2),
        );
    }
  }
}

class _ProviderConfig {
  final IconData icon;
  final String text;
  final Color backgroundColor;
  final Color textColor;
  final Color iconColor;
  final Color borderColor;

  const _ProviderConfig({
    required this.icon,
    required this.text,
    required this.backgroundColor,
    required this.textColor,
    required this.iconColor,
    required this.borderColor,
  });
}