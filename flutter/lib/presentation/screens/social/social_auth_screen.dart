import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/data/models/social/social_user_model.dart';
import 'package:koutu/services/social/social_auth_service.dart';
import 'package:go_router/go_router.dart';

/// Screen for social authentication and account creation
class SocialAuthScreen extends StatefulWidget {
  final bool isSignUp;
  
  const SocialAuthScreen({
    super.key,
    this.isSignUp = false,
  });

  @override
  State<SocialAuthScreen> createState() => _SocialAuthScreenState();
}

class _SocialAuthScreenState extends State<SocialAuthScreen> {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _displayNameController = TextEditingController();
  final _bioController = TextEditingController();
  final _websiteController = TextEditingController();
  
  bool _isLoading = false;
  bool _isCreatingAccount = false;
  bool _usernameAvailable = false;
  bool _checkingUsername = false;
  
  SocialAuthResult? _authResult;
  List<SocialAuthProvider> _linkedProviders = [];
  
  @override
  void initState() {
    super.initState();
    _usernameController.addListener(_onUsernameChanged);
  }
  
  @override
  void dispose() {
    _usernameController.dispose();
    _displayNameController.dispose();
    _bioController.dispose();
    _websiteController.dispose();
    super.dispose();
  }
  
  void _onUsernameChanged() {
    if (_usernameController.text.length >= 3) {
      _checkUsernameAvailability();
    }
  }
  
  void _checkUsernameAvailability() async {
    if (_checkingUsername) return;
    
    setState(() => _checkingUsername = true);
    
    final result = await SocialAuthService.checkUsernameAvailability(
      _usernameController.text,
    );
    
    result.fold(
      (failure) {
        setState(() {
          _usernameAvailable = false;
          _checkingUsername = false;
        });
      },
      (available) {
        setState(() {
          _usernameAvailable = available;
          _checkingUsername = false;
        });
      },
    );
  }
  
  void _onSocialSignIn(SocialAuthProvider provider) async {
    setState(() => _isLoading = true);
    
    try {
      late final result;
      
      switch (provider) {
        case SocialAuthProvider.google:
          result = await SocialAuthService.signInWithGoogle();
          break;
        case SocialAuthProvider.facebook:
          result = await SocialAuthService.signInWithFacebook();
          break;
        case SocialAuthProvider.apple:
          result = await SocialAuthService.signInWithApple();
          break;
        case SocialAuthProvider.instagram:
          result = await SocialAuthService.signInWithInstagram();
          break;
        case SocialAuthProvider.twitter:
          result = await SocialAuthService.signInWithTwitter();
          break;
      }
      
      result.fold(
        (failure) {
          _showErrorDialog('Sign In Failed', failure.message);
        },
        (authResult) {
          setState(() {
            _authResult = authResult;
            _isCreatingAccount = true;
          });
          
          // Pre-fill form with social data
          if (authResult.displayName != null) {
            _displayNameController.text = authResult.displayName!;
          }
          if (authResult.email != null) {
            _usernameController.text = authResult.email!.split('@')[0];
          }
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onCreateAccount() async {
    if (!_formKey.currentState!.validate()) return;
    if (_authResult == null) return;
    
    setState(() => _isLoading = true);
    
    try {
      final result = await SocialAuthService.createSocialUser(
        _authResult!,
        _usernameController.text,
        _displayNameController.text,
        _bioController.text.isNotEmpty ? _bioController.text : null,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Account Creation Failed', failure.message);
        },
        (user) {
          _showSuccessDialog('Account Created', 'Welcome to Koutu!');
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onLinkAccount(SocialAuthProvider provider) async {
    setState(() => _isLoading = true);
    
    try {
      late final result;
      
      switch (provider) {
        case SocialAuthProvider.google:
          result = await SocialAuthService.signInWithGoogle();
          break;
        case SocialAuthProvider.facebook:
          result = await SocialAuthService.signInWithFacebook();
          break;
        case SocialAuthProvider.apple:
          result = await SocialAuthService.signInWithApple();
          break;
        case SocialAuthProvider.instagram:
          result = await SocialAuthService.signInWithInstagram();
          break;
        case SocialAuthProvider.twitter:
          result = await SocialAuthService.signInWithTwitter();
          break;
      }
      
      result.fold(
        (failure) {
          _showErrorDialog('Link Failed', failure.message);
        },
        (authResult) async {
          final linkResult = await SocialAuthService.linkSocialAccount(
            'current_user_id', // In real app, get from auth state
            authResult,
          );
          
          linkResult.fold(
            (failure) {
              _showErrorDialog('Link Failed', failure.message);
            },
            (success) {
              setState(() {
                _linkedProviders.add(provider);
              });
              
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('${provider.displayName} account linked successfully'),
                  backgroundColor: AppColors.success,
                ),
              );
            },
          );
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onUnlinkAccount(SocialAuthProvider provider) async {
    final confirmed = await AppDialog.confirm(
      context,
      title: 'Unlink Account',
      message: 'Are you sure you want to unlink your ${provider.displayName} account?',
      confirmText: 'Unlink',
      confirmIsDestructive: true,
    );
    
    if (!confirmed) return;
    
    setState(() => _isLoading = true);
    
    try {
      final result = await SocialAuthService.unlinkSocialAccount(
        'current_user_id', // In real app, get from auth state
        provider,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Unlink Failed', failure.message);
        },
        (success) {
          setState(() {
            _linkedProviders.remove(provider);
          });
          
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('${provider.displayName} account unlinked'),
              backgroundColor: AppColors.warning,
            ),
          );
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _showErrorDialog(String title, String message) {
    AppDialog.error(
      context,
      title: title,
      message: message,
    );
  }
  
  void _showSuccessDialog(String title, String message) {
    AppDialog.success(
      context,
      title: title,
      message: message,
      onOkPressed: () {
        context.go('/social/profile');
      },
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: _isCreatingAccount ? 'Create Profile' : 'Social Authentication',
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : _isCreatingAccount
              ? _buildAccountCreationForm()
              : _buildSocialAuthOptions(),
    );
  }
  
  Widget _buildSocialAuthOptions() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          AppFadeAnimation(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  widget.isSignUp ? 'Create Account' : 'Sign In',
                  style: AppTextStyles.h1,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                Text(
                  widget.isSignUp
                      ? 'Connect with your social accounts to get started'
                      : 'Connect with your social accounts to continue',
                  style: AppTextStyles.bodyLarge.copyWith(
                    color: AppColors.textSecondary,
                  ),
                ),
              ],
            ),
          ),
          
          const SizedBox(height: AppDimensions.paddingXL),
          
          // Social auth buttons
          ...SocialAuthProvider.values.map((provider) {
            final isLinked = _linkedProviders.contains(provider);
            
            return AppFadeAnimation(
              delay: Duration(milliseconds: provider.index * 100),
              child: Container(
                width: double.infinity,
                margin: const EdgeInsets.only(bottom: AppDimensions.paddingM),
                child: ElevatedButton.icon(
                  onPressed: widget.isSignUp
                      ? () => _onSocialSignIn(provider)
                      : isLinked
                          ? () => _onUnlinkAccount(provider)
                          : () => _onLinkAccount(provider),
                  icon: Icon(
                    _getProviderIcon(provider),
                    size: 24,
                  ),
                  label: Text(
                    widget.isSignUp
                        ? 'Continue with ${provider.displayName}'
                        : isLinked
                            ? 'Unlink ${provider.displayName}'
                            : 'Link ${provider.displayName}',
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: isLinked ? AppColors.success : _getProviderColor(provider),
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingL,
                      vertical: AppDimensions.paddingM,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                    ),
                  ),
                ),
              ),
            );
          }).toList(),
          
          const SizedBox(height: AppDimensions.paddingXL),
          
          // Footer
          AppFadeAnimation(
            delay: const Duration(milliseconds: 600),
            child: Center(
              child: Text(
                'By continuing, you agree to our Terms of Service and Privacy Policy',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
                textAlign: TextAlign.center,
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildAccountCreationForm() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Form(
        key: _formKey,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            AppFadeAnimation(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Complete Your Profile',
                    style: AppTextStyles.h1,
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                  Text(
                    'Tell us a bit about yourself to personalize your experience',
                    style: AppTextStyles.bodyLarge.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingXL),
            
            // Username field
            AppFadeAnimation(
              delay: const Duration(milliseconds: 100),
              child: TextFormField(
                controller: _usernameController,
                decoration: InputDecoration(
                  labelText: 'Username',
                  hintText: 'Enter your username',
                  prefixIcon: const Icon(Icons.alternate_email),
                  suffixIcon: _checkingUsername
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: Center(
                            child: AppLoadingIndicator(
                              size: LoadingIndicatorSize.small,
                            ),
                          ),
                        )
                      : _usernameController.text.length >= 3
                          ? Icon(
                              _usernameAvailable ? Icons.check_circle : Icons.error,
                              color: _usernameAvailable ? AppColors.success : AppColors.error,
                            )
                          : null,
                  helperText: _usernameController.text.length >= 3
                      ? _usernameAvailable
                          ? 'Username is available'
                          : 'Username is not available'
                      : 'Username must be at least 3 characters',
                  helperStyle: TextStyle(
                    color: _usernameController.text.length >= 3
                        ? _usernameAvailable
                            ? AppColors.success
                            : AppColors.error
                        : AppColors.textSecondary,
                  ),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter a username';
                  }
                  if (value.length < 3) {
                    return 'Username must be at least 3 characters';
                  }
                  if (!RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(value)) {
                    return 'Username can only contain letters, numbers, and underscores';
                  }
                  if (!_usernameAvailable) {
                    return 'Username is not available';
                  }
                  return null;
                },
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Display name field
            AppFadeAnimation(
              delay: const Duration(milliseconds: 200),
              child: TextFormField(
                controller: _displayNameController,
                decoration: const InputDecoration(
                  labelText: 'Display Name',
                  hintText: 'Enter your display name',
                  prefixIcon: Icon(Icons.person),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter a display name';
                  }
                  if (value.length > 50) {
                    return 'Display name must be 50 characters or less';
                  }
                  return null;
                },
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Bio field
            AppFadeAnimation(
              delay: const Duration(milliseconds: 300),
              child: TextFormField(
                controller: _bioController,
                maxLines: 3,
                maxLength: 160,
                decoration: const InputDecoration(
                  labelText: 'Bio (Optional)',
                  hintText: 'Tell us about yourself...',
                  prefixIcon: Icon(Icons.info_outline),
                ),
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Website field
            AppFadeAnimation(
              delay: const Duration(milliseconds: 400),
              child: TextFormField(
                controller: _websiteController,
                decoration: const InputDecoration(
                  labelText: 'Website (Optional)',
                  hintText: 'https://yourwebsite.com',
                  prefixIcon: Icon(Icons.link),
                ),
                validator: (value) {
                  if (value != null && value.isNotEmpty) {
                    final uri = Uri.tryParse(value);
                    if (uri == null || !uri.hasScheme || !uri.hasAuthority) {
                      return 'Please enter a valid website URL';
                    }
                  }
                  return null;
                },
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingXL),
            
            // Create account button
            AppFadeAnimation(
              delay: const Duration(milliseconds: 500),
              child: SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _onCreateAccount,
                  child: const Text('Create Account'),
                ),
              ),
            ),
            
            const SizedBox(height: AppDimensions.paddingL),
            
            // Skip button
            AppFadeAnimation(
              delay: const Duration(milliseconds: 600),
              child: Center(
                child: TextButton(
                  onPressed: () {
                    context.go('/home');
                  },
                  child: const Text('Skip for now'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  IconData _getProviderIcon(SocialAuthProvider provider) {
    switch (provider) {
      case SocialAuthProvider.google:
        return Icons.g_mobiledata;
      case SocialAuthProvider.facebook:
        return Icons.facebook;
      case SocialAuthProvider.apple:
        return Icons.apple;
      case SocialAuthProvider.instagram:
        return Icons.camera_alt;
      case SocialAuthProvider.twitter:
        return Icons.alternate_email;
    }
  }
  
  Color _getProviderColor(SocialAuthProvider provider) {
    switch (provider) {
      case SocialAuthProvider.google:
        return const Color(0xFF4285F4);
      case SocialAuthProvider.facebook:
        return const Color(0xFF1877F2);
      case SocialAuthProvider.apple:
        return const Color(0xFF000000);
      case SocialAuthProvider.instagram:
        return const Color(0xFFE4405F);
      case SocialAuthProvider.twitter:
        return const Color(0xFF1DA1F2);
    }
  }
}