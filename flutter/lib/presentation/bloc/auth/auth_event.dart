import 'package:freezed_annotation/freezed_annotation.dart';

part 'auth_event.freezed.dart';

@freezed
class AuthEvent with _$AuthEvent {
  const factory AuthEvent.checkAuthStatus() = _CheckAuthStatus;
  
  const factory AuthEvent.signIn({
    required String email,
    required String password,
    @Default(false) bool rememberMe,
  }) = _SignIn;
  
  const factory AuthEvent.signUp({
    required String email,
    required String password,
    required String name,
    required String username,
  }) = _SignUp;
  
  const factory AuthEvent.signInWithBiometric() = _SignInWithBiometric;
  
  const factory AuthEvent.signInWithGoogle() = _SignInWithGoogle;
  
  const factory AuthEvent.signInWithApple() = _SignInWithApple;
  
  const factory AuthEvent.signOut() = _SignOut;
  
  const factory AuthEvent.resetPassword({
    required String email,
  }) = _ResetPassword;
  
  const factory AuthEvent.refreshToken() = _RefreshToken;
  
  const factory AuthEvent.updateProfile({
    required String userId,
    String? name,
    String? username,
    String? email,
    String? profilePictureUrl,
  }) = _UpdateProfile;
  
  const factory AuthEvent.enableBiometric() = _EnableBiometric;
  
  const factory AuthEvent.disableBiometric() = _DisableBiometric;
  
  const factory AuthEvent.verifyEmail({
    required String token,
  }) = _VerifyEmail;
  
  const factory AuthEvent.verifyPhone({
    required String code,
  }) = _VerifyPhone;
  
  const factory AuthEvent.enableTwoFactor() = _EnableTwoFactor;
  
  const factory AuthEvent.disableTwoFactor() = _DisableTwoFactor;
  
  const factory AuthEvent.verifyTwoFactor({
    required String code,
  }) = _VerifyTwoFactor;
  
  const factory AuthEvent.changePassword({
    required String currentPassword,
    required String newPassword,
  }) = _ChangePassword;
  
  const factory AuthEvent.deleteAccount({
    required String password,
  }) = _DeleteAccount;
  
  const factory AuthEvent.linkSocialAccount({
    required String provider,
  }) = _LinkSocialAccount;
  
  const factory AuthEvent.unlinkSocialAccount({
    required String provider,
  }) = _UnlinkSocialAccount;
  
  const factory AuthEvent.clearError() = _ClearError;
  
  const factory AuthEvent.retry() = _Retry;
}