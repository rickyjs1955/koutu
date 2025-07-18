import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/domain/entities/user.dart';

part 'auth_state.freezed.dart';

@freezed
class AuthState with _$AuthState {
  const factory AuthState.initial() = _Initial;
  
  const factory AuthState.loading() = _Loading;
  
  const factory AuthState.authenticated(User user) = _Authenticated;
  
  const factory AuthState.unauthenticated() = _Unauthenticated;
  
  const factory AuthState.error(String message) = _Error;
  
  const factory AuthState.biometricSetup() = _BiometricSetup;
  
  const factory AuthState.socialSignIn() = _SocialSignIn;
  
  const factory AuthState.passwordReset() = _PasswordReset;
  
  const factory AuthState.profileUpdate() = _ProfileUpdate;
  
  const factory AuthState.emailVerification() = _EmailVerification;
  
  const factory AuthState.phoneVerification() = _PhoneVerification;
  
  const factory AuthState.twoFactorAuth() = _TwoFactorAuth;
  
  const factory AuthState.sessionExpired() = _SessionExpired;
  
  const factory AuthState.accountLocked() = _AccountLocked;
  
  const factory AuthState.networkError() = _NetworkError;
}

extension AuthStateX on AuthState {
  bool get isAuthenticated => this is _Authenticated;
  
  bool get isLoading => this is _Loading;
  
  bool get isError => this is _Error;
  
  bool get isInitial => this is _Initial;
  
  bool get isUnauthenticated => this is _Unauthenticated;
  
  User? get user => maybeWhen(
    authenticated: (user) => user,
    orElse: () => null,
  );
  
  String? get errorMessage => maybeWhen(
    error: (message) => message,
    orElse: () => null,
  );
  
  bool get canRetry => maybeWhen(
    error: (_) => true,
    networkError: () => true,
    orElse: () => false,
  );
  
  bool get requiresReauthentication => maybeWhen(
    sessionExpired: () => true,
    accountLocked: () => true,
    orElse: () => false,
  );
}