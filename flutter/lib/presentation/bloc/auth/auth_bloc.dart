import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/core/constants/storage_keys.dart';
import 'package:koutu/domain/repositories/i_auth_repository.dart';
import 'package:koutu/presentation/bloc/auth/auth_event.dart';
import 'package:koutu/presentation/bloc/auth/auth_state.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

@injectable
class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final IAuthRepository _authRepository;
  final SharedPreferences _sharedPreferences;
  final FlutterSecureStorage _secureStorage;
  final LocalAuthentication _localAuth = LocalAuthentication();

  AuthBloc(
    this._authRepository,
    this._sharedPreferences,
    @Named('secureStorage') this._secureStorage,
  ) : super(const AuthState.initial()) {
    on<AuthEvent>((event, emit) async {
      await event.map(
        checkAuthStatus: (e) => _onCheckAuthStatus(e, emit),
        signIn: (e) => _onSignIn(e, emit),
        signUp: (e) => _onSignUp(e, emit),
        signInWithBiometric: (e) => _onSignInWithBiometric(e, emit),
        signInWithGoogle: (e) => _onSignInWithGoogle(e, emit),
        signInWithApple: (e) => _onSignInWithApple(e, emit),
        signOut: (e) => _onSignOut(e, emit),
        resetPassword: (e) => _onResetPassword(e, emit),
        refreshToken: (e) => _onRefreshToken(e, emit),
        updateProfile: (e) => _onUpdateProfile(e, emit),
        enableBiometric: (e) => _onEnableBiometric(e, emit),
        disableBiometric: (e) => _onDisableBiometric(e, emit),
        verifyEmail: (e) => _onVerifyEmail(e, emit),
        verifyPhone: (e) => _onVerifyPhone(e, emit),
        enableTwoFactor: (e) => _onEnableTwoFactor(e, emit),
        disableTwoFactor: (e) => _onDisableTwoFactor(e, emit),
        verifyTwoFactor: (e) => _onVerifyTwoFactor(e, emit),
        changePassword: (e) => _onChangePassword(e, emit),
        deleteAccount: (e) => _onDeleteAccount(e, emit),
        linkSocialAccount: (e) => _onLinkSocialAccount(e, emit),
        unlinkSocialAccount: (e) => _onUnlinkSocialAccount(e, emit),
        clearError: (e) => _onClearError(e, emit),
        retry: (e) => _onRetry(e, emit),
      );
    });
  }

  Future<void> _onCheckAuthStatus(
    _CheckAuthStatus event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final isAuthenticated = await _authRepository.isAuthenticated;
    if (isAuthenticated) {
      final userResult = await _authRepository.getCurrentUser();
      userResult.fold(
        (failure) => emit(const AuthState.unauthenticated()),
        (user) {
          if (user != null) {
            emit(AuthState.authenticated(user));
          } else {
            emit(const AuthState.unauthenticated());
          }
        },
      );
    } else {
      emit(const AuthState.unauthenticated());
    }
  }

  Future<void> _onSignIn(
    _SignIn event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.login(
      email: event.email,
      password: event.password,
    );

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        // Save credentials if remember me is checked
        if (event.rememberMe) {
          await _sharedPreferences.setBool(StorageKeys.rememberMe, true);
          await _secureStorage.write(
            key: StorageKeys.userEmail,
            value: event.email,
          );
        }

        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onSignUp(
    _SignUp event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.register(
      email: event.email,
      password: event.password,
      name: event.name,
    );

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        // Auto sign in after successful registration
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onSignInWithBiometric(
    _SignInWithBiometric event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    try {
      // Check if biometric is available
      final canCheckBiometrics = await _localAuth.canCheckBiometrics;
      final isDeviceSupported = await _localAuth.isDeviceSupported();
      
      if (!canCheckBiometrics || !isDeviceSupported) {
        emit(const AuthState.error('Biometric authentication not available'));
        return;
      }

      // Check if biometric is enabled for this app
      final biometricEnabled = _sharedPreferences.getBool(
        StorageKeys.biometricEnabled,
      ) ?? false;
      
      if (!biometricEnabled) {
        emit(const AuthState.error('Please enable biometric authentication in settings'));
        return;
      }

      // Authenticate with biometric
      final authenticated = await _localAuth.authenticate(
        localizedReason: 'Authenticate to access Koutu',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );

      if (authenticated) {
        // Get stored credentials
        final email = await _secureStorage.read(key: StorageKeys.userEmail);
        final token = await _secureStorage.read(key: StorageKeys.authToken);
        
        if (email != null && token != null) {
          final userResult = await _authRepository.getCurrentUser();
          userResult.fold(
            (failure) => emit(AuthState.error(failure.message)),
            (user) {
              if (user != null) {
                emit(AuthState.authenticated(user));
              } else {
                emit(const AuthState.error('Failed to authenticate'));
              }
            },
          );
        } else {
          emit(const AuthState.error('No stored credentials found'));
        }
      } else {
        emit(const AuthState.error('Biometric authentication failed'));
      }
    } catch (e) {
      emit(AuthState.error(e.toString()));
    }
  }

  Future<void> _onSignInWithGoogle(
    _SignInWithGoogle event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());
    // TODO: Implement Google Sign In
    emit(const AuthState.error('Google Sign In not implemented yet'));
  }

  Future<void> _onSignInWithApple(
    _SignInWithApple event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());
    // TODO: Implement Apple Sign In
    emit(const AuthState.error('Apple Sign In not implemented yet'));
  }

  Future<void> _onSignOut(
    _SignOut event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.logout();

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (_) async {
        // Clear stored credentials
        await _secureStorage.deleteAll();
        await _sharedPreferences.remove(StorageKeys.lastSyncTime);
        
        emit(const AuthState.unauthenticated());
      },
    );
  }

  Future<void> _onResetPassword(
    _ResetPassword event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.resetPassword(event.email);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (_) async {
        // Return to initial state to indicate success
        emit(const AuthState.initial());
      },
    );
  }

  Future<void> _onRefreshToken(
    _RefreshToken event,
    Emitter<AuthState> emit,
  ) async {
    final result = await _authRepository.refreshToken();

    await result.fold(
      (failure) async {
        // Token refresh failed, user needs to login again
        emit(const AuthState.unauthenticated());
      },
      (_) async {
        // Token refreshed successfully, check auth status
        add(const AuthEvent.checkAuthStatus());
      },
    );
  }

  Future<void> _onUpdateProfile(
    _UpdateProfile event,
    Emitter<AuthState> emit,
  ) async {
    state.maybeWhen(
      authenticated: (currentUser) async {
        emit(const AuthState.loading());

        final updatedUser = currentUser.copyWith(
          firstName: event.name?.split(' ').first ?? currentUser.firstName,
          lastName: event.name?.split(' ').skip(1).join(' ') ?? currentUser.lastName,
          username: event.username ?? currentUser.username,
          email: event.email ?? currentUser.email,
          profilePictureUrl: event.profilePictureUrl ?? currentUser.profilePictureUrl,
        );

        final result = await _authRepository.updateProfile(updatedUser);

        await result.fold(
          (failure) async => emit(AuthState.error(failure.message)),
          (user) async => emit(AuthState.authenticated(user)),
        );
      },
      orElse: () {
        emit(const AuthState.error('Not authenticated'));
      },
    );
  }

  Future<void> _onEnableBiometric(
    _EnableBiometric event,
    Emitter<AuthState> emit,
  ) async {
    try {
      // Check if biometric is available
      final canCheckBiometrics = await _localAuth.canCheckBiometrics;
      final isDeviceSupported = await _localAuth.isDeviceSupported();
      
      if (!canCheckBiometrics || !isDeviceSupported) {
        emit(const AuthState.error('Biometric authentication not available on this device'));
        return;
      }

      // Check for available biometrics
      final availableBiometrics = await _localAuth.getAvailableBiometrics();
      if (availableBiometrics.isEmpty) {
        emit(const AuthState.error('No biometric authentication methods available'));
        return;
      }

      // Test biometric authentication
      final authenticated = await _localAuth.authenticate(
        localizedReason: 'Enable biometric authentication for Koutu',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );

      if (authenticated) {
        await _sharedPreferences.setBool(StorageKeys.biometricEnabled, true);
        emit(const AuthState.biometricSetup());
      } else {
        emit(const AuthState.error('Biometric authentication failed'));
      }
    } catch (e) {
      emit(AuthState.error('Failed to enable biometric authentication: ${e.toString()}'));
    }
  }

  Future<void> _onDisableBiometric(
    _DisableBiometric event,
    Emitter<AuthState> emit,
  ) async {
    try {
      await _sharedPreferences.setBool(StorageKeys.biometricEnabled, false);
      emit(const AuthState.biometricSetup());
    } catch (e) {
      emit(AuthState.error('Failed to disable biometric authentication: ${e.toString()}'));
    }
  }

  Future<void> _onVerifyEmail(
    _VerifyEmail event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.verifyEmail(event.token);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onVerifyPhone(
    _VerifyPhone event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.verifyPhone(event.code);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onEnableTwoFactor(
    _EnableTwoFactor event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.enableTwoFactor();

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (qrCodeUrl) async {
        emit(const AuthState.twoFactorAuth());
      },
    );
  }

  Future<void> _onDisableTwoFactor(
    _DisableTwoFactor event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.disableTwoFactor();

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onVerifyTwoFactor(
    _VerifyTwoFactor event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.verifyTwoFactor(event.code);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onChangePassword(
    _ChangePassword event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.changePassword(
      currentPassword: event.currentPassword,
      newPassword: event.newPassword,
    );

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onDeleteAccount(
    _DeleteAccount event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.deleteAccount(event.password);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (_) async {
        // Clear all local data
        await _secureStorage.deleteAll();
        await _sharedPreferences.clear();
        
        emit(const AuthState.unauthenticated());
      },
    );
  }

  Future<void> _onLinkSocialAccount(
    _LinkSocialAccount event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.linkSocialAccount(event.provider);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onUnlinkSocialAccount(
    _UnlinkSocialAccount event,
    Emitter<AuthState> emit,
  ) async {
    emit(const AuthState.loading());

    final result = await _authRepository.unlinkSocialAccount(event.provider);

    await result.fold(
      (failure) async => emit(AuthState.error(failure.message)),
      (user) async {
        emit(AuthState.authenticated(user));
      },
    );
  }

  Future<void> _onClearError(
    _ClearError event,
    Emitter<AuthState> emit,
  ) async {
    // Return to previous state or initial state
    final isAuthenticated = await _authRepository.isAuthenticated;
    if (isAuthenticated) {
      final userResult = await _authRepository.getCurrentUser();
      userResult.fold(
        (failure) => emit(const AuthState.initial()),
        (user) => user != null
          ? emit(AuthState.authenticated(user))
          : emit(const AuthState.initial()),
      );
    } else {
      emit(const AuthState.initial());
    }
  }

  Future<void> _onRetry(
    _Retry event,
    Emitter<AuthState> emit,
  ) async {
    // Retry the last failed operation by checking auth status
    add(const AuthEvent.checkAuthStatus());
  }
}