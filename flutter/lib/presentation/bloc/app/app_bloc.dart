import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/presentation/bloc/app/app_event.dart';
import 'package:koutu/presentation/bloc/app/app_state.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/domain/repositories/i_connectivity_repository.dart';
import 'package:koutu/domain/repositories/i_sync_repository.dart';
import 'package:koutu/domain/repositories/i_settings_repository.dart';
import 'package:koutu/core/constants/app_constants.dart';
import 'package:shared_preferences/shared_preferences.dart';

@injectable
class AppBloc extends Bloc<AppEvent, AppState> {
  final AuthBloc _authBloc;
  final WardrobeBloc _wardrobeBloc;
  final GarmentBloc _garmentBloc;
  final IConnectivityRepository _connectivityRepository;
  final ISyncRepository _syncRepository;
  final ISettingsRepository _settingsRepository;
  final SharedPreferences _sharedPreferences;

  AppBloc(
    this._authBloc,
    this._wardrobeBloc,
    this._garmentBloc,
    this._connectivityRepository,
    this._syncRepository,
    this._settingsRepository,
    this._sharedPreferences,
  ) : super(const AppState.initial()) {
    on<AppEvent>((event, emit) async {
      await event.map(
        initialize: (e) => _onInitialize(e, emit),
        themeChanged: (e) => _onThemeChanged(e, emit),
        languageChanged: (e) => _onLanguageChanged(e, emit),
        connectivityChanged: (e) => _onConnectivityChanged(e, emit),
        syncData: (e) => _onSyncData(e, emit),
        clearCache: (e) => _onClearCache(e, emit),
        showSnackbar: (e) => _onShowSnackbar(e, emit),
        hideSnackbar: (e) => _onHideSnackbar(e, emit),
        showDialog: (e) => _onShowDialog(e, emit),
        hideDialog: (e) => _onHideDialog(e, emit),
        updateSettings: (e) => _onUpdateSettings(e, emit),
        resetApp: (e) => _onResetApp(e, emit),
        enableOfflineMode: (e) => _onEnableOfflineMode(e, emit),
        disableOfflineMode: (e) => _onDisableOfflineMode(e, emit),
        logError: (e) => _onLogError(e, emit),
        enableDebugMode: (e) => _onEnableDebugMode(e, emit),
        disableDebugMode: (e) => _onDisableDebugMode(e, emit),
        updateOnboardingStatus: (e) => _onUpdateOnboardingStatus(e, emit),
        scheduleBackgroundSync: (e) => _onScheduleBackgroundSync(e, emit),
        cancelBackgroundSync: (e) => _onCancelBackgroundSync(e, emit),
        handleDeepLink: (e) => _onHandleDeepLink(e, emit),
        updateBadgeCount: (e) => _onUpdateBadgeCount(e, emit),
        clearBadgeCount: (e) => _onClearBadgeCount(e, emit),
        requestPermissions: (e) => _onRequestPermissions(e, emit),
        updateAnalytics: (e) => _onUpdateAnalytics(e, emit),
        refreshApp: (e) => _onRefreshApp(e, emit),
      );
    });

    // Listen to connectivity changes
    _connectivityRepository.connectivityStream.listen((isConnected) {
      add(AppEvent.connectivityChanged(isConnected));
    });

    // Listen to auth state changes
    _authBloc.stream.listen((authState) {
      authState.maybeWhen(
        authenticated: (user) => add(const AppEvent.refreshApp()),
        unauthenticated: () => add(const AppEvent.resetApp()),
        orElse: () {},
      );
    });
  }

  Future<void> _onInitialize(
    _Initialize event,
    Emitter<AppState> emit,
  ) async {
    try {
      emit(const AppState.loading());

      // Load app settings
      final settings = await _settingsRepository.getSettings();
      final isOnboardingCompleted = _sharedPreferences.getBool(
        AppConstants.onboardingCompletedKey,
      ) ?? false;

      // Initialize connectivity
      final isConnected = await _connectivityRepository.isConnected();
      
      // Check for first time user
      final isFirstTime = !isOnboardingCompleted;

      emit(AppState.ready(
        themeMode: settings.themeMode,
        language: settings.language,
        isConnected: isConnected,
        isFirstTime: isFirstTime,
        isOfflineMode: settings.isOfflineMode,
        isDebugMode: settings.isDebugMode,
        settings: settings,
        badgeCount: 0,
        lastSyncTime: settings.lastSyncTime,
      ));

      // Initialize auth check
      _authBloc.add(const AuthEvent.checkAuthStatus());

      // Schedule background sync if connected
      if (isConnected && !settings.isOfflineMode) {
        add(const AppEvent.scheduleBackgroundSync());
      }
    } catch (e) {
      emit(AppState.error(
        'Failed to initialize app: ${e.toString()}',
        AppSettings.defaultSettings(),
      ));
    }
  }

  Future<void> _onThemeChanged(
    _ThemeChanged event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        themeMode: event.themeMode,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        themeMode: event.themeMode,
        settings: updatedSettings,
      ));
    }
  }

  Future<void> _onLanguageChanged(
    _LanguageChanged event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        language: event.language,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        language: event.language,
        settings: updatedSettings,
      ));
    }
  }

  Future<void> _onConnectivityChanged(
    _ConnectivityChanged event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(isConnected: event.isConnected));
      
      // Auto-sync when connection is restored
      if (event.isConnected && !currentState.isOfflineMode) {
        add(const AppEvent.syncData());
      }
    }
  }

  Future<void> _onSyncData(
    _SyncData event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady && currentState.isConnected) {
      emit(currentState.copyWith(isSyncing: true));
      
      try {
        await _syncRepository.syncAll();
        
        final updatedSettings = currentState.settings.copyWith(
          lastSyncTime: DateTime.now(),
        );
        
        await _settingsRepository.updateSettings(updatedSettings);
        
        emit(currentState.copyWith(
          isSyncing: false,
          settings: updatedSettings,
          lastSyncTime: DateTime.now(),
        ));
      } catch (e) {
        emit(currentState.copyWith(
          isSyncing: false,
          errorMessage: 'Sync failed: ${e.toString()}',
        ));
      }
    }
  }

  Future<void> _onClearCache(
    _ClearCache event,
    Emitter<AppState> emit,
  ) async {
    try {
      await _settingsRepository.clearCache();
      
      // Clear BLoC caches
      _wardrobeBloc.add(const WardrobeEvent.clearCache());
      _garmentBloc.add(const GarmentEvent.clearCache());
      
      add(const AppEvent.showSnackbar('Cache cleared successfully'));
    } catch (e) {
      add(AppEvent.showSnackbar('Failed to clear cache: ${e.toString()}'));
    }
  }

  Future<void> _onShowSnackbar(
    _ShowSnackbar event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(
        snackbarMessage: event.message,
        snackbarType: event.type,
      ));
    }
  }

  Future<void> _onHideSnackbar(
    _HideSnackbar event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(
        snackbarMessage: null,
        snackbarType: null,
      ));
    }
  }

  Future<void> _onShowDialog(
    _ShowDialog event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(
        dialogTitle: event.title,
        dialogMessage: event.message,
        dialogType: event.type,
      ));
    }
  }

  Future<void> _onHideDialog(
    _HideDialog event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(
        dialogTitle: null,
        dialogMessage: null,
        dialogType: null,
      ));
    }
  }

  Future<void> _onUpdateSettings(
    _UpdateSettings event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      await _settingsRepository.updateSettings(event.settings);
      emit(currentState.copyWith(settings: event.settings));
    }
  }

  Future<void> _onResetApp(
    _ResetApp event,
    Emitter<AppState> emit,
  ) async {
    try {
      // Clear all stored data
      await _settingsRepository.clearAll();
      await _sharedPreferences.clear();
      
      // Reset BLoCs
      _wardrobeBloc.add(const WardrobeEvent.clearCache());
      _garmentBloc.add(const GarmentEvent.clearCache());
      
      // Re-initialize app
      add(const AppEvent.initialize());
    } catch (e) {
      emit(AppState.error(
        'Failed to reset app: ${e.toString()}',
        AppSettings.defaultSettings(),
      ));
    }
  }

  Future<void> _onEnableOfflineMode(
    _EnableOfflineMode event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        isOfflineMode: true,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        isOfflineMode: true,
        settings: updatedSettings,
      ));
    }
  }

  Future<void> _onDisableOfflineMode(
    _DisableOfflineMode event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        isOfflineMode: false,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        isOfflineMode: false,
        settings: updatedSettings,
      ));
      
      // Sync data when offline mode is disabled
      if (currentState.isConnected) {
        add(const AppEvent.syncData());
      }
    }
  }

  Future<void> _onLogError(
    _LogError event,
    Emitter<AppState> emit,
  ) async {
    // Log error to analytics/crash reporting
    print('App Error: ${event.error}');
    if (event.stackTrace != null) {
      print('Stack Trace: ${event.stackTrace}');
    }
    
    // Show error message to user if needed
    if (event.showToUser) {
      add(AppEvent.showSnackbar(
        'An error occurred: ${event.error}',
        type: SnackbarType.error,
      ));
    }
  }

  Future<void> _onEnableDebugMode(
    _EnableDebugMode event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        isDebugMode: true,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        isDebugMode: true,
        settings: updatedSettings,
      ));
    }
  }

  Future<void> _onDisableDebugMode(
    _DisableDebugMode event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        isDebugMode: false,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(
        isDebugMode: false,
        settings: updatedSettings,
      ));
    }
  }

  Future<void> _onUpdateOnboardingStatus(
    _UpdateOnboardingStatus event,
    Emitter<AppState> emit,
  ) async {
    await _sharedPreferences.setBool(
      AppConstants.onboardingCompletedKey,
      event.isCompleted,
    );
    
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(isFirstTime: !event.isCompleted));
    }
  }

  Future<void> _onScheduleBackgroundSync(
    _ScheduleBackgroundSync event,
    Emitter<AppState> emit,
  ) async {
    // Schedule periodic sync
    await _syncRepository.scheduleBackgroundSync();
  }

  Future<void> _onCancelBackgroundSync(
    _CancelBackgroundSync event,
    Emitter<AppState> emit,
  ) async {
    // Cancel scheduled sync
    await _syncRepository.cancelBackgroundSync();
  }

  Future<void> _onHandleDeepLink(
    _HandleDeepLink event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(pendingDeepLink: event.deepLink));
    }
  }

  Future<void> _onUpdateBadgeCount(
    _UpdateBadgeCount event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(badgeCount: event.count));
    }
  }

  Future<void> _onClearBadgeCount(
    _ClearBadgeCount event,
    Emitter<AppState> emit,
  ) async {
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(badgeCount: 0));
    }
  }

  Future<void> _onRequestPermissions(
    _RequestPermissions event,
    Emitter<AppState> emit,
  ) async {
    // Handle permission requests
    final currentState = state;
    if (currentState is AppReady) {
      emit(currentState.copyWith(
        permissionRequests: event.permissions,
      ));
    }
  }

  Future<void> _onUpdateAnalytics(
    _UpdateAnalytics event,
    Emitter<AppState> emit,
  ) async {
    // Update analytics settings
    final currentState = state;
    if (currentState is AppReady) {
      final updatedSettings = currentState.settings.copyWith(
        analyticsEnabled: event.enabled,
      );
      
      await _settingsRepository.updateSettings(updatedSettings);
      
      emit(currentState.copyWith(settings: updatedSettings));
    }
  }

  Future<void> _onRefreshApp(
    _RefreshApp event,
    Emitter<AppState> emit,
  ) async {
    // Refresh all data
    _wardrobeBloc.add(const WardrobeEvent.refreshWardrobes());
    _garmentBloc.add(const GarmentEvent.refreshGarments());
    
    if (state is AppReady && (state as AppReady).isConnected) {
      add(const AppEvent.syncData());
    }
  }
}