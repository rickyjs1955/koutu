import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:koutu/core/routing/app_router.dart';
import 'package:koutu/core/theme/app_theme.dart';
import 'package:koutu/injection/injection.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/theme/theme_cubit.dart';

class KoutuApp extends StatefulWidget {
  const KoutuApp({super.key});

  @override
  State<KoutuApp> createState() => _KoutuAppState();
}

class _KoutuAppState extends State<KoutuApp> with WidgetsBindingObserver {
  late final AppRouter _appRouter;
  late final AuthBloc _authBloc;
  late final ThemeCubit _themeCubit;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    
    // Initialize dependencies
    _appRouter = getIt<AppRouter>();
    _authBloc = getIt<AuthBloc>()..add(const AuthEvent.checkAuthStatus());
    _themeCubit = getIt<ThemeCubit>()..loadTheme();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _authBloc.close();
    _themeCubit.close();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        // App resumed from background
        _authBloc.add(const AuthEvent.checkAuthStatus());
        break;
      case AppLifecycleState.paused:
        // App moved to background
        break;
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
      case AppLifecycleState.hidden:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return MultiBlocProvider(
      providers: [
        BlocProvider.value(value: _authBloc),
        BlocProvider.value(value: _themeCubit),
      ],
      child: BlocBuilder<ThemeCubit, ThemeState>(
        builder: (context, themeState) {
          return MaterialApp.router(
            title: 'Koutu',
            debugShowCheckedModeBanner: false,
            theme: AppTheme.lightTheme,
            darkTheme: AppTheme.darkTheme,
            themeMode: themeState.themeMode,
            routerConfig: _appRouter.config(
              reevaluateListenable: _authBloc.stream.asBroadcastStream(),
            ),
            builder: (context, child) {
              // Global app wrapper for consistent behavior
              return MediaQuery(
                // Prevent font scaling beyond reasonable limits
                data: MediaQuery.of(context).copyWith(
                  textScaleFactor: MediaQuery.of(context).textScaleFactor.clamp(0.8, 1.3),
                ),
                child: child!,
              );
            },
          );
        },
      ),
    );
  }
}