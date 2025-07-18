import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:hydrated_bloc/hydrated_bloc.dart';
import 'package:path_provider/path_provider.dart';
import 'package:koutu/app.dart';
import 'package:koutu/injection/injection.dart';
import 'package:koutu/core/utils/logger.dart';
import 'package:koutu/services/search/search_history_manager.dart';
import 'dart:async';

void main() async {
  // Ensure Flutter bindings are initialized
  WidgetsFlutterBinding.ensureInitialized();

  // Set up error handling
  FlutterError.onError = (FlutterErrorDetails details) {
    Logger.error('Flutter error', error: details.exception, stackTrace: details.stack);
  };

  // Initialize HydratedBloc storage
  final storage = await HydratedStorage.build(
    storageDirectory: await getApplicationDocumentsDirectory(),
  );

  // Configure dependency injection
  await configureDependencies();

  // Initialize search history manager
  await SearchHistoryManager.initialize();

  // Set preferred orientations
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Set system UI overlay style
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
      systemNavigationBarColor: Colors.white,
      systemNavigationBarIconBrightness: Brightness.dark,
    ),
  );

  // Run the app with error zone
  runZonedGuarded(
    () {
      HydratedBloc.storage = storage;
      
      // Set up Bloc observer for debugging
      if (const bool.fromEnvironment('dart.vm.product') == false) {
        Bloc.observer = AppBlocObserver();
      }

      runApp(const KoutuApp());
    },
    (error, stackTrace) {
      Logger.error('Uncaught error', error: error, stackTrace: stackTrace);
    },
  );
}

/// Bloc observer for debugging purposes
class AppBlocObserver extends BlocObserver {
  @override
  void onCreate(BlocBase bloc) {
    super.onCreate(bloc);
    Logger.debug('onCreate -- ${bloc.runtimeType}');
  }

  @override
  void onEvent(Bloc bloc, Object? event) {
    super.onEvent(bloc, event);
    Logger.debug('onEvent -- ${bloc.runtimeType}, $event');
  }

  @override
  void onChange(BlocBase bloc, Change change) {
    super.onChange(bloc, change);
    Logger.debug('onChange -- ${bloc.runtimeType}, $change');
  }

  @override
  void onError(BlocBase bloc, Object error, StackTrace stackTrace) {
    Logger.error('onError -- ${bloc.runtimeType}', error: error, stackTrace: stackTrace);
    super.onError(bloc, error, stackTrace);
  }

  @override
  void onClose(BlocBase bloc) {
    super.onClose(bloc);
    Logger.debug('onClose -- ${bloc.runtimeType}');
  }
}