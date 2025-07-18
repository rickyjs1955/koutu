import 'package:injectable/injectable.dart';

/// Module for registering BLoC dependencies
/// 
/// Note: BLoCs are typically registered as factories rather than singletons
/// to ensure fresh state for each screen/feature that uses them.
@module
abstract class BlocModule {
  // BLoCs will be registered here as they are implemented
  // Example:
  // @factoryMethod
  // AuthBloc authBloc(IAuthRepository authRepository) => 
  //     AuthBloc(authRepository);
}