import 'package:get_it/get_it.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/injection/injection.config.dart';

final GetIt getIt = GetIt.instance;

@InjectableInit(
  initializerName: 'init',
  preferRelativeImports: true,
  asExtension: true,
)
Future<void> configureDependencies({
  String? environment,
}) async {
  await getIt.init(environment: environment);
}

/// Available environments
abstract class Environment {
  static const dev = 'dev';
  static const staging = 'staging';
  static const prod = 'prod';
  static const test = 'test';
}