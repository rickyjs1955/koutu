import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:injectable/injectable.dart';
import 'theme_state.dart';

@injectable
class ThemeCubit extends Cubit<ThemeState> {
  ThemeCubit() : super(const ThemeState.light());

  void toggleTheme() {
    emit(
      state.when(
        light: () => const ThemeState.dark(),
        dark: () => const ThemeState.light(),
      ),
    );
  }

  void setLightTheme() {
    emit(const ThemeState.light());
  }

  void setDarkTheme() {
    emit(const ThemeState.dark());
  }
}