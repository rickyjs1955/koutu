import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/theme/app_theme.dart';
import 'package:mockito/mockito.dart';

/// Widget test helpers for common setup
class WidgetTestHelpers {
  /// Creates a test app with routing
  static Widget createTestApp({
    required Widget home,
    List<BlocProvider>? blocProviders,
    GoRouter? router,
    ThemeData? theme,
  }) {
    if (router != null) {
      return MultiBlocProvider(
        providers: blocProviders ?? [],
        child: MaterialApp.router(
          theme: theme ?? AppTheme.lightTheme,
          routerConfig: router,
        ),
      );
    }

    return MultiBlocProvider(
      providers: blocProviders ?? [],
      child: MaterialApp(
        theme: theme ?? AppTheme.lightTheme,
        home: home,
      ),
    );
  }

  /// Creates a test router with mock navigation
  static GoRouter createTestRouter({
    required String initialLocation,
    required List<GoRoute> routes,
  }) {
    return GoRouter(
      initialLocation: initialLocation,
      routes: routes,
    );
  }

  /// Wraps a widget with common test providers
  static Widget wrapWithProviders({
    required Widget child,
    AuthBloc? authBloc,
    WardrobeBloc? wardrobeBloc,
    GarmentBloc? garmentBloc,
  }) {
    final providers = <BlocProvider>[];

    if (authBloc != null) {
      providers.add(BlocProvider<AuthBloc>.value(value: authBloc));
    }
    if (wardrobeBloc != null) {
      providers.add(BlocProvider<WardrobeBloc>.value(value: wardrobeBloc));
    }
    if (garmentBloc != null) {
      providers.add(BlocProvider<GarmentBloc>.value(value: garmentBloc));
    }

    return MultiBlocProvider(
      providers: providers,
      child: child,
    );
  }

  /// Common widget finders
  static Finder findButtonWithText(String text) {
    return find.widgetWithText(ElevatedButton, text);
  }

  static Finder findTextFieldWithLabel(String label) {
    return find.ancestor(
      of: find.text(label),
      matching: find.byType(TextField),
    );
  }

  static Finder findIconButton(IconData icon) {
    return find.widgetWithIcon(IconButton, icon);
  }

  /// Verifies navigation occurred
  static void verifyNavigation(MockGoRouter mockRouter, String path) {
    verify(mockRouter.push(path)).called(1);
  }

  /// Waits for async operations to complete
  static Future<void> waitForAsync(WidgetTester tester) async {
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    await tester.pumpAndSettle();
  }

  /// Scrolls to find a widget
  static Future<void> scrollUntilVisible(
    WidgetTester tester,
    Finder finder, {
    Finder? scrollable,
    double delta = 300,
  }) async {
    await tester.dragUntilVisible(
      finder,
      scrollable ?? find.byType(Scrollable).first,
      Offset(0, -delta),
    );
  }

  /// Enters text in a form field
  static Future<void> enterFormText(
    WidgetTester tester,
    String label,
    String text,
  ) async {
    final field = findTextFieldWithLabel(label);
    await tester.enterText(field, text);
    await tester.pump();
  }

  /// Verifies a snackbar is shown
  static void verifySnackBar(String message) {
    expect(find.text(message), findsOneWidget);
    expect(find.byType(SnackBar), findsOneWidget);
  }

  /// Verifies a dialog is shown
  static void verifyDialog({String? title, String? content}) {
    expect(find.byType(Dialog), findsOneWidget);
    if (title != null) {
      expect(find.text(title), findsOneWidget);
    }
    if (content != null) {
      expect(find.text(content), findsOneWidget);
    }
  }

  /// Dismisses a dialog
  static Future<void> dismissDialog(WidgetTester tester) async {
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
  }

  /// Confirms a dialog
  static Future<void> confirmDialog(WidgetTester tester) async {
    await tester.tap(find.text('Confirm'));
    await tester.pumpAndSettle();
  }
}

/// Mock classes for testing
class MockGoRouter extends Mock implements GoRouter {}

class MockNavigatorObserver extends Mock implements NavigatorObserver {}

/// Test data for widgets
class WidgetTestData {
  static const validEmail = 'test@example.com';
  static const validPassword = 'password123';
  static const validUsername = 'testuser';
  static const validFullName = 'Test User';
  
  static const invalidEmail = 'invalid-email';
  static const shortPassword = '123';
  
  static const wardrobeName = 'Test Wardrobe';
  static const wardrobeDescription = 'A test wardrobe description';
  
  static const garmentName = 'Test Garment';
  static const garmentBrand = 'Test Brand';
  static const garmentPrice = '29.99';
}

/// Custom matchers for widget tests
class WidgetMatchers {
  /// Matches a widget with specific properties
  static Matcher hasColor(Color color) {
    return _HasColorMatcher(color);
  }

  /// Matches a widget that is enabled/disabled
  static Matcher isEnabled() {
    return _IsEnabledMatcher(true);
  }

  static Matcher isDisabled() {
    return _IsEnabledMatcher(false);
  }

  /// Matches a loading indicator
  static Matcher isLoading() {
    return find.byType(CircularProgressIndicator);
  }
}

class _HasColorMatcher extends Matcher {
  final Color color;

  _HasColorMatcher(this.color);

  @override
  bool matches(Object? item, Map matchState) {
    if (item is Container) {
      final decoration = item.decoration;
      if (decoration is BoxDecoration) {
        return decoration.color == color;
      }
    }
    return false;
  }

  @override
  Description describe(Description description) {
    return description.add('has color $color');
  }
}

class _IsEnabledMatcher extends Matcher {
  final bool shouldBeEnabled;

  _IsEnabledMatcher(this.shouldBeEnabled);

  @override
  bool matches(Object? item, Map matchState) {
    if (item is ElevatedButton) {
      return (item.onPressed != null) == shouldBeEnabled;
    }
    if (item is TextButton) {
      return (item.onPressed != null) == shouldBeEnabled;
    }
    if (item is IconButton) {
      return (item.onPressed != null) == shouldBeEnabled;
    }
    return false;
  }

  @override
  Description describe(Description description) {
    return description.add(shouldBeEnabled ? 'is enabled' : 'is disabled');
  }
}