import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/screens/auth/login_screen.dart';
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/widgets/forms/app_text_field.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/core/error/failures.dart';

import '../../../test_helpers/test_helpers.mocks.dart';
import '../../../test_helpers/widget_test_helpers.dart';
import '../../../test_helpers/mock_data.dart';

void main() {
  late MockAuthBloc mockAuthBloc;

  setUp(() {
    mockAuthBloc = MockAuthBloc();
  });

  group('LoginScreen', () {
    testWidgets('renders correctly', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Welcome Back'), findsOneWidget);
      expect(find.text('Sign in to continue'), findsOneWidget);
      expect(find.byType(AppTextField), findsNWidgets(2)); // Email and password
      expect(find.text('Sign In'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text('Don\'t have an account? Sign Up'), findsOneWidget);
    });

    testWidgets('validates empty email', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // assert
      expect(find.text('Email is required'), findsOneWidget);
    });

    testWidgets('validates invalid email format', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.enterText(
        find.byType(AppTextField).first,
        WidgetTestData.invalidEmail,
      );
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // assert
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('validates empty password', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.enterText(
        find.byType(AppTextField).first,
        WidgetTestData.validEmail,
      );
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // assert
      expect(find.text('Password is required'), findsOneWidget);
    });

    testWidgets('submits form with valid data', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.enterText(
        find.byType(AppTextField).first,
        WidgetTestData.validEmail,
      );
      await tester.enterText(
        find.byType(AppTextField).last,
        WidgetTestData.validPassword,
      );
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // assert
      verify(mockAuthBloc.add(
        argThat(isA<Login>()
          .having((e) => e.email, 'email', WidgetTestData.validEmail)
          .having((e) => e.password, 'password', WidgetTestData.validPassword)),
      )).called(1);
    });

    testWidgets('shows loading indicator when authenticating', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.loading());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.loading()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.text('Signing in...'), findsOneWidget);
      
      // Verify form is disabled
      final signInButton = tester.widget<AppButton>(
        find.widgetWithText(AppButton, 'Sign In'),
      );
      expect(signInButton.onPressed, isNull);
    });

    testWidgets('shows error message on login failure', (tester) async {
      // arrange
      const errorMessage = 'Invalid credentials';
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.fromIterable([
        const AuthState.initial(),
        const AuthState.error(errorMessage),
      ]));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.pump();
      await tester.pump(); // Process stream

      // assert
      expect(find.text(errorMessage), findsOneWidget);
      expect(find.byType(SnackBar), findsOneWidget);
    });

    testWidgets('navigates to home on successful login', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.fromIterable([
        const AuthState.initial(),
        AuthState.authenticated(MockData.testUser),
      ]));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.pump();
      await tester.pump(); // Process stream

      // assert
      verify(mockRouter.go('/')).called(1);
    });

    testWidgets('navigates to register screen', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.tap(find.text('Sign Up'));
      await tester.pump();

      // assert
      verify(mockRouter.push('/register')).called(1);
    });

    testWidgets('navigates to forgot password screen', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act
      await tester.tap(find.text('Forgot Password?'));
      await tester.pump();

      // assert
      verify(mockRouter.push('/forgot-password')).called(1);
    });

    testWidgets('toggles password visibility', (tester) async {
      // arrange
      when(mockAuthBloc.state).thenReturn(const AuthState.initial());
      when(mockAuthBloc.stream).thenAnswer((_) => Stream.value(const AuthState.initial()));

      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const LoginScreen(),
          blocProviders: [
            BlocProvider<AuthBloc>.value(value: mockAuthBloc),
          ],
        ),
      );

      // act & assert
      // Initially password is obscured
      final passwordField = tester.widget<AppTextField>(
        find.byType(AppTextField).last,
      );
      expect(passwordField.obscureText, isTrue);

      // Toggle visibility
      await tester.tap(find.byIcon(Icons.visibility_off));
      await tester.pump();

      // Password should be visible
      final updatedPasswordField = tester.widget<AppTextField>(
        find.byType(AppTextField).last,
      );
      expect(updatedPasswordField.obscureText, isFalse);
      expect(find.byIcon(Icons.visibility), findsOneWidget);
    });
  });
}

// Mock AuthBloc
class MockAuthBloc extends Mock implements AuthBloc {
  @override
  AuthState get state => super.noSuchMethod(
        Invocation.getter(#state),
        returnValue: const AuthState.initial(),
      );

  @override
  Stream<AuthState> get stream => super.noSuchMethod(
        Invocation.getter(#stream),
        returnValue: Stream.value(const AuthState.initial()),
      );
}