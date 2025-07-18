import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:koutu/main.dart' as app;
import 'package:koutu/injection/injection.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('App Integration Tests', () {
    setUp(() async {
      // Initialize dependencies for testing
      await configureDependencies();
    });

    tearDown(() {
      // Clean up after each test
      getIt.reset();
    });

    testWidgets('complete user flow - login to create wardrobe', (tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Verify we're on the login screen
      expect(find.text('Welcome Back'), findsOneWidget);

      // Enter credentials
      await tester.enterText(
        find.byKey(const Key('email_field')),
        'test@example.com',
      );
      await tester.enterText(
        find.byKey(const Key('password_field')),
        'password123',
      );

      // Tap sign in
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Should navigate to home screen
      expect(find.text('My Wardrobes'), findsOneWidget);

      // Tap create wardrobe button
      await tester.tap(find.byIcon(Icons.add));
      await tester.pumpAndSettle();

      // Fill wardrobe form
      await tester.enterText(
        find.byKey(const Key('wardrobe_name_field')),
        'Summer Collection',
      );
      await tester.enterText(
        find.byKey(const Key('wardrobe_description_field')),
        'My summer wardrobe',
      );

      // Select color theme
      await tester.tap(find.byKey(const Key('color_blue')));
      await tester.pump();

      // Select icon
      await tester.tap(find.byKey(const Key('icon_wardrobe')));
      await tester.pump();

      // Create wardrobe
      await tester.tap(find.text('Create Wardrobe'));
      await tester.pumpAndSettle();

      // Verify wardrobe was created
      expect(find.text('Summer Collection'), findsOneWidget);
      expect(find.text('Wardrobe created successfully!'), findsOneWidget);
    });

    testWidgets('add garment to wardrobe flow', (tester) async {
      // Start the app (assume already logged in)
      app.main();
      await tester.pumpAndSettle();

      // Navigate to wardrobe detail
      await tester.tap(find.text('Summer Collection').first);
      await tester.pumpAndSettle();

      // Tap add garment FAB
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pumpAndSettle();

      // Fill garment form
      await tester.enterText(
        find.byKey(const Key('garment_name_field')),
        'Blue T-Shirt',
      );
      await tester.enterText(
        find.byKey(const Key('garment_brand_field')),
        'Nike',
      );

      // Select category
      await tester.tap(find.byKey(const Key('category_dropdown')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Tops').last);
      await tester.pumpAndSettle();

      // Select color
      await tester.tap(find.byKey(const Key('color_blue')));
      await tester.pump();

      // Select size
      await tester.tap(find.byKey(const Key('size_dropdown')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('M').last);
      await tester.pumpAndSettle();

      // Add tags
      await tester.tap(find.text('Casual'));
      await tester.pump();
      await tester.tap(find.text('Summer'));
      await tester.pump();

      // Scroll to submit button
      await tester.scrollUntilVisible(
        find.text('Add Garment'),
        500,
      );

      // Submit form
      await tester.tap(find.text('Add Garment'));
      await tester.pumpAndSettle();

      // Verify garment was added
      expect(find.text('Blue T-Shirt'), findsOneWidget);
      expect(find.text('Garment added successfully!'), findsOneWidget);
    });

    testWidgets('search and filter garments', (tester) async {
      // Start the app (assume wardrobe with garments exists)
      app.main();
      await tester.pumpAndSettle();

      // Navigate to all garments
      await tester.tap(find.text('All Garments'));
      await tester.pumpAndSettle();

      // Enter search query
      await tester.enterText(
        find.byKey(const Key('search_field')),
        'blue',
      );
      await tester.pumpAndSettle();

      // Verify search results
      expect(find.text('Blue T-Shirt'), findsOneWidget);
      expect(find.text('Red Dress'), findsNothing);

      // Clear search
      await tester.tap(find.byIcon(Icons.clear));
      await tester.pumpAndSettle();

      // Open filter sheet
      await tester.tap(find.byIcon(Icons.filter_list));
      await tester.pumpAndSettle();

      // Select category filter
      await tester.tap(find.text('Tops'));
      await tester.pump();

      // Apply filters
      await tester.tap(find.text('Apply Filters'));
      await tester.pumpAndSettle();

      // Verify filtered results
      expect(find.text('Blue T-Shirt'), findsOneWidget);
      expect(find.text('Black Jeans'), findsNothing);
    });

    testWidgets('record garment wear', (tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Navigate to garment detail
      await tester.tap(find.text('Blue T-Shirt').first);
      await tester.pumpAndSettle();

      // Get initial wear count
      expect(find.text('5x worn'), findsOneWidget);

      // Tap wear button
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pumpAndSettle();

      // Verify wear was recorded
      expect(find.text('6x worn'), findsOneWidget);
      expect(find.text('Wear recorded!'), findsOneWidget);
    });

    testWidgets('share wardrobe flow', (tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Navigate to wardrobe detail
      await tester.tap(find.text('Summer Collection').first);
      await tester.pumpAndSettle();

      // Tap share button
      await tester.tap(find.byIcon(Icons.share));
      await tester.pumpAndSettle();

      // Enter email to share with
      await tester.enterText(
        find.byKey(const Key('share_email_field')),
        'friend@example.com',
      );

      // Send invitation
      await tester.tap(find.byIcon(Icons.send));
      await tester.pumpAndSettle();

      // Verify invitation was sent
      expect(find.text('Invitation sent to friend@example.com'), findsOneWidget);
    });

    testWidgets('logout flow', (tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Open drawer or navigate to profile
      await tester.tap(find.byIcon(Icons.menu));
      await tester.pumpAndSettle();

      // Tap profile
      await tester.tap(find.text('Profile'));
      await tester.pumpAndSettle();

      // Tap logout
      await tester.tap(find.text('Logout'));
      await tester.pumpAndSettle();

      // Confirm logout
      await tester.tap(find.text('Confirm'));
      await tester.pumpAndSettle();

      // Verify we're back at login screen
      expect(find.text('Welcome Back'), findsOneWidget);
    });
  });
}