import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/theme/app_theme.dart';

import '../../test_helpers/test_helpers.dart';

void main() {
  group('AppButton Golden Tests', () {
    for (final variant in TestHelpers.screenVariants) {
      testWidgets('renders all button types - $variant', (tester) async {
        await TestHelpers.setScreenSize(tester, variant);

        await tester.pumpWidget(
          MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    // Primary button
                    AppButton(
                      text: 'Primary Button',
                      onPressed: () {},
                      type: AppButtonType.primary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Secondary button
                    AppButton(
                      text: 'Secondary Button',
                      onPressed: () {},
                      type: AppButtonType.secondary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Text button
                    AppButton(
                      text: 'Text Button',
                      onPressed: () {},
                      type: AppButtonType.text,
                    ),
                    const SizedBox(height: 16),
                    
                    // Loading button
                    const AppButton(
                      text: 'Loading Button',
                      isLoading: true,
                      type: AppButtonType.primary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Disabled button
                    const AppButton(
                      text: 'Disabled Button',
                      onPressed: null,
                      type: AppButtonType.primary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Button with icon
                    AppButton(
                      text: 'Button with Icon',
                      onPressed: () {},
                      icon: Icons.add,
                      type: AppButtonType.primary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Small button
                    AppButton(
                      text: 'Small Button',
                      onPressed: () {},
                      size: AppButtonSize.small,
                      type: AppButtonType.primary,
                    ),
                    const SizedBox(height: 16),
                    
                    // Large button
                    AppButton(
                      text: 'Large Button',
                      onPressed: () {},
                      size: AppButtonSize.large,
                      type: AppButtonType.primary,
                    ),
                  ],
                ),
              ),
            ),
          ),
        );

        await expectLater(
          find.byType(MaterialApp),
          matchesGoldenFile('goldens/app_button_all_types_$variant.png'),
        );
      });
    }

    testWidgets('renders dark theme buttons', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          theme: AppTheme.darkTheme,
          home: Scaffold(
            body: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  AppButton(
                    text: 'Primary Dark',
                    onPressed: () {},
                    type: AppButtonType.primary,
                  ),
                  const SizedBox(height: 16),
                  AppButton(
                    text: 'Secondary Dark',
                    onPressed: () {},
                    type: AppButtonType.secondary,
                  ),
                  const SizedBox(height: 16),
                  AppButton(
                    text: 'Text Dark',
                    onPressed: () {},
                    type: AppButtonType.text,
                  ),
                ],
              ),
            ),
          ),
        ),
      );

      await expectLater(
        find.byType(MaterialApp),
        matchesGoldenFile('goldens/app_button_dark_theme.png'),
      );
    });
  });
}