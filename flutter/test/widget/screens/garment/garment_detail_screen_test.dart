import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/screens/garment/garment_detail_screen.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:smooth_page_indicator/smooth_page_indicator.dart';

import '../../../test_helpers/test_helpers.mocks.dart';
import '../../../test_helpers/widget_test_helpers.dart';
import '../../../test_helpers/mock_data.dart';

void main() {
  late MockGarmentBloc mockGarmentBloc;

  setUp(() {
    mockGarmentBloc = MockGarmentBloc();
  });

  group('GarmentDetailScreen', () {
    testWidgets('renders loading state correctly', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(const GarmentState.loading());
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(const GarmentState.loading()));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(AppLoadingIndicator), findsOneWidget);
      expect(find.text('Loading garment...'), findsOneWidget);
    });

    testWidgets('renders error state correctly', (tester) async {
      // arrange
      const errorMessage = 'Garment not found';
      when(mockGarmentBloc.state).thenReturn(const GarmentState.error(errorMessage));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(const GarmentState.error(errorMessage)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(AppErrorWidget), findsOneWidget);
      expect(find.text(errorMessage), findsOneWidget);
    });

    testWidgets('renders garment detail correctly', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Blue T-Shirt'), findsOneWidget);
      expect(find.text('Nike'), findsOneWidget);
      expect(find.text('\$29.99'), findsOneWidget);
      expect(find.text('Tops'), findsOneWidget);
      expect(find.text('Blue'), findsOneWidget);
      expect(find.text('M'), findsOneWidget);
    });

    testWidgets('displays image carousel correctly', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(PageView), findsOneWidget);
      expect(find.byType(SmoothPageIndicator), findsOneWidget);
      expect(find.byType(Image), findsNWidgets(MockData.testGarment.images.length));
    });

    testWidgets('displays wear statistics correctly', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('${MockData.testGarment.wearCount}x worn'), findsOneWidget);
      expect(find.text('Cost per wear: \$${(MockData.testGarment.price / MockData.testGarment.wearCount).toStringAsFixed(2)}'), findsOneWidget);
    });

    testWidgets('displays tags correctly', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      for (final tag in MockData.testGarment.tags) {
        expect(find.text(tag), findsOneWidget);
      }
    });

    testWidgets('shows edit button in app bar', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byIcon(Icons.edit), findsOneWidget);
    });

    testWidgets('shows options menu in app bar', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byIcon(Icons.more_vert), findsOneWidget);
    });

    testWidgets('shows record wear FAB', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(FloatingActionButton), findsOneWidget);
      expect(find.byIcon(Icons.check), findsOneWidget);
    });

    testWidgets('navigates to edit screen when edit button is tapped', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          router: mockRouter,
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // tap edit button
      await tester.tap(find.byIcon(Icons.edit));
      await tester.pump();

      // assert
      verify(mockRouter.push('/edit-garment/garment123')).called(1);
    });

    testWidgets('shows options menu when more button is tapped', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // tap more button
      await tester.tap(find.byIcon(Icons.more_vert));
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Share'), findsOneWidget);
      expect(find.text('Duplicate'), findsOneWidget);
      expect(find.text('Move to Wardrobe'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
    });

    testWidgets('shows delete confirmation dialog when Delete is selected', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // tap more button and select Delete
      await tester.tap(find.byIcon(Icons.more_vert));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Delete Garment'), findsOneWidget);
      expect(find.text('Are you sure you want to delete this garment?'), findsOneWidget);
      expect(find.text('Cancel'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
    });

    testWidgets('triggers RecordWear event when FAB is tapped', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // tap FAB
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pump();

      // assert
      verify(mockGarmentBloc.add(
        argThat(isA<RecordWear>()
          .having((e) => e.garmentId, 'garmentId', 'garment123')),
      )).called(1);
    });

    testWidgets('triggers DeleteGarment event when deletion is confirmed', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // open delete dialog and confirm
      await tester.tap(find.byIcon(Icons.more_vert));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete').last);
      await tester.pump();

      // assert
      verify(mockGarmentBloc.add(
        argThat(isA<DeleteGarment>()
          .having((e) => e.garmentId, 'garmentId', 'garment123')),
      )).called(1);
    });

    testWidgets('shows wear history section', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Wear History'), findsOneWidget);
      expect(find.text('View All'), findsOneWidget);
    });

    testWidgets('shows similar garments section', (tester) async {
      // arrange
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(MockData.testGarment));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(MockData.testGarment)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Similar Garments'), findsOneWidget);
    });

    testWidgets('displays care instructions if available', (tester) async {
      // arrange
      final garmentWithCareInstructions = MockData.testGarment.copyWith(
        careInstructions: 'Machine wash cold, tumble dry low',
      );
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(garmentWithCareInstructions));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(garmentWithCareInstructions)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Care Instructions'), findsOneWidget);
      expect(find.text('Machine wash cold, tumble dry low'), findsOneWidget);
    });

    testWidgets('shows purchase details if available', (tester) async {
      // arrange
      final garmentWithPurchaseDetails = MockData.testGarment.copyWith(
        purchaseDate: DateTime.now().subtract(const Duration(days: 30)),
        purchaseLocation: 'Nike Store',
      );
      when(mockGarmentBloc.state).thenReturn(GarmentState.detail(garmentWithPurchaseDetails));
      when(mockGarmentBloc.stream).thenAnswer((_) => Stream.value(GarmentState.detail(garmentWithPurchaseDetails)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const GarmentDetailScreen(garmentId: 'garment123'),
          blocProviders: [
            BlocProvider<GarmentBloc>.value(value: mockGarmentBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Purchase Details'), findsOneWidget);
      expect(find.text('Nike Store'), findsOneWidget);
    });
  });
}

// Mock GarmentBloc
class MockGarmentBloc extends Mock implements GarmentBloc {
  @override
  GarmentState get state => super.noSuchMethod(
        Invocation.getter(#state),
        returnValue: const GarmentState.initial(),
      );

  @override
  Stream<GarmentState> get stream => super.noSuchMethod(
        Invocation.getter(#stream),
        returnValue: Stream.value(const GarmentState.initial()),
      );
}