import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:mockito/mockito.dart';
import 'package:koutu/presentation/screens/wardrobe/wardrobe_list_screen.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';

import '../../../test_helpers/test_helpers.mocks.dart';
import '../../../test_helpers/widget_test_helpers.dart';
import '../../../test_helpers/mock_data.dart';

void main() {
  late MockWardrobeBloc mockWardrobeBloc;

  setUp(() {
    mockWardrobeBloc = MockWardrobeBloc();
  });

  group('WardrobeListScreen', () {
    testWidgets('renders loading state correctly', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(const WardrobeState.loading());
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(const WardrobeState.loading()));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(AppLoadingIndicator), findsOneWidget);
      expect(find.text('Loading wardrobes...'), findsOneWidget);
    });

    testWidgets('renders error state correctly', (tester) async {
      // arrange
      const errorMessage = 'Failed to load wardrobes';
      when(mockWardrobeBloc.state).thenReturn(const WardrobeState.error(errorMessage));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(const WardrobeState.error(errorMessage)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      expect(find.byType(AppErrorWidget), findsOneWidget);
      expect(find.text(errorMessage), findsOneWidget);
    });

    testWidgets('renders empty state correctly', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(const WardrobeState.loaded([]));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(const WardrobeState.loaded([])));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      expect(find.text('No wardrobes found'), findsOneWidget);
      expect(find.text('Create your first wardrobe to get started!'), findsOneWidget);
      expect(find.text('Create Wardrobe'), findsOneWidget);
    });

    testWidgets('renders wardrobes list correctly', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      expect(find.text('My Wardrobes'), findsOneWidget);
      expect(find.text('Summer Collection'), findsOneWidget);
      expect(find.text('Winter Collection'), findsOneWidget);
      expect(find.byType(Card), findsNWidgets(MockData.testWardrobeList.length));
    });

    testWidgets('displays wardrobe details correctly', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      final firstWardrobe = MockData.testWardrobeList.first;
      expect(find.text(firstWardrobe.name), findsOneWidget);
      expect(find.text(firstWardrobe.description), findsOneWidget);
      expect(find.text('${firstWardrobe.garmentCount} items'), findsOneWidget);
      expect(find.text('Default'), findsOneWidget);
    });

    testWidgets('navigates to create wardrobe screen when FAB is tapped', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap FAB
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pump();

      // assert
      verify(mockRouter.push('/create-wardrobe')).called(1);
    });

    testWidgets('navigates to wardrobe detail when wardrobe is tapped', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap first wardrobe
      await tester.tap(find.text('Summer Collection'));
      await tester.pump();

      // assert
      verify(mockRouter.push('/wardrobe/wardrobe123')).called(1);
    });

    testWidgets('shows wardrobe options menu when more button is tapped', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap more button
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Edit'), findsOneWidget);
      expect(find.text('Share'), findsOneWidget);
      expect(find.text('Set as Default'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
    });

    testWidgets('shows edit wardrobe dialog when Edit is selected', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap more button and select Edit
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Edit'));
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Edit Wardrobe'), findsOneWidget);
      expect(find.text('Name'), findsOneWidget);
      expect(find.text('Description'), findsOneWidget);
    });

    testWidgets('shows share dialog when Share is selected', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap more button and select Share
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Share'));
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Share Wardrobe'), findsOneWidget);
      expect(find.text('Invite via Email'), findsOneWidget);
      expect(find.text('QR Code'), findsOneWidget);
    });

    testWidgets('shows delete confirmation dialog when Delete is selected', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap more button and select Delete
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();

      // assert
      expect(find.text('Delete Wardrobe'), findsOneWidget);
      expect(find.text('Are you sure you want to delete this wardrobe?'), findsOneWidget);
      expect(find.text('Cancel'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
    });

    testWidgets('triggers DeleteWardrobe event when deletion is confirmed', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // open delete dialog and confirm
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Delete').last);
      await tester.pump();

      // assert
      verify(mockWardrobeBloc.add(
        argThat(isA<DeleteWardrobe>()
          .having((e) => e.wardrobeId, 'wardrobeId', 'wardrobe123')),
      )).called(1);
    });

    testWidgets('triggers SetDefaultWardrobe event when Set as Default is selected', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap more button and select Set as Default
      await tester.tap(find.byIcon(Icons.more_vert).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Set as Default'));
      await tester.pump();

      // assert
      verify(mockWardrobeBloc.add(
        argThat(isA<SetDefaultWardrobe>()
          .having((e) => e.wardrobeId, 'wardrobeId', 'wardrobe123')),
      )).called(1);
    });

    testWidgets('refreshes wardrobes when pull to refresh is triggered', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // pull to refresh
      await tester.drag(find.byType(RefreshIndicator), const Offset(0, 300));
      await tester.pumpAndSettle();

      // assert
      verify(mockWardrobeBloc.add(const LoadWardrobes())).called(1);
    });

    testWidgets('displays shared wardrobes section', (tester) async {
      // arrange
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // assert
      expect(find.text('Shared with Me'), findsOneWidget);
      expect(find.text('View All'), findsOneWidget);
    });

    testWidgets('navigates to shared wardrobes screen when View All is tapped', (tester) async {
      // arrange
      final mockRouter = MockGoRouter();
      when(mockWardrobeBloc.state).thenReturn(WardrobeState.loaded(MockData.testWardrobeList));
      when(mockWardrobeBloc.stream).thenAnswer((_) => Stream.value(WardrobeState.loaded(MockData.testWardrobeList)));

      // act
      await tester.pumpWidget(
        WidgetTestHelpers.createTestApp(
          home: const WardrobeListScreen(),
          router: mockRouter,
          blocProviders: [
            BlocProvider<WardrobeBloc>.value(value: mockWardrobeBloc),
          ],
        ),
      );

      // tap View All
      await tester.tap(find.text('View All'));
      await tester.pump();

      // assert
      verify(mockRouter.push('/shared-wardrobes')).called(1);
    });
  });
}

// Mock WardrobeBloc
class MockWardrobeBloc extends Mock implements WardrobeBloc {
  @override
  WardrobeState get state => super.noSuchMethod(
        Invocation.getter(#state),
        returnValue: const WardrobeState.initial(),
      );

  @override
  Stream<WardrobeState> get stream => super.noSuchMethod(
        Invocation.getter(#stream),
        returnValue: Stream.value(const WardrobeState.initial()),
      );
}