# Flutter Testing Infrastructure

This directory contains the complete testing infrastructure for the Koutu Flutter application, implementing a comprehensive testing strategy with multiple test types and coverage analysis.

## 🧪 Test Types

### 1. Unit Tests (`test/unit/`)
**Purpose**: Test individual components in isolation
- **Repositories**: Data layer testing with mocked dependencies
- **BLoCs**: Business logic testing with state verification
- **Services**: Core service functionality testing
- **Models**: Data model serialization and validation

**Coverage**: 
- Repository tests: API calls, offline handling, error scenarios
- BLoC tests: State transitions, event handling, side effects
- Service tests: Business logic, validation, error handling

### 2. Widget Tests (`test/widget/`)
**Purpose**: Test UI components and user interactions
- **Screens**: Complete screen rendering and interaction
- **Widgets**: Individual widget behavior and properties
- **Forms**: Input validation and submission flows
- **Navigation**: Route transitions and parameter passing

**Coverage**:
- Rendering verification
- User interaction simulation
- State management integration
- Error state handling

### 3. Golden Tests (`test/golden/`)
**Purpose**: Visual regression testing
- **UI Components**: Button styles, themes, responsive layouts
- **Screen Layouts**: Complete screen visual validation
- **Theme Variations**: Light/dark theme consistency
- **Responsive Design**: Multiple screen size validation

**Coverage**:
- Component visual consistency
- Theme application
- Responsive breakpoints
- Cross-platform rendering

### 4. Integration Tests (`integration_test/`)
**Purpose**: End-to-end user flow testing
- **User Journeys**: Complete feature workflows
- **API Integration**: Real backend communication
- **Database Operations**: Data persistence verification
- **Performance**: Load time and responsiveness

**Coverage**:
- Authentication flows
- Wardrobe management
- Garment operations
- Data synchronization

## 📁 Directory Structure

```
test/
├── unit/                          # Unit tests
│   ├── repositories/             # Data layer tests
│   │   ├── auth_repository_test.dart
│   │   ├── wardrobe_repository_test.dart
│   │   ├── garment_repository_test.dart
│   │   └── image_repository_test.dart
│   └── blocs/                    # Business logic tests
│       ├── auth_bloc_test.dart
│       ├── wardrobe_bloc_test.dart
│       └── garment_bloc_test.dart
├── widget/                       # Widget tests
│   └── screens/                  # Screen widget tests
│       ├── auth/
│       │   └── login_screen_test.dart
│       ├── wardrobe/
│       │   └── wardrobe_list_screen_test.dart
│       └── garment/
│           └── garment_detail_screen_test.dart
├── golden/                       # Golden tests
│   └── widgets/
│       └── app_button_golden_test.dart
├── test_helpers/                 # Test utilities
│   ├── test_helpers.dart         # Mock generators
│   ├── mock_data.dart           # Test data
│   └── widget_test_helpers.dart  # Widget test utilities
├── coverage_test.dart           # Coverage inclusion
├── coverage_config.yaml         # Coverage configuration
├── run_tests.sh                 # Test runner script
└── README.md                    # This file
```

## 🛠️ Test Utilities

### MockData (`test_helpers/mock_data.dart`)
Provides realistic test data for all models:
- User profiles with authentication data
- Wardrobe collections with metadata
- Garment items with images and statistics
- API responses and error scenarios

### TestHelpers (`test_helpers/test_helpers.dart`)
Generated mocks for all dependencies:
- Repository interfaces
- External services
- BLoC instances
- Database connections

### WidgetTestHelpers (`test_helpers/widget_test_helpers.dart`)
Widget testing utilities:
- App wrapper with providers
- Navigation testing
- Form interaction helpers
- Custom matchers

## 🚀 Running Tests

### Quick Start
```bash
# Run all tests
flutter test

# Run specific test type
flutter test test/unit/
flutter test test/widget/
flutter test test/golden/

# Run with coverage
flutter test --coverage
```

### Using Test Runner Script
```bash
# Run comprehensive test suite
./test/run_tests.sh

# This will:
# 1. Run all test types
# 2. Generate coverage reports
# 3. Update golden files
# 4. Create HTML reports
```

### Coverage Analysis
```bash
# Generate detailed coverage report
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html

# View coverage in browser
open coverage/html/index.html
```

## 📊 Coverage Requirements

### Minimum Coverage Thresholds
- **Line Coverage**: 80%
- **Branch Coverage**: 70%
- **Function Coverage**: 85%

### Coverage Exclusions
- Generated files (*.g.dart, *.freezed.dart)
- Configuration files (*.config.dart)
- Main entry points (main.dart)
- Dependency injection (injection.dart)
- Environment configuration (env.dart)

## 🎯 Test Strategy

### Test Pyramid
1. **Unit Tests (70%)**: Fast, isolated, comprehensive
2. **Widget Tests (20%)**: UI behavior and integration
3. **Integration Tests (10%)**: End-to-end workflows

### Testing Principles
- **Arrange-Act-Assert**: Clear test structure
- **Given-When-Then**: Behavior-driven descriptions
- **Mock External Dependencies**: Isolated testing
- **Test Edge Cases**: Error scenarios and boundaries
- **Maintain Test Data**: Realistic and consistent

## 🔧 Configuration

### Test Configuration (`pubspec.yaml`)
```yaml
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.2
  bloc_test: ^9.1.4
  integration_test:
    sdk: flutter
```

### Coverage Configuration (`coverage_config.yaml`)
- Minimum coverage thresholds
- File inclusion/exclusion patterns
- Report generation settings
- Quality gate configuration

## 🐛 Debugging Tests

### Common Issues
1. **Mock Setup**: Ensure all dependencies are mocked
2. **Async Operations**: Use `await tester.pumpAndSettle()`
3. **State Management**: Verify BLoC state transitions
4. **Widget Rendering**: Check widget tree structure

### Debug Tools
```bash
# Verbose test output
flutter test --verbose

# Debug specific test
flutter test test/unit/repositories/auth_repository_test.dart --verbose

# Update golden files
flutter test --update-goldens
```

## 📈 Continuous Integration

### GitHub Actions Integration
```yaml
- name: Run Tests
  run: |
    flutter test --coverage
    ./test/run_tests.sh

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: coverage/lcov.info
```

### Quality Gates
- All tests must pass
- Coverage thresholds must be met
- Golden files must be up-to-date
- No new uncovered code

## 🔄 Maintenance

### Regular Tasks
1. **Update Test Data**: Keep mock data current
2. **Review Coverage**: Identify uncovered areas
3. **Update Golden Files**: After UI changes
4. **Refactor Tests**: Maintain test quality

### Best Practices
- Write tests before implementing features
- Keep tests simple and focused
- Use descriptive test names
- Maintain test independence
- Regular test refactoring

## 📚 Resources

### Documentation
- [Flutter Testing Guide](https://docs.flutter.dev/testing)
- [BLoC Testing](https://bloclibrary.dev/#/testing)
- [Mockito Documentation](https://pub.dev/packages/mockito)

### Tools
- [Flutter Test Coverage](https://pub.dev/packages/test_coverage)
- [Golden Toolkit](https://pub.dev/packages/golden_toolkit)
- [Integration Test](https://pub.dev/packages/integration_test)

## 🎉 Success Metrics

### Test Health Indicators
- **Test Pass Rate**: >99%
- **Code Coverage**: >80%
- **Test Execution Time**: <5 minutes
- **Flaky Test Rate**: <1%

### Quality Metrics
- **Bug Detection**: Tests catch issues before release
- **Regression Prevention**: Golden tests prevent UI breaks
- **Documentation**: Tests serve as living documentation
- **Confidence**: High confidence in releases