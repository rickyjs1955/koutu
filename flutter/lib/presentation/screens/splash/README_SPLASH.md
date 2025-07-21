# Koutu Splash Screen Implementation

This directory contains multiple implementations of the splash screen with wardrobe opening animation and logo reveal.

## Available Implementations

### 1. Simple Splash Screen (`simple_splash_screen.dart`)
- Works with the simple app version (without dependency injection)
- Uses standard Navigator for routing
- Pure Flutter animations (no external animation files needed)

### 2. Go Router Splash Screen (`splash_screen.dart`)
- Works with the full app version using go_router
- Integrates with the app's routing system
- Pure Flutter animations

### 3. Lottie Splash Screen (`splash_screen_lottie.dart`)
- Alternative version that supports Lottie animations
- Can use custom wardrobe animation files
- Fallback to static animation if Lottie file not found

## Animation Sequence

1. **Initial Delay** (500ms) - Brief pause before animation starts
2. **Wardrobe Opening** (1200ms) - Doors slide apart revealing the logo
3. **Logo Appearance** (800ms) - Logo scales in with elastic effect and glow
4. **Hold** (1500ms) - Display complete animation before navigation
5. **Navigation** - Automatically navigates to the home screen

## Customization Options

### Colors
The splash screen uses colors from `AppColors`:
- Wardrobe doors: Brown wood texture
- Logo background: Primary color
- Glow effect: Primary color with opacity

### Timing
You can adjust animation timings in the `_initAnimations()` method:
```dart
_wardrobeController = AnimationController(
  duration: const Duration(milliseconds: 1200), // Adjust door opening speed
  vsync: this,
);

_logoController = AnimationController(
  duration: const Duration(milliseconds: 800), // Adjust logo animation speed
  vsync: this,
);
```

### Logo
Currently using the `Icons.checkroom` icon. To use a custom logo:

1. Add your logo image to `assets/images/logo/`
2. Update `pubspec.yaml` to include the asset
3. Replace the Icon widget with:
```dart
Image.asset(
  'assets/images/logo/koutu_logo.png',
  width: 50,
  height: 50,
  color: Colors.white,
)
```

### Wardrobe Design
The wardrobe doors include:
- Wood grain texture (horizontal lines)
- Golden door handles
- Inner panel borders
- Gradient shading for depth

## Using Lottie Animations

To use the Lottie version:

1. Create or download a wardrobe opening animation (JSON format)
2. Place it in `assets/animations/wardrobe_opening.json`
3. Update `pubspec.yaml`:
```yaml
flutter:
  assets:
    - assets/animations/
```
4. Use `SplashScreenLottie` instead of `SimpleSplashScreen`

## Performance Considerations

- The splash screen disposes of animation controllers properly
- Animations are optimized for smooth 60fps performance
- Loading indicator provides visual feedback during initialization

## Future Enhancements

1. **Sound Effects** - Add door opening sound
2. **Particle Effects** - Add sparkles when logo appears
3. **Custom Fonts** - Use brand-specific typography
4. **Responsive Sizing** - Better adaptation to different screen sizes
5. **Dark Mode** - Adapt colors based on theme