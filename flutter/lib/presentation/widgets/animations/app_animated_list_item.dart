import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

class AppAnimatedListItem extends StatelessWidget {
  final Widget child;
  final int index;
  final Duration duration;
  final Duration baseDelay;
  final Duration itemDelay;
  final Curve curve;
  final bool animate;
  final double slideOffset;
  final VoidCallback? onComplete;

  const AppAnimatedListItem({
    super.key,
    required this.child,
    required this.index,
    this.duration = const Duration(milliseconds: 400),
    this.baseDelay = Duration.zero,
    this.itemDelay = const Duration(milliseconds: 50),
    this.curve = Curves.easeOutQuart,
    this.animate = true,
    this.slideOffset = 30,
    this.onComplete,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    final delay = baseDelay + (itemDelay * index);

    return child
        .animate(
          onComplete: onComplete != null ? (_) => onComplete!() : null,
        )
        .fade(
          duration: duration,
          delay: delay,
          curve: curve,
        )
        .slideY(
          begin: slideOffset / MediaQuery.of(context).size.height,
          end: 0,
          duration: duration,
          delay: delay,
          curve: curve,
        );
  }
}

class AppAnimatedSwitcher extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final Duration? reverseDuration;
  final Curve switchInCurve;
  final Curve switchOutCurve;
  final AnimatedSwitcherTransitionBuilder? transitionBuilder;
  final AnimatedSwitcherLayoutBuilder? layoutBuilder;

  const AppAnimatedSwitcher({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 300),
    this.reverseDuration,
    this.switchInCurve = Curves.easeIn,
    this.switchOutCurve = Curves.easeOut,
    this.transitionBuilder,
    this.layoutBuilder,
  });

  @override
  Widget build(BuildContext context) {
    return AnimatedSwitcher(
      duration: duration,
      reverseDuration: reverseDuration,
      switchInCurve: switchInCurve,
      switchOutCurve: switchOutCurve,
      transitionBuilder: transitionBuilder ?? _defaultTransitionBuilder,
      layoutBuilder: layoutBuilder ?? AnimatedSwitcher.defaultLayoutBuilder,
      child: child,
    );
  }

  Widget _defaultTransitionBuilder(Widget child, Animation<double> animation) {
    return FadeTransition(
      opacity: animation,
      child: SlideTransition(
        position: Tween<Offset>(
          begin: const Offset(0, 0.05),
          end: Offset.zero,
        ).animate(animation),
        child: child,
      ),
    );
  }
}

class AppHeroAnimation extends StatelessWidget {
  final String tag;
  final Widget child;
  final CreateRectTween? createRectTween;
  final HeroFlightShuttleBuilder? flightShuttleBuilder;
  final HeroPlaceholderBuilder? placeholderBuilder;
  final bool transitionOnUserGestures;

  const AppHeroAnimation({
    super.key,
    required this.tag,
    required this.child,
    this.createRectTween,
    this.flightShuttleBuilder,
    this.placeholderBuilder,
    this.transitionOnUserGestures = false,
  });

  @override
  Widget build(BuildContext context) {
    return Hero(
      tag: tag,
      createRectTween: createRectTween,
      flightShuttleBuilder: flightShuttleBuilder,
      placeholderBuilder: placeholderBuilder,
      transitionOnUserGestures: transitionOnUserGestures,
      child: child,
    );
  }
}

class AppPulseAnimation extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final double minScale;
  final double maxScale;
  final bool animate;
  final int? repeat;

  const AppPulseAnimation({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 1000),
    this.minScale = 0.95,
    this.maxScale = 1.05,
    this.animate = true,
    this.repeat,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    return child
        .animate(
          onPlay: (controller) {
            if (repeat == null) {
              controller.repeat(reverse: true);
            } else {
              controller.repeat(reverse: true, period: duration * 2 * repeat!);
            }
          },
        )
        .scale(
          begin: Offset(minScale, minScale),
          end: Offset(maxScale, maxScale),
          duration: duration,
          curve: Curves.easeInOut,
        );
  }
}

class AppShakeAnimation extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final double offset;
  final int shakes;
  final bool animate;
  final VoidCallback? onComplete;

  const AppShakeAnimation({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 500),
    this.offset = 10,
    this.shakes = 3,
    this.animate = true,
    this.onComplete,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    return child
        .animate(
          onComplete: onComplete != null ? (_) => onComplete!() : null,
        )
        .shake(
          duration: duration,
          offset: Offset(offset, 0),
          rotation: 0,
          hz: shakes.toDouble(),
        );
  }
}