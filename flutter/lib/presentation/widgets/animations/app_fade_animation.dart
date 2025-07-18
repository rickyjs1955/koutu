import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';

class AppFadeAnimation extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final Duration delay;
  final Curve curve;
  final bool animate;
  final double begin;
  final double end;
  final VoidCallback? onComplete;

  const AppFadeAnimation({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 300),
    this.delay = Duration.zero,
    this.curve = Curves.easeInOut,
    this.animate = true,
    this.begin = 0.0,
    this.end = 1.0,
    this.onComplete,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    return child
        .animate(
          onComplete: onComplete != null ? (_) => onComplete!() : null,
        )
        .fade(
          duration: duration,
          delay: delay,
          curve: curve,
          begin: begin,
          end: end,
        );
  }
}

class AppSlideAnimation extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final Duration delay;
  final Curve curve;
  final bool animate;
  final Offset begin;
  final Offset end;
  final VoidCallback? onComplete;

  const AppSlideAnimation({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 300),
    this.delay = Duration.zero,
    this.curve = Curves.easeInOut,
    this.animate = true,
    this.begin = const Offset(0, 0.1),
    this.end = Offset.zero,
    this.onComplete,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    return child
        .animate(
          onComplete: onComplete != null ? (_) => onComplete!() : null,
        )
        .slide(
          duration: duration,
          delay: delay,
          curve: curve,
          begin: begin,
          end: end,
        );
  }
}

class AppScaleAnimation extends StatelessWidget {
  final Widget child;
  final Duration duration;
  final Duration delay;
  final Curve curve;
  final bool animate;
  final double begin;
  final double end;
  final Alignment alignment;
  final VoidCallback? onComplete;

  const AppScaleAnimation({
    super.key,
    required this.child,
    this.duration = const Duration(milliseconds: 300),
    this.delay = Duration.zero,
    this.curve = Curves.easeInOut,
    this.animate = true,
    this.begin = 0.8,
    this.end = 1.0,
    this.alignment = Alignment.center,
    this.onComplete,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) return child;

    return child
        .animate(
          onComplete: onComplete != null ? (_) => onComplete!() : null,
        )
        .scale(
          duration: duration,
          delay: delay,
          curve: curve,
          begin: Offset(begin, begin),
          end: const Offset(1.0, 1.0),
          alignment: alignment,
        );
  }
}

class AppStaggeredAnimation extends StatelessWidget {
  final List<Widget> children;
  final Duration itemDuration;
  final Duration delayBetween;
  final Curve curve;
  final bool animate;
  final Axis direction;
  final MainAxisAlignment mainAxisAlignment;
  final CrossAxisAlignment crossAxisAlignment;
  final double spacing;

  const AppStaggeredAnimation({
    super.key,
    required this.children,
    this.itemDuration = const Duration(milliseconds: 300),
    this.delayBetween = const Duration(milliseconds: 100),
    this.curve = Curves.easeInOut,
    this.animate = true,
    this.direction = Axis.vertical,
    this.mainAxisAlignment = MainAxisAlignment.start,
    this.crossAxisAlignment = CrossAxisAlignment.center,
    this.spacing = 0,
  });

  @override
  Widget build(BuildContext context) {
    if (!animate) {
      return direction == Axis.vertical
          ? Column(
              mainAxisAlignment: mainAxisAlignment,
              crossAxisAlignment: crossAxisAlignment,
              children: children,
            )
          : Row(
              mainAxisAlignment: mainAxisAlignment,
              crossAxisAlignment: crossAxisAlignment,
              children: children,
            );
    }

    final animatedChildren = children.asMap().entries.map((entry) {
      final index = entry.key;
      final child = entry.value;
      final delay = delayBetween * index;

      return child
          .animate()
          .fade(
            duration: itemDuration,
            delay: delay,
            curve: curve,
          )
          .slide(
            duration: itemDuration,
            delay: delay,
            curve: curve,
            begin: direction == Axis.vertical
                ? const Offset(0, 0.1)
                : const Offset(0.1, 0),
          );
    }).toList();

    return direction == Axis.vertical
        ? Column(
            mainAxisAlignment: mainAxisAlignment,
            crossAxisAlignment: crossAxisAlignment,
            children: animatedChildren
                .map((child) => Padding(
                      padding: EdgeInsets.only(bottom: spacing),
                      child: child,
                    ))
                .toList(),
          )
        : Row(
            mainAxisAlignment: mainAxisAlignment,
            crossAxisAlignment: crossAxisAlignment,
            children: animatedChildren
                .map((child) => Padding(
                      padding: EdgeInsets.only(right: spacing),
                      child: child,
                    ))
                .toList(),
          );
  }
}