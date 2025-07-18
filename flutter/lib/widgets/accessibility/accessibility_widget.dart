import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/accessibility/accessibility_service.dart';
import 'package:koutu/services/accessibility/multi_language_service.dart';
import 'package:koutu/providers/accessibility_provider.dart';

/// Accessibility-enhanced text widget
class AccessibilityText extends ConsumerWidget {
  final String text;
  final TextStyle? style;
  final TextAlign? textAlign;
  final int? maxLines;
  final TextOverflow? overflow;
  final String? semanticsLabel;
  final bool? softWrap;
  
  const AccessibilityText(
    this.text, {
    Key? key,
    this.style,
    this.textAlign,
    this.maxLines,
    this.overflow,
    this.semanticsLabel,
    this.softWrap,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settingsAsync = ref.watch(accessibilitySettingsProvider);
    final textDirectionAsync = ref.watch(textDirectionProvider);
    
    return settingsAsync.when(
      data: (settings) => textDirectionAsync.when(
        data: (textDirection) {
          final accessibilityService = AccessibilityService(
            preferences: ref.read(accessibilityServiceProvider).value!._preferences,
          );
          
          // Apply accessibility adjustments
          final adjustedStyle = accessibilityService.getAccessibilityTextStyle(
            style ?? Theme.of(context).textTheme.bodyMedium ?? const TextStyle(),
            textScaleFactor: settings.textScaleFactor,
            fontFamily: settings.fontFamily,
          );
          
          return Semantics(
            label: semanticsLabel ?? text,
            child: Text(
              text,
              style: adjustedStyle,
              textAlign: textAlign,
              maxLines: maxLines,
              overflow: overflow,
              softWrap: softWrap,
              textDirection: textDirection,
            ),
          );
        },
        loading: () => Text(text, style: style),
        error: (_, __) => Text(text, style: style),
      ),
      loading: () => Text(text, style: style),
      error: (_, __) => Text(text, style: style),
    );
  }
}

/// Accessibility-enhanced button widget
class AccessibilityButton extends ConsumerWidget {
  final Widget child;
  final VoidCallback? onPressed;
  final String? semanticsLabel;
  final String? semanticsHint;
  final bool? isEnabled;
  final ButtonStyle? style;
  final AccessibilityHapticType hapticType;
  
  const AccessibilityButton({
    Key? key,
    required this.child,
    this.onPressed,
    this.semanticsLabel,
    this.semanticsHint,
    this.isEnabled,
    this.style,
    this.hapticType = AccessibilityHapticType.light,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settingsAsync = ref.watch(accessibilitySettingsProvider);
    
    return settingsAsync.when(
      data: (settings) {
        return Semantics(
          label: semanticsLabel,
          hint: semanticsHint,
          enabled: isEnabled ?? (onPressed != null),
          button: true,
          child: ElevatedButton(
            onPressed: onPressed != null ? () => _handlePress(ref) : null,
            style: style,
            child: child,
          ),
        );
      },
      loading: () => ElevatedButton(
        onPressed: onPressed,
        style: style,
        child: child,
      ),
      error: (_, __) => ElevatedButton(
        onPressed: onPressed,
        style: style,
        child: child,
      ),
    );
  }
  
  Future<void> _handlePress(WidgetRef ref) async {
    if (onPressed != null) {
      // Provide haptic feedback
      final serviceAsync = ref.read(accessibilityServiceProvider);
      if (serviceAsync.hasValue) {
        await serviceAsync.value!.provideHapticFeedback(hapticType);
      }
      
      onPressed!();
    }
  }
}

/// Accessibility-enhanced list tile
class AccessibilityListTile extends ConsumerWidget {
  final Widget? leading;
  final Widget? title;
  final Widget? subtitle;
  final Widget? trailing;
  final bool isThreeLine;
  final bool? dense;
  final EdgeInsetsGeometry? contentPadding;
  final bool enabled;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final bool selected;
  final Color? focusColor;
  final Color? hoverColor;
  final ListTileControlAffinity? controlAffinity;
  final bool? enableFeedback;
  final String? semanticsLabel;
  final String? semanticsHint;
  
  const AccessibilityListTile({
    Key? key,
    this.leading,
    this.title,
    this.subtitle,
    this.trailing,
    this.isThreeLine = false,
    this.dense,
    this.contentPadding,
    this.enabled = true,
    this.onTap,
    this.onLongPress,
    this.selected = false,
    this.focusColor,
    this.hoverColor,
    this.controlAffinity,
    this.enableFeedback,
    this.semanticsLabel,
    this.semanticsHint,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settingsAsync = ref.watch(accessibilitySettingsProvider);
    final multiLanguageService = ref.watch(multiLanguageServiceProvider);
    
    return settingsAsync.when(
      data: (settings) => multiLanguageService.when(
        data: (languageService) {
          // Get RTL-aware content padding
          final rtlPadding = languageService.getPadding(
            start: contentPadding?.horizontal ?? 16,
            end: contentPadding?.horizontal ?? 16,
            top: contentPadding?.vertical ?? 8,
            bottom: contentPadding?.vertical ?? 8,
          );
          
          return Semantics(
            label: semanticsLabel,
            hint: semanticsHint,
            enabled: enabled,
            selected: selected,
            button: onTap != null,
            child: ListTile(
              leading: leading,
              title: title,
              subtitle: subtitle,
              trailing: trailing,
              isThreeLine: isThreeLine,
              dense: dense,
              contentPadding: rtlPadding,
              enabled: enabled,
              onTap: onTap != null ? () => _handleTap(ref) : null,
              onLongPress: onLongPress != null ? () => _handleLongPress(ref) : null,
              selected: selected,
              focusColor: focusColor,
              hoverColor: hoverColor,
              controlAffinity: controlAffinity,
              enableFeedback: enableFeedback,
            ),
          );
        },
        loading: () => ListTile(
          leading: leading,
          title: title,
          subtitle: subtitle,
          trailing: trailing,
          isThreeLine: isThreeLine,
          dense: dense,
          contentPadding: contentPadding,
          enabled: enabled,
          onTap: onTap,
          onLongPress: onLongPress,
          selected: selected,
          focusColor: focusColor,
          hoverColor: hoverColor,
          controlAffinity: controlAffinity,
          enableFeedback: enableFeedback,
        ),
        error: (_, __) => ListTile(
          leading: leading,
          title: title,
          subtitle: subtitle,
          trailing: trailing,
          isThreeLine: isThreeLine,
          dense: dense,
          contentPadding: contentPadding,
          enabled: enabled,
          onTap: onTap,
          onLongPress: onLongPress,
          selected: selected,
          focusColor: focusColor,
          hoverColor: hoverColor,
          controlAffinity: controlAffinity,
          enableFeedback: enableFeedback,
        ),
      ),
      loading: () => ListTile(
        leading: leading,
        title: title,
        subtitle: subtitle,
        trailing: trailing,
        isThreeLine: isThreeLine,
        dense: dense,
        contentPadding: contentPadding,
        enabled: enabled,
        onTap: onTap,
        onLongPress: onLongPress,
        selected: selected,
        focusColor: focusColor,
        hoverColor: hoverColor,
        controlAffinity: controlAffinity,
        enableFeedback: enableFeedback,
      ),
      error: (_, __) => ListTile(
        leading: leading,
        title: title,
        subtitle: subtitle,
        trailing: trailing,
        isThreeLine: isThreeLine,
        dense: dense,
        contentPadding: contentPadding,
        enabled: enabled,
        onTap: onTap,
        onLongPress: onLongPress,
        selected: selected,
        focusColor: focusColor,
        hoverColor: hoverColor,
        controlAffinity: controlAffinity,
        enableFeedback: enableFeedback,
      ),
    );
  }
  
  Future<void> _handleTap(WidgetRef ref) async {
    if (onTap != null) {
      // Provide haptic feedback
      final serviceAsync = ref.read(accessibilityServiceProvider);
      if (serviceAsync.hasValue) {
        await serviceAsync.value!.provideHapticFeedback(AccessibilityHapticType.selection);
      }
      
      onTap!();
    }
  }
  
  Future<void> _handleLongPress(WidgetRef ref) async {
    if (onLongPress != null) {
      // Provide haptic feedback
      final serviceAsync = ref.read(accessibilityServiceProvider);
      if (serviceAsync.hasValue) {
        await serviceAsync.value!.provideHapticFeedback(AccessibilityHapticType.medium);
      }
      
      onLongPress!();
    }
  }
}

/// Accessibility-enhanced app bar
class AccessibilityAppBar extends ConsumerWidget implements PreferredSizeWidget {
  final Widget? title;
  final List<Widget>? actions;
  final Widget? leading;
  final bool automaticallyImplyLeading;
  final Color? backgroundColor;
  final Color? foregroundColor;
  final IconThemeData? iconTheme;
  final double? elevation;
  final String? semanticsLabel;
  
  const AccessibilityAppBar({
    Key? key,
    this.title,
    this.actions,
    this.leading,
    this.automaticallyImplyLeading = true,
    this.backgroundColor,
    this.foregroundColor,
    this.iconTheme,
    this.elevation,
    this.semanticsLabel,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settingsAsync = ref.watch(accessibilitySettingsProvider);
    final multiLanguageService = ref.watch(multiLanguageServiceProvider);
    
    return settingsAsync.when(
      data: (settings) => multiLanguageService.when(
        data: (languageService) {
          final adjustedTitle = title != null 
              ? languageService.getAppBarTitle(
                  (title as Text?)?.data ?? '',
                )
              : null;
          
          return Semantics(
            label: semanticsLabel,
            container: true,
            child: AppBar(
              title: adjustedTitle ?? title,
              actions: actions,
              leading: leading,
              automaticallyImplyLeading: automaticallyImplyLeading,
              backgroundColor: backgroundColor,
              foregroundColor: foregroundColor,
              iconTheme: iconTheme,
              elevation: elevation,
            ),
          );
        },
        loading: () => AppBar(
          title: title,
          actions: actions,
          leading: leading,
          automaticallyImplyLeading: automaticallyImplyLeading,
          backgroundColor: backgroundColor,
          foregroundColor: foregroundColor,
          iconTheme: iconTheme,
          elevation: elevation,
        ),
        error: (_, __) => AppBar(
          title: title,
          actions: actions,
          leading: leading,
          automaticallyImplyLeading: automaticallyImplyLeading,
          backgroundColor: backgroundColor,
          foregroundColor: foregroundColor,
          iconTheme: iconTheme,
          elevation: elevation,
        ),
      ),
      loading: () => AppBar(
        title: title,
        actions: actions,
        leading: leading,
        automaticallyImplyLeading: automaticallyImplyLeading,
        backgroundColor: backgroundColor,
        foregroundColor: foregroundColor,
        iconTheme: iconTheme,
        elevation: elevation,
      ),
      error: (_, __) => AppBar(
        title: title,
        actions: actions,
        leading: leading,
        automaticallyImplyLeading: automaticallyImplyLeading,
        backgroundColor: backgroundColor,
        foregroundColor: foregroundColor,
        iconTheme: iconTheme,
        elevation: elevation,
      ),
    );
  }
  
  @override
  Size get preferredSize => const Size.fromHeight(kToolbarHeight);
}

/// Accessibility-enhanced container with RTL support
class AccessibilityContainer extends ConsumerWidget {
  final Widget? child;
  final AlignmentGeometry? alignment;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final double? width;
  final double? height;
  final BoxConstraints? constraints;
  final Decoration? decoration;
  final Decoration? foregroundDecoration;
  final Matrix4? transform;
  final AlignmentGeometry? transformAlignment;
  final String? semanticsLabel;
  
  const AccessibilityContainer({
    Key? key,
    this.child,
    this.alignment,
    this.padding,
    this.margin,
    this.width,
    this.height,
    this.constraints,
    this.decoration,
    this.foregroundDecoration,
    this.transform,
    this.transformAlignment,
    this.semanticsLabel,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final multiLanguageService = ref.watch(multiLanguageServiceProvider);
    
    return multiLanguageService.when(
      data: (languageService) {
        // Get RTL-aware alignment
        final rtlAlignment = alignment != null 
            ? languageService.getAlignment(alignment as Alignment)
            : null;
        
        // Get RTL-aware padding
        final rtlPadding = padding != null
            ? EdgeInsets.only(
                left: languageService.isCurrentLanguageRtl() 
                    ? padding!.horizontal / 2
                    : padding!.horizontal / 2,
                right: languageService.isCurrentLanguageRtl() 
                    ? padding!.horizontal / 2
                    : padding!.horizontal / 2,
                top: padding!.vertical / 2,
                bottom: padding!.vertical / 2,
              )
            : null;
        
        // Get RTL-aware margin
        final rtlMargin = margin != null
            ? EdgeInsets.only(
                left: languageService.isCurrentLanguageRtl() 
                    ? margin!.horizontal / 2
                    : margin!.horizontal / 2,
                right: languageService.isCurrentLanguageRtl() 
                    ? margin!.horizontal / 2
                    : margin!.horizontal / 2,
                top: margin!.vertical / 2,
                bottom: margin!.vertical / 2,
              )
            : null;
        
        return Semantics(
          label: semanticsLabel,
          container: semanticsLabel != null,
          child: Container(
            alignment: rtlAlignment,
            padding: rtlPadding,
            margin: rtlMargin,
            width: width,
            height: height,
            constraints: constraints,
            decoration: decoration,
            foregroundDecoration: foregroundDecoration,
            transform: transform,
            transformAlignment: transformAlignment,
            child: child,
          ),
        );
      },
      loading: () => Container(
        alignment: alignment,
        padding: padding,
        margin: margin,
        width: width,
        height: height,
        constraints: constraints,
        decoration: decoration,
        foregroundDecoration: foregroundDecoration,
        transform: transform,
        transformAlignment: transformAlignment,
        child: child,
      ),
      error: (_, __) => Container(
        alignment: alignment,
        padding: padding,
        margin: margin,
        width: width,
        height: height,
        constraints: constraints,
        decoration: decoration,
        foregroundDecoration: foregroundDecoration,
        transform: transform,
        transformAlignment: transformAlignment,
        child: child,
      ),
    );
  }
}

/// Accessibility-enhanced form field
class AccessibilityTextFormField extends ConsumerWidget {
  final TextEditingController? controller;
  final String? initialValue;
  final FocusNode? focusNode;
  final InputDecoration? decoration;
  final TextInputType? keyboardType;
  final TextCapitalization textCapitalization;
  final TextInputAction? textInputAction;
  final TextStyle? style;
  final StrutStyle? strutStyle;
  final TextAlign textAlign;
  final TextAlignVertical? textAlignVertical;
  final bool autofocus;
  final bool readOnly;
  final bool? showCursor;
  final String obscuringCharacter;
  final bool obscureText;
  final bool autocorrect;
  final int? maxLines;
  final int? minLines;
  final bool expands;
  final int? maxLength;
  final ValueChanged<String>? onChanged;
  final VoidCallback? onEditingComplete;
  final ValueChanged<String>? onFieldSubmitted;
  final FormFieldSetter<String>? onSaved;
  final FormFieldValidator<String>? validator;
  final List<TextInputFormatter>? inputFormatters;
  final bool? enabled;
  final String? semanticsLabel;
  final String? semanticsHint;
  
  const AccessibilityTextFormField({
    Key? key,
    this.controller,
    this.initialValue,
    this.focusNode,
    this.decoration,
    this.keyboardType,
    this.textCapitalization = TextCapitalization.none,
    this.textInputAction,
    this.style,
    this.strutStyle,
    this.textAlign = TextAlign.start,
    this.textAlignVertical,
    this.autofocus = false,
    this.readOnly = false,
    this.showCursor,
    this.obscuringCharacter = '•',
    this.obscureText = false,
    this.autocorrect = true,
    this.maxLines = 1,
    this.minLines,
    this.expands = false,
    this.maxLength,
    this.onChanged,
    this.onEditingComplete,
    this.onFieldSubmitted,
    this.onSaved,
    this.validator,
    this.inputFormatters,
    this.enabled,
    this.semanticsLabel,
    this.semanticsHint,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settingsAsync = ref.watch(accessibilitySettingsProvider);
    final textDirectionAsync = ref.watch(textDirectionProvider);
    
    return settingsAsync.when(
      data: (settings) => textDirectionAsync.when(
        data: (textDirection) {
          final accessibilityService = AccessibilityService(
            preferences: ref.read(accessibilityServiceProvider).value!._preferences,
          );
          
          // Apply accessibility adjustments
          final adjustedStyle = accessibilityService.getAccessibilityTextStyle(
            style ?? Theme.of(context).textTheme.bodyMedium ?? const TextStyle(),
            textScaleFactor: settings.textScaleFactor,
            fontFamily: settings.fontFamily,
          );
          
          return Semantics(
            label: semanticsLabel,
            hint: semanticsHint,
            textField: true,
            child: TextFormField(
              controller: controller,
              initialValue: initialValue,
              focusNode: focusNode,
              decoration: decoration,
              keyboardType: keyboardType,
              textCapitalization: textCapitalization,
              textInputAction: textInputAction,
              style: adjustedStyle,
              strutStyle: strutStyle,
              textAlign: textAlign,
              textAlignVertical: textAlignVertical,
              textDirection: textDirection,
              autofocus: autofocus,
              readOnly: readOnly,
              showCursor: showCursor,
              obscuringCharacter: obscuringCharacter,
              obscureText: obscureText,
              autocorrect: autocorrect,
              maxLines: maxLines,
              minLines: minLines,
              expands: expands,
              maxLength: maxLength,
              onChanged: onChanged,
              onEditingComplete: onEditingComplete,
              onFieldSubmitted: onFieldSubmitted,
              onSaved: onSaved,
              validator: validator,
              inputFormatters: inputFormatters,
              enabled: enabled,
            ),
          );
        },
        loading: () => TextFormField(
          controller: controller,
          initialValue: initialValue,
          focusNode: focusNode,
          decoration: decoration,
          keyboardType: keyboardType,
          textCapitalization: textCapitalization,
          textInputAction: textInputAction,
          style: style,
          strutStyle: strutStyle,
          textAlign: textAlign,
          textAlignVertical: textAlignVertical,
          autofocus: autofocus,
          readOnly: readOnly,
          showCursor: showCursor,
          obscuringCharacter: obscuringCharacter,
          obscureText: obscureText,
          autocorrect: autocorrect,
          maxLines: maxLines,
          minLines: minLines,
          expands: expands,
          maxLength: maxLength,
          onChanged: onChanged,
          onEditingComplete: onEditingComplete,
          onFieldSubmitted: onFieldSubmitted,
          onSaved: onSaved,
          validator: validator,
          inputFormatters: inputFormatters,
          enabled: enabled,
        ),
        error: (_, __) => TextFormField(
          controller: controller,
          initialValue: initialValue,
          focusNode: focusNode,
          decoration: decoration,
          keyboardType: keyboardType,
          textCapitalization: textCapitalization,
          textInputAction: textInputAction,
          style: style,
          strutStyle: strutStyle,
          textAlign: textAlign,
          textAlignVertical: textAlignVertical,
          autofocus: autofocus,
          readOnly: readOnly,
          showCursor: showCursor,
          obscuringCharacter: obscuringCharacter,
          obscureText: obscureText,
          autocorrect: autocorrect,
          maxLines: maxLines,
          minLines: minLines,
          expands: expands,
          maxLength: maxLength,
          onChanged: onChanged,
          onEditingComplete: onEditingComplete,
          onFieldSubmitted: onFieldSubmitted,
          onSaved: onSaved,
          validator: validator,
          inputFormatters: inputFormatters,
          enabled: enabled,
        ),
      ),
      loading: () => TextFormField(
        controller: controller,
        initialValue: initialValue,
        focusNode: focusNode,
        decoration: decoration,
        keyboardType: keyboardType,
        textCapitalization: textCapitalization,
        textInputAction: textInputAction,
        style: style,
        strutStyle: strutStyle,
        textAlign: textAlign,
        textAlignVertical: textAlignVertical,
        autofocus: autofocus,
        readOnly: readOnly,
        showCursor: showCursor,
        obscuringCharacter: obscuringCharacter,
        obscureText: obscureText,
        autocorrect: autocorrect,
        maxLines: maxLines,
        minLines: minLines,
        expands: expands,
        maxLength: maxLength,
        onChanged: onChanged,
        onEditingComplete: onEditingComplete,
        onFieldSubmitted: onFieldSubmitted,
        onSaved: onSaved,
        validator: validator,
        inputFormatters: inputFormatters,
        enabled: enabled,
      ),
      error: (_, __) => TextFormField(
        controller: controller,
        initialValue: initialValue,
        focusNode: focusNode,
        decoration: decoration,
        keyboardType: keyboardType,
        textCapitalization: textCapitalization,
        textInputAction: textInputAction,
        style: style,
        strutStyle: strutStyle,
        textAlign: textAlign,
        textAlignVertical: textAlignVertical,
        autofocus: autofocus,
        readOnly: readOnly,
        showCursor: showCursor,
        obscuringCharacter: obscuringCharacter,
        obscureText: obscureText,
        autocorrect: autocorrect,
        maxLines: maxLines,
        minLines: minLines,
        expands: expands,
        maxLength: maxLength,
        onChanged: onChanged,
        onEditingComplete: onEditingComplete,
        onFieldSubmitted: onFieldSubmitted,
        onSaved: onSaved,
        validator: validator,
        inputFormatters: inputFormatters,
        enabled: enabled,
      ),
    );
  }
}