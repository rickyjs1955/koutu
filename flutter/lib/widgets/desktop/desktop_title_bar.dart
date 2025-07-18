import 'package:flutter/material.dart';

/// Desktop title bar with window controls
class DesktopTitleBar extends StatelessWidget {
  final String title;
  final VoidCallback? onMinimize;
  final VoidCallback? onMaximize;
  final VoidCallback? onClose;

  const DesktopTitleBar({
    Key? key,
    required this.title,
    this.onMinimize,
    this.onMaximize,
    this.onClose,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Container(
      height: 40,
      decoration: BoxDecoration(
        color: colorScheme.surface,
        border: Border(
          bottom: BorderSide(
            color: colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Title
          Expanded(
            child: GestureDetector(
              // Allow dragging the window
              onPanStart: (details) {
                // TODO: Start window drag
              },
              onPanUpdate: (details) {
                // TODO: Update window position
              },
              child: Container(
                padding: const EdgeInsets.only(left: 16),
                alignment: Alignment.centerLeft,
                child: Text(
                  title,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    fontWeight: FontWeight.w500,
                    color: colorScheme.onSurface,
                  ),
                ),
              ),
            ),
          ),
          
          // Window controls
          Row(
            children: [
              // Minimize
              _WindowControlButton(
                icon: Icons.minimize,
                onPressed: onMinimize,
                color: colorScheme.onSurfaceVariant,
              ),
              
              // Maximize
              _WindowControlButton(
                icon: Icons.crop_square,
                onPressed: onMaximize,
                color: colorScheme.onSurfaceVariant,
              ),
              
              // Close
              _WindowControlButton(
                icon: Icons.close,
                onPressed: onClose,
                color: Colors.red,
                hoverColor: Colors.red,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _WindowControlButton extends StatefulWidget {
  final IconData icon;
  final VoidCallback? onPressed;
  final Color color;
  final Color? hoverColor;

  const _WindowControlButton({
    Key? key,
    required this.icon,
    this.onPressed,
    required this.color,
    this.hoverColor,
  }) : super(key: key);

  @override
  State<_WindowControlButton> createState() => _WindowControlButtonState();
}

class _WindowControlButtonState extends State<_WindowControlButton> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return MouseRegion(
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: GestureDetector(
        onTap: widget.onPressed,
        child: Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            color: _isHovered
                ? (widget.hoverColor ?? colorScheme.surfaceVariant)
                : Colors.transparent,
          ),
          child: Icon(
            widget.icon,
            size: 16,
            color: _isHovered && widget.hoverColor != null
                ? Colors.white
                : widget.color,
          ),
        ),
      ),
    );
  }
}