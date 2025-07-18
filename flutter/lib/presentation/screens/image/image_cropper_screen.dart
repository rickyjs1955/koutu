import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/services/image/image_processor.dart';

class ImageCropperScreen extends StatefulWidget {
  final File imageFile;
  final CropAspectRatio? aspectRatio;
  final bool lockAspectRatio;
  final Function(File) onImageCropped;

  const ImageCropperScreen({
    super.key,
    required this.imageFile,
    this.aspectRatio,
    this.lockAspectRatio = false,
    required this.onImageCropped,
  });

  @override
  State<ImageCropperScreen> createState() => _ImageCropperScreenState();
}

class _ImageCropperScreenState extends State<ImageCropperScreen> {
  final GlobalKey _cropKey = GlobalKey();
  bool _isProcessing = false;
  Rect _cropRect = const Rect.fromLTWH(0, 0, 1, 1); // Normalized coordinates
  Size? _imageSize;
  CropAspectRatio? _currentAspectRatio;

  @override
  void initState() {
    super.initState();
    _currentAspectRatio = widget.aspectRatio;
    _loadImage();
  }

  Future<void> _loadImage() async {
    final image = await decodeImageFromList(widget.imageFile.readAsBytesSync());
    setState(() {
      _imageSize = Size(image.width.toDouble(), image.height.toDouble());
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppCustomAppBar(
        title: 'Crop Image',
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            icon: const Icon(Icons.check),
            onPressed: _isProcessing ? null : _cropImage,
          ),
        ],
      ),
      body: _isProcessing
          ? const Center(
              child: AppLoadingIndicator(
                message: 'Processing image...',
                color: Colors.white,
              ),
            )
          : Column(
              children: [
                Expanded(
                  child: _buildCropArea(),
                ),
                _buildControls(),
              ],
            ),
    );
  }

  Widget _buildCropArea() {
    if (_imageSize == null) {
      return const Center(
        child: AppLoadingIndicator(color: Colors.white),
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        return Stack(
          alignment: Alignment.center,
          children: [
            // Original image
            Image.file(
              widget.imageFile,
              fit: BoxFit.contain,
            ),
            // Crop overlay
            CustomPaint(
              size: constraints.biggest,
              painter: CropOverlayPainter(
                cropRect: _cropRect,
                imageSize: _imageSize!,
                aspectRatio: _currentAspectRatio,
              ),
            ),
            // Crop handles
            _buildCropHandles(constraints),
          ],
        );
      },
    );
  }

  Widget _buildCropHandles(BoxConstraints constraints) {
    return GestureDetector(
      onPanStart: _onPanStart,
      onPanUpdate: _onPanUpdate,
      child: Container(
        color: Colors.transparent,
        child: CustomPaint(
          size: constraints.biggest,
          painter: CropHandlePainter(
            cropRect: _cropRect,
            imageSize: _imageSize!,
          ),
        ),
      ),
    );
  }

  Widget _buildControls() {
    return Container(
      color: Colors.black87,
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Aspect ratio options
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: [
                  _buildAspectRatioButton('Free', null),
                  const SizedBox(width: AppDimensions.paddingS),
                  _buildAspectRatioButton('1:1', CropAspectRatio.square),
                  const SizedBox(width: AppDimensions.paddingS),
                  _buildAspectRatioButton('4:3', CropAspectRatio.ratio4x3),
                  const SizedBox(width: AppDimensions.paddingS),
                  _buildAspectRatioButton('16:9', CropAspectRatio.ratio16x9),
                  const SizedBox(width: AppDimensions.paddingS),
                  _buildAspectRatioButton('3:4', CropAspectRatio.ratio3x4),
                  const SizedBox(width: AppDimensions.paddingS),
                  _buildAspectRatioButton('9:16', CropAspectRatio.ratio9x16),
                ],
              ),
            ),
            const SizedBox(height: AppDimensions.paddingM),
            // Action buttons
            Row(
              children: [
                Expanded(
                  child: AppButton(
                    text: 'Reset',
                    onPressed: _resetCrop,
                    type: AppButtonType.secondary,
                    size: AppButtonSize.medium,
                  ),
                ),
                const SizedBox(width: AppDimensions.paddingM),
                Expanded(
                  child: AppButton(
                    text: 'Rotate',
                    onPressed: _rotateImage,
                    type: AppButtonType.secondary,
                    size: AppButtonSize.medium,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAspectRatioButton(String label, CropAspectRatio? ratio) {
    final isSelected = _currentAspectRatio == ratio;
    
    return Material(
      color: isSelected ? AppColors.primary : Colors.transparent,
      borderRadius: AppDimensions.radiusM,
      child: InkWell(
        onTap: widget.lockAspectRatio
            ? null
            : () {
                setState(() {
                  _currentAspectRatio = ratio;
                  _updateCropRect();
                });
              },
        borderRadius: AppDimensions.radiusM,
        child: Container(
          padding: const EdgeInsets.symmetric(
            horizontal: AppDimensions.paddingM,
            vertical: AppDimensions.paddingS,
          ),
          decoration: BoxDecoration(
            border: Border.all(
              color: isSelected ? AppColors.primary : Colors.white54,
            ),
            borderRadius: AppDimensions.radiusM,
          ),
          child: Text(
            label,
            style: AppTextStyles.labelMedium.copyWith(
              color: isSelected ? AppColors.onPrimary : Colors.white,
            ),
          ),
        ),
      ),
    );
  }

  void _onPanStart(DragStartDetails details) {
    // Determine which handle or area is being dragged
  }

  void _onPanUpdate(DragUpdateDetails details) {
    setState(() {
      // Update crop rect based on drag
      final delta = details.delta;
      _cropRect = Rect.fromLTWH(
        (_cropRect.left + delta.dx / context.size!.width).clamp(0.0, 1.0),
        (_cropRect.top + delta.dy / context.size!.height).clamp(0.0, 1.0),
        _cropRect.width,
        _cropRect.height,
      );
    });
  }

  void _updateCropRect() {
    if (_currentAspectRatio == null) return;
    
    // Update crop rect to match aspect ratio
    final aspectRatio = _currentAspectRatio!.ratio;
    final currentRatio = _cropRect.width / _cropRect.height;
    
    if (currentRatio > aspectRatio) {
      // Too wide, adjust width
      final newWidth = _cropRect.height * aspectRatio;
      _cropRect = Rect.fromCenter(
        center: _cropRect.center,
        width: newWidth,
        height: _cropRect.height,
      );
    } else {
      // Too tall, adjust height
      final newHeight = _cropRect.width / aspectRatio;
      _cropRect = Rect.fromCenter(
        center: _cropRect.center,
        width: _cropRect.width,
        height: newHeight,
      );
    }
  }

  void _resetCrop() {
    setState(() {
      _cropRect = const Rect.fromLTWH(0, 0, 1, 1);
      _currentAspectRatio = widget.aspectRatio;
    });
  }

  void _rotateImage() {
    // TODO: Implement image rotation
  }

  Future<void> _cropImage() async {
    setState(() {
      _isProcessing = true;
    });

    try {
      final imageProcessor = ImageProcessor();
      final croppedFile = await imageProcessor.cropImage(
        widget.imageFile,
        _cropRect,
        _imageSize!,
      );
      
      widget.onImageCropped(croppedFile);
      Navigator.pop(context);
    } catch (e) {
      setState(() {
        _isProcessing = false;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to crop image: ${e.toString()}'),
          backgroundColor: Theme.of(context).colorScheme.error,
        ),
      );
    }
  }
}

enum CropAspectRatio {
  square(1.0),
  ratio4x3(4 / 3),
  ratio16x9(16 / 9),
  ratio3x4(3 / 4),
  ratio9x16(9 / 16);

  final double ratio;
  const CropAspectRatio(this.ratio);
}

class CropOverlayPainter extends CustomPainter {
  final Rect cropRect;
  final Size imageSize;
  final CropAspectRatio? aspectRatio;

  CropOverlayPainter({
    required this.cropRect,
    required this.imageSize,
    this.aspectRatio,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.black54
      ..style = PaintingStyle.fill;

    // Draw dark overlay around crop area
    final path = Path()
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height))
      ..addRect(
        Rect.fromLTWH(
          cropRect.left * size.width,
          cropRect.top * size.height,
          cropRect.width * size.width,
          cropRect.height * size.height,
        ),
      )
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(path, paint);

    // Draw crop grid
    final gridPaint = Paint()
      ..color = Colors.white30
      ..strokeWidth = 1;

    final cropRectPixels = Rect.fromLTWH(
      cropRect.left * size.width,
      cropRect.top * size.height,
      cropRect.width * size.width,
      cropRect.height * size.height,
    );

    // Vertical lines
    for (int i = 1; i < 3; i++) {
      final x = cropRectPixels.left + (cropRectPixels.width / 3) * i;
      canvas.drawLine(
        Offset(x, cropRectPixels.top),
        Offset(x, cropRectPixels.bottom),
        gridPaint,
      );
    }

    // Horizontal lines
    for (int i = 1; i < 3; i++) {
      final y = cropRectPixels.top + (cropRectPixels.height / 3) * i;
      canvas.drawLine(
        Offset(cropRectPixels.left, y),
        Offset(cropRectPixels.right, y),
        gridPaint,
      );
    }

    // Draw border
    final borderPaint = Paint()
      ..color = Colors.white
      ..strokeWidth = 2
      ..style = PaintingStyle.stroke;

    canvas.drawRect(cropRectPixels, borderPaint);
  }

  @override
  bool shouldRepaint(CropOverlayPainter oldDelegate) {
    return cropRect != oldDelegate.cropRect ||
        imageSize != oldDelegate.imageSize ||
        aspectRatio != oldDelegate.aspectRatio;
  }
}

class CropHandlePainter extends CustomPainter {
  final Rect cropRect;
  final Size imageSize;

  CropHandlePainter({
    required this.cropRect,
    required this.imageSize,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final handlePaint = Paint()
      ..color = Colors.white
      ..strokeWidth = 3
      ..style = PaintingStyle.stroke;

    final cropRectPixels = Rect.fromLTWH(
      cropRect.left * size.width,
      cropRect.top * size.height,
      cropRect.width * size.width,
      cropRect.height * size.height,
    );

    const handleLength = 20.0;

    // Top-left corner
    canvas.drawLine(
      cropRectPixels.topLeft,
      cropRectPixels.topLeft + const Offset(handleLength, 0),
      handlePaint,
    );
    canvas.drawLine(
      cropRectPixels.topLeft,
      cropRectPixels.topLeft + const Offset(0, handleLength),
      handlePaint,
    );

    // Top-right corner
    canvas.drawLine(
      cropRectPixels.topRight,
      cropRectPixels.topRight + const Offset(-handleLength, 0),
      handlePaint,
    );
    canvas.drawLine(
      cropRectPixels.topRight,
      cropRectPixels.topRight + const Offset(0, handleLength),
      handlePaint,
    );

    // Bottom-left corner
    canvas.drawLine(
      cropRectPixels.bottomLeft,
      cropRectPixels.bottomLeft + const Offset(handleLength, 0),
      handlePaint,
    );
    canvas.drawLine(
      cropRectPixels.bottomLeft,
      cropRectPixels.bottomLeft + const Offset(0, -handleLength),
      handlePaint,
    );

    // Bottom-right corner
    canvas.drawLine(
      cropRectPixels.bottomRight,
      cropRectPixels.bottomRight + const Offset(-handleLength, 0),
      handlePaint,
    );
    canvas.drawLine(
      cropRectPixels.bottomRight,
      cropRectPixels.bottomRight + const Offset(0, -handleLength),
      handlePaint,
    );
  }

  @override
  bool shouldRepaint(CropHandlePainter oldDelegate) {
    return cropRect != oldDelegate.cropRect || imageSize != oldDelegate.imageSize;
  }
}