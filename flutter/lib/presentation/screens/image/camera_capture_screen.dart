import 'dart:io';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';

class CameraCaptureScreen extends StatefulWidget {
  final bool allowMultiple;
  final int? maxImages;
  final Function(List<File>) onImagesSelected;

  const CameraCaptureScreen({
    super.key,
    this.allowMultiple = false,
    this.maxImages,
    required this.onImagesSelected,
  });

  @override
  State<CameraCaptureScreen> createState() => _CameraCaptureScreenState();
}

class _CameraCaptureScreenState extends State<CameraCaptureScreen> {
  final ImagePicker _picker = ImagePicker();
  final List<File> _selectedImages = [];
  bool _isLoading = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Capture Photo',
        actions: [
          if (_selectedImages.isNotEmpty)
            TextButton(
              onPressed: _onDone,
              child: Text(
                'Done (${_selectedImages.length})',
                style: AppTextStyles.labelMedium.copyWith(
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
            ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(
        child: AppLoadingIndicator(
          message: 'Processing image...',
        ),
      );
    }

    if (_error != null) {
      return AppErrorWidget(
        errorType: ErrorType.generic,
        message: _error,
        onRetry: () {
          setState(() {
            _error = null;
          });
        },
      );
    }

    if (_selectedImages.isEmpty) {
      return _buildCaptureOptions();
    }

    return _buildImagePreview();
  }

  Widget _buildCaptureOptions() {
    return Padding(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Icon(
            Icons.camera_alt,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Choose an option to add photos',
            style: AppTextStyles.h3,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: AppDimensions.paddingXL),
          AppButton(
            text: 'Take Photo',
            onPressed: _takePhoto,
            type: AppButtonType.primary,
            prefixIcon: const Icon(Icons.camera_alt),
          ),
          const SizedBox(height: AppDimensions.paddingM),
          AppButton(
            text: 'Choose from Gallery',
            onPressed: _pickFromGallery,
            type: AppButtonType.secondary,
            prefixIcon: const Icon(Icons.photo_library),
          ),
          if (widget.allowMultiple) ...[
            const SizedBox(height: AppDimensions.paddingM),
            Text(
              'You can select up to ${widget.maxImages ?? 'unlimited'} images',
              style: AppTextStyles.caption.copyWith(
                color: AppColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildImagePreview() {
    return Column(
      children: [
        Expanded(
          child: GridView.builder(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 2,
              crossAxisSpacing: AppDimensions.paddingM,
              mainAxisSpacing: AppDimensions.paddingM,
              childAspectRatio: 0.75,
            ),
            itemCount: _selectedImages.length,
            itemBuilder: (context, index) {
              return _buildImageTile(_selectedImages[index], index);
            },
          ),
        ),
        if (widget.allowMultiple &&
            (widget.maxImages == null ||
                _selectedImages.length < widget.maxImages!)) ...[
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: Row(
              children: [
                Expanded(
                  child: AppButton(
                    text: 'Add More',
                    onPressed: _addMoreImages,
                    type: AppButtonType.secondary,
                    size: AppButtonSize.medium,
                    prefixIcon: const Icon(Icons.add_photo_alternate),
                  ),
                ),
                const SizedBox(width: AppDimensions.paddingM),
                Expanded(
                  child: AppButton(
                    text: 'Done',
                    onPressed: _onDone,
                    type: AppButtonType.primary,
                    size: AppButtonSize.medium,
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildImageTile(File image, int index) {
    return Stack(
      fit: StackFit.expand,
      children: [
        ClipRRect(
          borderRadius: AppDimensions.radiusL,
          child: Image.file(
            image,
            fit: BoxFit.cover,
          ),
        ),
        Positioned(
          top: AppDimensions.paddingS,
          right: AppDimensions.paddingS,
          child: Material(
            color: Colors.black54,
            borderRadius: BorderRadius.circular(20),
            child: InkWell(
              onTap: () => _removeImage(index),
              borderRadius: BorderRadius.circular(20),
              child: const Padding(
                padding: EdgeInsets.all(AppDimensions.paddingS),
                child: Icon(
                  Icons.close,
                  color: Colors.white,
                  size: 20,
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Future<void> _takePhoto() async {
    try {
      setState(() {
        _isLoading = true;
        _error = null;
      });

      final XFile? photo = await _picker.pickImage(
        source: ImageSource.camera,
        imageQuality: 90,
      );

      if (photo != null) {
        final file = File(photo.path);
        setState(() {
          _selectedImages.add(file);
          _isLoading = false;
        });

        if (!widget.allowMultiple) {
          _onDone();
        }
      } else {
        setState(() {
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _error = 'Failed to capture photo: ${e.toString()}';
      });
    }
  }

  Future<void> _pickFromGallery() async {
    try {
      setState(() {
        _isLoading = true;
        _error = null;
      });

      if (widget.allowMultiple) {
        final List<XFile> images = await _picker.pickMultiImage(
          imageQuality: 90,
        );

        if (images.isNotEmpty) {
          final files = images.map((image) => File(image.path)).toList();
          
          if (widget.maxImages != null &&
              _selectedImages.length + files.length > widget.maxImages!) {
            await AppDialog.alert(
              context,
              title: 'Too Many Images',
              message:
                  'You can only select up to ${widget.maxImages} images. Please remove some images first.',
            );
            setState(() {
              _isLoading = false;
            });
            return;
          }

          setState(() {
            _selectedImages.addAll(files);
            _isLoading = false;
          });
        } else {
          setState(() {
            _isLoading = false;
          });
        }
      } else {
        final XFile? image = await _picker.pickImage(
          source: ImageSource.gallery,
          imageQuality: 90,
        );

        if (image != null) {
          final file = File(image.path);
          setState(() {
            _selectedImages.add(file);
            _isLoading = false;
          });
          _onDone();
        } else {
          setState(() {
            _isLoading = false;
          });
        }
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
        _error = 'Failed to pick images: ${e.toString()}';
      });
    }
  }

  void _addMoreImages() {
    showModalBottomSheet(
      context: context,
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.camera_alt),
                title: const Text('Take Photo'),
                onTap: () {
                  Navigator.pop(context);
                  _takePhoto();
                },
              ),
              ListTile(
                leading: const Icon(Icons.photo_library),
                title: const Text('Choose from Gallery'),
                onTap: () {
                  Navigator.pop(context);
                  _pickFromGallery();
                },
              ),
            ],
          ),
        );
      },
    );
  }

  void _removeImage(int index) {
    setState(() {
      _selectedImages.removeAt(index);
    });
  }

  void _onDone() {
    if (_selectedImages.isNotEmpty) {
      widget.onImagesSelected(_selectedImages);
      Navigator.pop(context);
    }
  }
}