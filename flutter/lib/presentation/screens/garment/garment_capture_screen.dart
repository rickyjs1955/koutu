import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:image_picker/image_picker.dart';
import 'dart:io';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';
import 'package:koutu/presentation/widgets/polygon/polygon_drawing_widget.dart';
import 'package:koutu/presentation/widgets/common/app_button.dart';
import 'package:go_router/go_router.dart';

class GarmentCaptureScreen extends StatefulWidget {
  const GarmentCaptureScreen({Key? key}) : super(key: key);

  @override
  State<GarmentCaptureScreen> createState() => _GarmentCaptureScreenState();
}

class _GarmentCaptureScreenState extends State<GarmentCaptureScreen> {
  File? _selectedImage;
  final ImagePicker _picker = ImagePicker();
  List<Offset>? _polygonPoints;
  bool _isProcessing = false;
  String _currentStep = 'upload'; // upload, polygon, metadata
  
  // Garment metadata
  String _garmentName = '';
  String _brand = '';
  String _category = 'Top';
  String _color = 'Black';
  String _size = 'M';
  final List<String> _tags = [];
  final TextEditingController _tagController = TextEditingController();

  Future<void> _pickImage(ImageSource source) async {
    try {
      final XFile? image = await _picker.pickImage(
        source: source,
        maxWidth: 1920,
        maxHeight: 1920,
        imageQuality: 85,
      );
      
      if (image != null) {
        setState(() {
          _selectedImage = File(image.path);
          _currentStep = 'polygon';
        });
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error picking image: $e')),
      );
    }
  }

  void _onPolygonComplete(List<Offset> points) {
    setState(() {
      _polygonPoints = points;
    });
  }

  void _proceedToMetadata() {
    if (_polygonPoints == null || _polygonPoints!.length < 3) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please draw a polygon around the garment')),
      );
      return;
    }
    
    setState(() {
      _currentStep = 'metadata';
    });
  }

  Future<void> _saveGarment() async {
    if (_garmentName.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter a garment name')),
      );
      return;
    }

    setState(() {
      _isProcessing = true;
    });

    // Simulate AI processing
    await Future.delayed(const Duration(seconds: 2));

    // TODO: Implement actual save logic with BLoC
    
    setState(() {
      _isProcessing = false;
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Garment saved successfully!'),
          backgroundColor: Colors.green,
        ),
      );
      context.go('/wardrobe');
    }
  }

  void _addTag() {
    final tag = _tagController.text.trim();
    if (tag.isNotEmpty && !_tags.contains(tag)) {
      setState(() {
        _tags.add(tag);
        _tagController.clear();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.backgroundLight,
      appBar: AppBar(
        title: Text(
          'Add Garment',
          style: AppTextStyles.h3,
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: AppColors.textPrimary),
          onPressed: () => context.pop(),
        ),
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    switch (_currentStep) {
      case 'upload':
        return _buildUploadStep();
      case 'polygon':
        return _buildPolygonStep();
      case 'metadata':
        return _buildMetadataStep();
      default:
        return _buildUploadStep();
    }
  }

  Widget _buildUploadStep() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(AppDimensions.paddingLarge),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.cloud_upload_outlined,
              size: 120,
              color: AppColors.primary.withOpacity(0.5),
            ),
            const SizedBox(height: AppDimensions.spacingXLarge),
            Text(
              'Upload Garment Image',
              style: AppTextStyles.h2,
            ),
            const SizedBox(height: AppDimensions.spacingMedium),
            Text(
              'Take a photo or select from gallery',
              style: AppTextStyles.body1.copyWith(color: AppColors.textSecondary),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: AppDimensions.spacingXLarge),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _buildImageSourceButton(
                  icon: Icons.camera_alt,
                  label: 'Camera',
                  onTap: () => _pickImage(ImageSource.camera),
                ),
                const SizedBox(width: AppDimensions.spacingLarge),
                _buildImageSourceButton(
                  icon: Icons.photo_library,
                  label: 'Gallery',
                  onTap: () => _pickImage(ImageSource.gallery),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildImageSourceButton({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      child: Container(
        padding: const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingLarge,
          vertical: AppDimensions.paddingMedium,
        ),
        decoration: BoxDecoration(
          color: AppColors.primary.withOpacity(0.1),
          borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
          border: Border.all(color: AppColors.primary.withOpacity(0.3)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 48, color: AppColors.primary),
            const SizedBox(height: AppDimensions.spacingSmall),
            Text(label, style: AppTextStyles.button),
          ],
        ),
      ),
    );
  }

  Widget _buildPolygonStep() {
    if (_selectedImage == null) return const SizedBox();

    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(AppDimensions.paddingMedium),
          color: AppColors.primary.withOpacity(0.1),
          child: Row(
            children: [
              Icon(Icons.gesture, color: AppColors.primary),
              const SizedBox(width: AppDimensions.spacingSmall),
              Expanded(
                child: Text(
                  'Draw a polygon around the garment',
                  style: AppTextStyles.body2,
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(AppDimensions.paddingMedium),
            decoration: BoxDecoration(
              border: Border.all(color: AppColors.divider),
              borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
              child: Stack(
                fit: StackFit.expand,
                children: [
                  Image.file(
                    _selectedImage!,
                    fit: BoxFit.contain,
                  ),
                  LayoutBuilder(
                    builder: (context, constraints) {
                      return PolygonDrawingWidget(
                        imageSize: Size(constraints.maxWidth, constraints.maxHeight),
                        onPolygonComplete: _onPolygonComplete,
                        polygonColor: AppColors.primary,
                      );
                    },
                  ),
                ],
              ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(AppDimensions.paddingLarge),
          child: AppButton(
            text: 'Continue to Details',
            onPressed: _polygonPoints != null ? _proceedToMetadata : null,
            isFullWidth: true,
          ),
        ),
      ],
    );
  }

  Widget _buildMetadataStep() {
    return Stack(
      children: [
        SingleChildScrollView(
          padding: const EdgeInsets.all(AppDimensions.paddingLarge),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Preview image with polygon
              Container(
                height: 200,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
                  border: Border.all(color: AppColors.divider),
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      Image.file(_selectedImage!, fit: BoxFit.cover),
                      Container(
                        color: Colors.black.withOpacity(0.3),
                      ),
                      const Center(
                        child: Icon(
                          Icons.checkroom,
                          size: 60,
                          color: Colors.white,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: AppDimensions.spacingLarge),
              
              // Garment details form
              Text('Garment Details', style: AppTextStyles.h3),
              const SizedBox(height: AppDimensions.spacingMedium),
              
              _buildTextField(
                label: 'Name',
                hint: 'e.g., Summer Floral Dress',
                onChanged: (value) => _garmentName = value,
              ),
              const SizedBox(height: AppDimensions.spacingMedium),
              
              _buildTextField(
                label: 'Brand',
                hint: 'e.g., Zara, H&M',
                onChanged: (value) => _brand = value,
              ),
              const SizedBox(height: AppDimensions.spacingMedium),
              
              Row(
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: 'Category',
                      value: _category,
                      items: ['Top', 'Bottom', 'Dress', 'Outerwear', 'Shoes', 'Accessories'],
                      onChanged: (value) => setState(() => _category = value!),
                    ),
                  ),
                  const SizedBox(width: AppDimensions.spacingMedium),
                  Expanded(
                    child: _buildDropdown(
                      label: 'Size',
                      value: _size,
                      items: ['XS', 'S', 'M', 'L', 'XL', 'XXL'],
                      onChanged: (value) => setState(() => _size = value!),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.spacingMedium),
              
              _buildDropdown(
                label: 'Primary Color',
                value: _color,
                items: ['Black', 'White', 'Red', 'Blue', 'Green', 'Yellow', 'Pink', 'Gray', 'Brown', 'Multi'],
                onChanged: (value) => setState(() => _color = value!),
              ),
              const SizedBox(height: AppDimensions.spacingMedium),
              
              // Tags
              Text('Tags', style: AppTextStyles.subtitle1),
              const SizedBox(height: AppDimensions.spacingSmall),
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _tagController,
                      decoration: InputDecoration(
                        hintText: 'Add tags (e.g., casual, summer)',
                        hintStyle: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
                        ),
                        contentPadding: const EdgeInsets.symmetric(
                          horizontal: AppDimensions.paddingMedium,
                          vertical: AppDimensions.paddingSmall,
                        ),
                      ),
                      onSubmitted: (_) => _addTag(),
                    ),
                  ),
                  const SizedBox(width: AppDimensions.spacingSmall),
                  IconButton(
                    onPressed: _addTag,
                    icon: const Icon(Icons.add_circle, color: AppColors.primary),
                  ),
                ],
              ),
              const SizedBox(height: AppDimensions.spacingSmall),
              Wrap(
                spacing: AppDimensions.spacingSmall,
                runSpacing: AppDimensions.spacingSmall,
                children: _tags.map((tag) => Chip(
                  label: Text(tag),
                  onDeleted: () => setState(() => _tags.remove(tag)),
                  backgroundColor: AppColors.primary.withOpacity(0.1),
                )).toList(),
              ),
              
              const SizedBox(height: AppDimensions.spacingXLarge * 2),
            ],
          ),
        ),
        
        // Save button
        Positioned(
          bottom: 0,
          left: 0,
          right: 0,
          child: Container(
            padding: const EdgeInsets.all(AppDimensions.paddingLarge),
            decoration: BoxDecoration(
              color: AppColors.backgroundLight,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 10,
                  offset: const Offset(0, -2),
                ),
              ],
            ),
            child: AppButton(
              text: _isProcessing ? 'Processing...' : 'Save Garment',
              onPressed: _isProcessing ? null : _saveGarment,
              isFullWidth: true,
              isLoading: _isProcessing,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTextField({
    required String label,
    required String hint,
    required Function(String) onChanged,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: AppTextStyles.subtitle1),
        const SizedBox(height: AppDimensions.spacingSmall),
        TextField(
          onChanged: onChanged,
          decoration: InputDecoration(
            hintText: hint,
            hintStyle: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
            ),
            contentPadding: const EdgeInsets.symmetric(
              horizontal: AppDimensions.paddingMedium,
              vertical: AppDimensions.paddingMedium,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDropdown({
    required String label,
    required String value,
    required List<String> items,
    required Function(String?) onChanged,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: AppTextStyles.subtitle1),
        const SizedBox(height: AppDimensions.spacingSmall),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingMedium),
          decoration: BoxDecoration(
            border: Border.all(color: AppColors.divider),
            borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<String>(
              value: value,
              isExpanded: true,
              items: items.map((item) => DropdownMenuItem(
                value: item,
                child: Text(item),
              )).toList(),
              onChanged: onChanged,
            ),
          ),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _tagController.dispose();
    super.dispose();
  }
}