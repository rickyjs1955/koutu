import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/forms/app_text_field.dart';
import 'package:koutu/presentation/widgets/forms/app_dropdown_field.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/screens/image/camera_capture_screen.dart';
import 'package:koutu/core/utils/validators.dart';
import 'package:koutu/core/constants/app_constants.dart';

class AddGarmentScreen extends StatefulWidget {
  final String wardrobeId;

  const AddGarmentScreen({
    super.key,
    required this.wardrobeId,
  });

  @override
  State<AddGarmentScreen> createState() => _AddGarmentScreenState();
}

class _AddGarmentScreenState extends State<AddGarmentScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _brandController = TextEditingController();
  final _materialController = TextEditingController();
  final _priceController = TextEditingController();
  final _notesController = TextEditingController();
  
  String _selectedCategory = AppConstants.garmentCategories.first;
  String? _selectedSubcategory;
  String? _selectedSize;
  final List<String> _selectedColors = [];
  final List<String> _selectedTags = [];
  final List<File> _selectedImages = [];
  DateTime? _purchaseDate;
  bool _isSubmitting = false;

  // Predefined tags
  final List<String> _availableTags = [
    'Favorite',
    'Formal',
    'Casual',
    'Work',
    'Party',
    'Sport',
    'Summer',
    'Winter',
    'Spring',
    'Fall',
    'Vintage',
    'Designer',
    'Comfortable',
    'Statement',
    'Basic',
    'Trendy',
  ];

  @override
  void dispose() {
    _nameController.dispose();
    _brandController.dispose();
    _materialController.dispose();
    _priceController.dispose();
    _notesController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return BlocListener<GarmentBloc, GarmentState>(
      listener: (context, state) {
        if (state is GarmentSuccess) {
          context.pop();
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Garment added successfully!'),
              backgroundColor: AppColors.success,
            ),
          );
        } else if (state is GarmentError) {
          setState(() {
            _isSubmitting = false;
          });
          AppDialog.error(
            context,
            message: state.message,
          );
        }
      },
      child: Scaffold(
        appBar: AppCustomAppBar(
          title: 'Add Garment',
        ),
        body: _isSubmitting
            ? const Center(
                child: AppLoadingIndicator(
                  message: 'Adding garment...',
                ),
              )
            : SingleChildScrollView(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                child: Form(
                  key: _formKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Images section
                      _buildImageSection(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Basic info section
                      _buildBasicInfoSection(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Category section
                      _buildCategorySection(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Details section
                      _buildDetailsSection(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Tags section
                      _buildTagsSection(),
                      const SizedBox(height: AppDimensions.paddingXL),
                      
                      // Submit button
                      SizedBox(
                        width: double.infinity,
                        child: AppButton(
                          text: 'Add Garment',
                          onPressed: _submitGarment,
                          type: AppButtonType.primary,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
      ),
    );
  }

  Widget _buildImageSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Photos',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Text(
          'Add at least one photo of your garment',
          style: AppTextStyles.bodyMedium.copyWith(
            color: AppColors.textSecondary,
          ),
        ),
        const SizedBox(height: AppDimensions.paddingM),
        SizedBox(
          height: 120,
          child: ListView(
            scrollDirection: Axis.horizontal,
            children: [
              // Add photo button
              _buildAddPhotoButton(),
              // Selected images
              ..._selectedImages.map((image) => _buildImageThumbnail(image)),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildAddPhotoButton() {
    return Padding(
      padding: const EdgeInsets.only(right: AppDimensions.paddingS),
      child: InkWell(
        onTap: _selectImages,
        borderRadius: AppDimensions.radiusM,
        child: Container(
          width: 120,
          height: 120,
          decoration: BoxDecoration(
            color: AppColors.backgroundSecondary,
            borderRadius: AppDimensions.radiusM,
            border: Border.all(
              color: AppColors.border,
              width: 2,
              style: BorderStyle.dashed,
            ),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.add_photo_alternate,
                size: 32,
                color: AppColors.textTertiary,
              ),
              const SizedBox(height: AppDimensions.paddingXS),
              Text(
                'Add Photo',
                style: AppTextStyles.caption.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildImageThumbnail(File image) {
    return Padding(
      padding: const EdgeInsets.only(right: AppDimensions.paddingS),
      child: Stack(
        children: [
          Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              borderRadius: AppDimensions.radiusM,
              image: DecorationImage(
                image: FileImage(image),
                fit: BoxFit.cover,
              ),
            ),
          ),
          Positioned(
            top: 4,
            right: 4,
            child: GestureDetector(
              onTap: () => _removeImage(image),
              child: Container(
                padding: const EdgeInsets.all(4),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.close,
                  color: Colors.white,
                  size: 16,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBasicInfoSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Basic Information',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        AppTextField(
          controller: _nameController,
          label: 'Name',
          hint: 'e.g., Blue Denim Jacket',
          validator: Validators.required('Name is required'),
          textCapitalization: TextCapitalization.words,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        AppTextField(
          controller: _brandController,
          label: 'Brand (optional)',
          hint: 'e.g., Nike, Zara, H&M',
          textCapitalization: TextCapitalization.words,
        ),
      ],
    );
  }

  Widget _buildCategorySection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Category',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        AppDropdownField<String>(
          value: _selectedCategory,
          label: 'Category',
          items: AppConstants.garmentCategories
              .map((category) => DropdownMenuItem(
                    value: category,
                    child: Text(category.capitalize()),
                  ))
              .toList(),
          onChanged: (value) {
            setState(() {
              _selectedCategory = value!;
              _selectedSubcategory = null;
            });
          },
        ),
        if (_getSubcategories().isNotEmpty) ...[
          const SizedBox(height: AppDimensions.paddingM),
          AppDropdownField<String>(
            value: _selectedSubcategory,
            label: 'Subcategory',
            items: _getSubcategories()
                .map((subcategory) => DropdownMenuItem(
                      value: subcategory,
                      child: Text(subcategory),
                    ))
                .toList(),
            onChanged: (value) {
              setState(() {
                _selectedSubcategory = value;
              });
            },
          ),
        ],
      ],
    );
  }

  Widget _buildDetailsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Details',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Colors
        _buildColorSelector(),
        const SizedBox(height: AppDimensions.paddingM),
        // Size
        AppDropdownField<String>(
          value: _selectedSize,
          label: 'Size',
          items: _getSizes()
              .map((size) => DropdownMenuItem(
                    value: size,
                    child: Text(size),
                  ))
              .toList(),
          onChanged: (value) {
            setState(() {
              _selectedSize = value;
            });
          },
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Material
        AppTextField(
          controller: _materialController,
          label: 'Material (optional)',
          hint: 'e.g., Cotton, Polyester, Wool',
          textCapitalization: TextCapitalization.words,
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Price
        AppTextField(
          controller: _priceController,
          label: 'Price (optional)',
          hint: '0.00',
          keyboardType: TextInputType.numberWithOptions(decimal: true),
          prefixIcon: const Icon(Icons.attach_money),
        ),
        const SizedBox(height: AppDimensions.paddingM),
        // Purchase date
        _buildPurchaseDateField(),
        const SizedBox(height: AppDimensions.paddingM),
        // Notes
        AppTextField(
          controller: _notesController,
          label: 'Notes (optional)',
          hint: 'Add any additional notes',
          maxLines: 3,
          textCapitalization: TextCapitalization.sentences,
        ),
      ],
    );
  }

  Widget _buildColorSelector() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Colors',
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: AppConstants.colors.entries.map((entry) {
            final isSelected = _selectedColors.contains(entry.key);
            return InkWell(
              onTap: () {
                setState(() {
                  if (isSelected) {
                    _selectedColors.remove(entry.key);
                  } else {
                    _selectedColors.add(entry.key);
                  }
                });
              },
              borderRadius: BorderRadius.circular(24),
              child: Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: entry.value,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected ? AppColors.textPrimary : AppColors.border,
                    width: isSelected ? 3 : 1,
                  ),
                ),
                child: isSelected
                    ? const Icon(
                        Icons.check,
                        color: Colors.white,
                        size: 20,
                      )
                    : null,
              ),
            );
          }).toList(),
        ),
        if (_selectedColors.isEmpty)
          Padding(
            padding: const EdgeInsets.only(top: AppDimensions.paddingS),
            child: Text(
              'Select at least one color',
              style: AppTextStyles.caption.copyWith(
                color: AppColors.error,
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildPurchaseDateField() {
    return InkWell(
      onTap: _selectPurchaseDate,
      child: InputDecorator(
        decoration: InputDecoration(
          labelText: 'Purchase Date (optional)',
          suffixIcon: const Icon(Icons.calendar_today),
          border: OutlineInputBorder(
            borderRadius: AppDimensions.radiusM,
          ),
        ),
        child: Text(
          _purchaseDate != null
              ? '${_purchaseDate!.day}/${_purchaseDate!.month}/${_purchaseDate!.year}'
              : 'Select date',
          style: _purchaseDate != null
              ? AppTextStyles.bodyMedium
              : AppTextStyles.bodyMedium.copyWith(
                  color: AppColors.textTertiary,
                ),
        ),
      ),
    );
  }

  Widget _buildTagsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Tags',
          style: AppTextStyles.h3,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Text(
          'Add tags to help organize and find your garments',
          style: AppTextStyles.bodyMedium.copyWith(
            color: AppColors.textSecondary,
          ),
        ),
        const SizedBox(height: AppDimensions.paddingM),
        Wrap(
          spacing: AppDimensions.paddingS,
          runSpacing: AppDimensions.paddingS,
          children: _availableTags.map((tag) {
            final isSelected = _selectedTags.contains(tag);
            return FilterChip(
              label: Text(tag),
              selected: isSelected,
              onSelected: (selected) {
                setState(() {
                  if (selected) {
                    _selectedTags.add(tag);
                  } else {
                    _selectedTags.remove(tag);
                  }
                });
              },
            );
          }).toList(),
        ),
      ],
    );
  }

  List<String> _getSubcategories() {
    switch (_selectedCategory) {
      case 'tops':
        return ['T-Shirt', 'Shirt', 'Blouse', 'Tank Top', 'Sweater', 'Hoodie', 'Jacket'];
      case 'bottoms':
        return ['Jeans', 'Trousers', 'Shorts', 'Skirt', 'Leggings'];
      case 'dresses':
        return ['Casual Dress', 'Formal Dress', 'Maxi Dress', 'Mini Dress'];
      case 'outerwear':
        return ['Coat', 'Blazer', 'Vest', 'Cardigan'];
      case 'shoes':
        return ['Sneakers', 'Boots', 'Heels', 'Flats', 'Sandals', 'Loafers'];
      case 'accessories':
        return ['Bag', 'Belt', 'Hat', 'Scarf', 'Jewelry', 'Watch', 'Sunglasses'];
      default:
        return [];
    }
  }

  List<String> _getSizes() {
    switch (_selectedCategory) {
      case 'shoes':
        return ['35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45'];
      case 'accessories':
        return ['One Size', 'Small', 'Medium', 'Large'];
      default:
        return ['XXS', 'XS', 'S', 'M', 'L', 'XL', 'XXL', 'XXXL'];
    }
  }

  void _selectImages() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => CameraCaptureScreen(
          allowMultiple: true,
          onImagesSelected: (images) {
            setState(() {
              _selectedImages.addAll(images);
            });
          },
        ),
      ),
    );
  }

  void _removeImage(File image) {
    setState(() {
      _selectedImages.remove(image);
    });
  }

  void _selectPurchaseDate() async {
    final date = await showDatePicker(
      context: context,
      initialDate: _purchaseDate ?? DateTime.now(),
      firstDate: DateTime(2000),
      lastDate: DateTime.now(),
    );
    
    if (date != null) {
      setState(() {
        _purchaseDate = date;
      });
    }
  }

  void _submitGarment() {
    if (!_formKey.currentState!.validate()) {
      return;
    }

    if (_selectedImages.isEmpty) {
      AppDialog.error(
        context,
        message: 'Please add at least one photo',
      );
      return;
    }

    if (_selectedColors.isEmpty) {
      AppDialog.error(
        context,
        message: 'Please select at least one color',
      );
      return;
    }

    setState(() {
      _isSubmitting = true;
    });

    final price = _priceController.text.isNotEmpty
        ? double.tryParse(_priceController.text)
        : null;

    context.read<GarmentBloc>().add(
          CreateGarment(
            wardrobeId: widget.wardrobeId,
            name: _nameController.text.trim(),
            category: _selectedCategory,
            subcategory: _selectedSubcategory,
            brand: _brandController.text.trim().isEmpty
                ? null
                : _brandController.text.trim(),
            colors: _selectedColors,
            size: _selectedSize,
            material: _materialController.text.trim().isEmpty
                ? null
                : _materialController.text.trim(),
            price: price,
            purchaseDate: _purchaseDate,
            tags: _selectedTags,
            notes: _notesController.text.trim().isEmpty
                ? null
                : _notesController.text.trim(),
            imageFiles: _selectedImages,
          ),
        );
  }
}

extension StringExtension on String {
  String capitalize() {
    return "${this[0].toUpperCase()}${substring(1)}";
  }
}