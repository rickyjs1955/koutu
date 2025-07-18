import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/forms/app_text_field.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/screens/image/camera_capture_screen.dart';
import 'package:koutu/core/utils/validators.dart';
import 'package:cached_network_image/cached_network_image.dart';

class CreateWardrobeScreen extends StatefulWidget {
  const CreateWardrobeScreen({super.key});

  @override
  State<CreateWardrobeScreen> createState() => _CreateWardrobeScreenState();
}

class _CreateWardrobeScreenState extends State<CreateWardrobeScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _descriptionController = TextEditingController();
  
  String? _selectedColorTheme;
  String? _selectedIcon;
  File? _selectedImage;
  bool _isDefault = false;
  bool _isShared = false;
  bool _isSubmitting = false;

  final List<(String, Color)> _colorThemes = [
    ('blue', Colors.blue),
    ('green', Colors.green),
    ('purple', Colors.purple),
    ('pink', Colors.pink),
    ('orange', Colors.orange),
    ('teal', Colors.teal),
    ('indigo', Colors.indigo),
    ('amber', Colors.amber),
  ];

  final List<(String, IconData)> _icons = [
    ('wardrobe', Icons.checkroom),
    ('hanger', Icons.dry_cleaning),
    ('shirt', Icons.checkroom_outlined),
    ('dress', Icons.woman),
    ('suit', Icons.man),
    ('casual', Icons.weekend),
    ('sport', Icons.sports),
    ('formal', Icons.business_center),
  ];

  @override
  void dispose() {
    _nameController.dispose();
    _descriptionController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return BlocListener<WardrobeBloc, WardrobeState>(
      listener: (context, state) {
        if (state is WardrobeSuccess) {
          context.pop();
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Wardrobe created successfully!'),
              backgroundColor: AppColors.success,
            ),
          );
        } else if (state is WardrobeError) {
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
          title: 'Create Wardrobe',
        ),
        body: _isSubmitting
            ? const Center(
                child: AppLoadingIndicator(
                  message: 'Creating wardrobe...',
                ),
              )
            : SingleChildScrollView(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                child: Form(
                  key: _formKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Image selection
                      _buildImageSelector(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Name field
                      AppTextField(
                        controller: _nameController,
                        label: 'Wardrobe Name',
                        hint: 'e.g., Summer Collection, Work Attire',
                        validator: Validators.required('Name is required'),
                        textCapitalization: TextCapitalization.words,
                      ),
                      const SizedBox(height: AppDimensions.paddingM),
                      
                      // Description field
                      AppTextField(
                        controller: _descriptionController,
                        label: 'Description (optional)',
                        hint: 'Add a description for your wardrobe',
                        maxLines: 3,
                        textCapitalization: TextCapitalization.sentences,
                      ),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Color theme selection
                      Text(
                        'Color Theme',
                        style: AppTextStyles.labelLarge,
                      ),
                      const SizedBox(height: AppDimensions.paddingS),
                      _buildColorThemeSelector(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Icon selection
                      Text(
                        'Icon',
                        style: AppTextStyles.labelLarge,
                      ),
                      const SizedBox(height: AppDimensions.paddingS),
                      _buildIconSelector(),
                      const SizedBox(height: AppDimensions.paddingL),
                      
                      // Settings
                      _buildSettings(),
                      const SizedBox(height: AppDimensions.paddingXL),
                      
                      // Create button
                      SizedBox(
                        width: double.infinity,
                        child: AppButton(
                          text: 'Create Wardrobe',
                          onPressed: _createWardrobe,
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

  Widget _buildImageSelector() {
    return GestureDetector(
      onTap: _selectImage,
      child: Container(
        height: 200,
        width: double.infinity,
        decoration: BoxDecoration(
          color: AppColors.backgroundSecondary,
          borderRadius: AppDimensions.radiusL,
          border: Border.all(
            color: AppColors.border,
            width: 2,
          ),
        ),
        child: _selectedImage != null
            ? ClipRRect(
                borderRadius: AppDimensions.radiusL,
                child: Image.file(
                  _selectedImage!,
                  fit: BoxFit.cover,
                ),
              )
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.add_photo_alternate,
                    size: 48,
                    color: AppColors.textTertiary,
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                  Text(
                    'Add Cover Image',
                    style: AppTextStyles.bodyLarge.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Optional',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textTertiary,
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildColorThemeSelector() {
    return Wrap(
      spacing: AppDimensions.paddingS,
      runSpacing: AppDimensions.paddingS,
      children: _colorThemes.map((theme) {
        final isSelected = _selectedColorTheme == theme.$1;
        return InkWell(
          onTap: () {
            setState(() {
              _selectedColorTheme = theme.$1;
            });
          },
          borderRadius: BorderRadius.circular(24),
          child: Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: theme.$2,
              shape: BoxShape.circle,
              border: Border.all(
                color: isSelected ? AppColors.textPrimary : Colors.transparent,
                width: 3,
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
    );
  }

  Widget _buildIconSelector() {
    return Wrap(
      spacing: AppDimensions.paddingS,
      runSpacing: AppDimensions.paddingS,
      children: _icons.map((icon) {
        final isSelected = _selectedIcon == icon.$1;
        return InkWell(
          onTap: () {
            setState(() {
              _selectedIcon = icon.$1;
            });
          },
          borderRadius: AppDimensions.radiusM,
          child: Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: isSelected
                  ? Theme.of(context).colorScheme.primary
                  : AppColors.backgroundSecondary,
              borderRadius: AppDimensions.radiusM,
              border: Border.all(
                color: isSelected
                    ? Theme.of(context).colorScheme.primary
                    : AppColors.border,
              ),
            ),
            child: Icon(
              icon.$2,
              color: isSelected ? Colors.white : AppColors.textSecondary,
            ),
          ),
        );
      }).toList(),
    );
  }

  Widget _buildSettings() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Settings',
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        SwitchListTile(
          title: const Text('Set as default wardrobe'),
          subtitle: const Text('New items will be added here by default'),
          value: _isDefault,
          onChanged: (value) {
            setState(() {
              _isDefault = value;
            });
          },
          contentPadding: EdgeInsets.zero,
        ),
        SwitchListTile(
          title: const Text('Share with others'),
          subtitle: const Text('Allow others to view this wardrobe'),
          value: _isShared,
          onChanged: (value) {
            setState(() {
              _isShared = value;
            });
          },
          contentPadding: EdgeInsets.zero,
        ),
      ],
    );
  }

  void _selectImage() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => CameraCaptureScreen(
          onImagesSelected: (images) {
            if (images.isNotEmpty) {
              setState(() {
                _selectedImage = images.first;
              });
            }
          },
        ),
      ),
    );
  }

  void _createWardrobe() {
    if (!_formKey.currentState!.validate()) {
      return;
    }

    setState(() {
      _isSubmitting = true;
    });

    context.read<WardrobeBloc>().add(
          CreateWardrobe(
            name: _nameController.text.trim(),
            description: _descriptionController.text.trim().isEmpty
                ? null
                : _descriptionController.text.trim(),
            imageFile: _selectedImage,
            colorTheme: _selectedColorTheme,
            iconName: _selectedIcon,
            isDefault: _isDefault,
            isShared: _isShared,
          ),
        );
  }
}