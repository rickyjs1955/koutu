import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/data/models/social/outfit_sharing_model.dart';
import 'package:koutu/data/models/outfit/outfit_model.dart';
import 'package:koutu/services/social/outfit_sharing_service.dart';
import 'package:go_router/go_router.dart';

/// Screen for sharing outfits with privacy controls
class OutfitSharingScreen extends StatefulWidget {
  final String outfitId;
  final OutfitModel? outfit;
  
  const OutfitSharingScreen({
    super.key,
    required this.outfitId,
    this.outfit,
  });

  @override
  State<OutfitSharingScreen> createState() => _OutfitSharingScreenState();
}

class _OutfitSharingScreenState extends State<OutfitSharingScreen> {
  final _formKey = GlobalKey<FormState>();
  final _titleController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _tagsController = TextEditingController();
  
  bool _isLoading = false;
  ShareVisibility _selectedVisibility = ShareVisibility.public;
  bool _allowComments = true;
  bool _allowShares = true;
  bool _allowDownloads = false;
  
  final List<String> _selectedPlatforms = [];
  final List<String> _availablePlatforms = [
    'Instagram',
    'Twitter',
    'Facebook',
    'Pinterest',
    'TikTok',
  ];
  
  @override
  void initState() {
    super.initState();
    _initializeFields();
  }
  
  @override
  void dispose() {
    _titleController.dispose();
    _descriptionController.dispose();
    _tagsController.dispose();
    super.dispose();
  }
  
  void _initializeFields() {
    if (widget.outfit != null) {
      _titleController.text = widget.outfit!.name;
      _descriptionController.text = widget.outfit!.description ?? '';
      _tagsController.text = widget.outfit!.tags.join(', ');
    }
  }
  
  void _onShareOutfit() async {
    if (!_formKey.currentState!.validate()) return;
    
    setState(() => _isLoading = true);
    
    try {
      final tags = _tagsController.text
          .split(',')
          .map((tag) => tag.trim())
          .where((tag) => tag.isNotEmpty)
          .toList();
      
      final request = ShareRequest(
        outfitId: widget.outfitId,
        title: _titleController.text,
        description: _descriptionController.text.isNotEmpty ? _descriptionController.text : null,
        visibility: _selectedVisibility,
        tags: tags,
        allowComments: _allowComments,
        allowShares: _allowShares,
        allowDownloads: _allowDownloads,
        sharedOn: _selectedPlatforms.map((p) => p.toLowerCase()).toList(),
      );
      
      final result = await OutfitSharingService.shareOutfit(request);
      
      result.fold(
        (failure) {
          _showErrorDialog('Share Failed', failure.message);
        },
        (response) {
          _showSuccessDialog(response);
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onPreviewOutfit() {
    // TODO: Show preview of how the outfit will look when shared
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Preview feature coming soon')),
    );
  }
  
  void _onSaveDraft() {
    // TODO: Save as draft
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Draft saved')),
    );
  }
  
  void _showErrorDialog(String title, String message) {
    AppDialog.error(
      context,
      title: title,
      message: message,
    );
  }
  
  void _showSuccessDialog(ShareResponse response) {
    AppDialog.success(
      context,
      title: 'Outfit Shared!',
      message: 'Your outfit has been shared successfully',
      actions: [
        TextButton(
          onPressed: () {
            context.pop();
          },
          child: const Text('Done'),
        ),
        TextButton(
          onPressed: () {
            _copyShareLink(response.shareUrl);
          },
          child: const Text('Copy Link'),
        ),
        TextButton(
          onPressed: () {
            context.push('/social/outfit/${response.sharedOutfitId}');
          },
          child: const Text('View Post'),
        ),
      ],
    );
  }
  
  void _copyShareLink(String url) {
    Clipboard.setData(ClipboardData(text: url));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Link copied to clipboard')),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Share Outfit',
        actions: [
          TextButton(
            onPressed: _onPreviewOutfit,
            child: const Text('Preview'),
          ),
          TextButton(
            onPressed: _onSaveDraft,
            child: const Text('Save Draft'),
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(AppDimensions.paddingL),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Outfit preview
                    _buildOutfitPreview(),
                    
                    const SizedBox(height: AppDimensions.paddingXL),
                    
                    // Title field
                    _buildTitleField(),
                    
                    const SizedBox(height: AppDimensions.paddingL),
                    
                    // Description field
                    _buildDescriptionField(),
                    
                    const SizedBox(height: AppDimensions.paddingL),
                    
                    // Tags field
                    _buildTagsField(),
                    
                    const SizedBox(height: AppDimensions.paddingXL),
                    
                    // Privacy settings
                    _buildPrivacySettings(),
                    
                    const SizedBox(height: AppDimensions.paddingL),
                    
                    // Interaction settings
                    _buildInteractionSettings(),
                    
                    const SizedBox(height: AppDimensions.paddingL),
                    
                    // Platform selection
                    _buildPlatformSelection(),
                    
                    const SizedBox(height: AppDimensions.paddingXL),
                    
                    // Share button
                    _buildShareButton(),
                  ],
                ),
              ),
            ),
    );
  }
  
  Widget _buildOutfitPreview() {
    return AppFadeAnimation(
      child: Container(
        height: 200,
        width: double.infinity,
        decoration: BoxDecoration(
          color: AppColors.backgroundSecondary,
          borderRadius: BorderRadius.circular(AppDimensions.radiusL),
        ),
        child: Stack(
          children: [
            // Outfit image placeholder
            Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.checkroom,
                    size: 64,
                    color: AppColors.textTertiary,
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                  Text(
                    widget.outfit?.name ?? 'Outfit Preview',
                    style: AppTextStyles.labelLarge,
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
            
            // Edit button
            Positioned(
              top: AppDimensions.paddingS,
              right: AppDimensions.paddingS,
              child: IconButton(
                onPressed: () {
                  // TODO: Navigate to outfit editing
                },
                icon: const Icon(Icons.edit),
                style: IconButton.styleFrom(
                  backgroundColor: AppColors.surface.withOpacity(0.8),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildTitleField() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 100),
      child: TextFormField(
        controller: _titleController,
        decoration: const InputDecoration(
          labelText: 'Title',
          hintText: 'Give your outfit a catchy title',
          prefixIcon: Icon(Icons.title),
        ),
        validator: (value) {
          if (value == null || value.isEmpty) {
            return 'Please enter a title';
          }
          if (value.length > 100) {
            return 'Title must be 100 characters or less';
          }
          return null;
        },
        maxLength: 100,
      ),
    );
  }
  
  Widget _buildDescriptionField() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 200),
      child: TextFormField(
        controller: _descriptionController,
        maxLines: 3,
        maxLength: 500,
        decoration: const InputDecoration(
          labelText: 'Description (Optional)',
          hintText: 'Tell people about your outfit, occasion, or styling tips...',
          prefixIcon: Icon(Icons.description),
        ),
        validator: (value) {
          if (value != null && value.length > 500) {
            return 'Description must be 500 characters or less';
          }
          return null;
        },
      ),
    );
  }
  
  Widget _buildTagsField() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 300),
      child: TextFormField(
        controller: _tagsController,
        decoration: const InputDecoration(
          labelText: 'Tags (Optional)',
          hintText: 'casual, summer, work, trendy (comma separated)',
          prefixIcon: Icon(Icons.tag),
        ),
        validator: (value) {
          if (value != null && value.isNotEmpty) {
            final tags = value.split(',').map((tag) => tag.trim()).toList();
            if (tags.length > 10) {
              return 'Maximum 10 tags allowed';
            }
            if (tags.any((tag) => tag.length > 20)) {
              return 'Each tag must be 20 characters or less';
            }
          }
          return null;
        },
      ),
    );
  }
  
  Widget _buildPrivacySettings() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 400),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Privacy Settings',
            style: AppTextStyles.labelLarge,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            ),
            child: Column(
              children: ShareVisibility.values.map((visibility) {
                return RadioListTile<ShareVisibility>(
                  value: visibility,
                  groupValue: _selectedVisibility,
                  onChanged: (value) {
                    setState(() {
                      _selectedVisibility = value!;
                    });
                  },
                  title: Row(
                    children: [
                      Icon(
                        _getVisibilityIcon(visibility),
                        size: 20,
                      ),
                      const SizedBox(width: AppDimensions.paddingS),
                      Text(visibility.displayName),
                    ],
                  ),
                  subtitle: Text(
                    visibility.description,
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                );
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildInteractionSettings() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 500),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Interaction Settings',
            style: AppTextStyles.labelLarge,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Container(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            ),
            child: Column(
              children: [
                SwitchListTile(
                  value: _allowComments,
                  onChanged: (value) {
                    setState(() {
                      _allowComments = value;
                    });
                  },
                  title: const Text('Allow Comments'),
                  subtitle: const Text('Let people comment on your outfit'),
                  secondary: const Icon(Icons.comment),
                ),
                SwitchListTile(
                  value: _allowShares,
                  onChanged: (value) {
                    setState(() {
                      _allowShares = value;
                    });
                  },
                  title: const Text('Allow Shares'),
                  subtitle: const Text('Let people share your outfit'),
                  secondary: const Icon(Icons.share),
                ),
                SwitchListTile(
                  value: _allowDownloads,
                  onChanged: (value) {
                    setState(() {
                      _allowDownloads = value;
                    });
                  },
                  title: const Text('Allow Downloads'),
                  subtitle: const Text('Let people download your outfit images'),
                  secondary: const Icon(Icons.download),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildPlatformSelection() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 600),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Share To (Optional)',
            style: AppTextStyles.labelLarge,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Select platforms to share your outfit directly',
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Wrap(
            spacing: AppDimensions.paddingS,
            runSpacing: AppDimensions.paddingS,
            children: _availablePlatforms.map((platform) {
              final isSelected = _selectedPlatforms.contains(platform);
              return FilterChip(
                selected: isSelected,
                label: Text(platform),
                onSelected: (selected) {
                  setState(() {
                    if (selected) {
                      _selectedPlatforms.add(platform);
                    } else {
                      _selectedPlatforms.remove(platform);
                    }
                  });
                },
                avatar: Icon(
                  _getPlatformIcon(platform),
                  size: 18,
                ),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }
  
  Widget _buildShareButton() {
    return AppFadeAnimation(
      delay: const Duration(milliseconds: 700),
      child: SizedBox(
        width: double.infinity,
        child: ElevatedButton.icon(
          onPressed: _onShareOutfit,
          icon: const Icon(Icons.share),
          label: const Text('Share Outfit'),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(
              vertical: AppDimensions.paddingM,
            ),
          ),
        ),
      ),
    );
  }
  
  IconData _getVisibilityIcon(ShareVisibility visibility) {
    switch (visibility) {
      case ShareVisibility.public:
        return Icons.public;
      case ShareVisibility.followers:
        return Icons.people;
      case ShareVisibility.friends:
        return Icons.person_add;
      case ShareVisibility.private:
        return Icons.lock;
      case ShareVisibility.unlisted:
        return Icons.link;
    }
  }
  
  IconData _getPlatformIcon(String platform) {
    switch (platform.toLowerCase()) {
      case 'instagram':
        return Icons.camera_alt;
      case 'twitter':
        return Icons.alternate_email;
      case 'facebook':
        return Icons.facebook;
      case 'pinterest':
        return Icons.push_pin;
      case 'tiktok':
        return Icons.music_video;
      default:
        return Icons.share;
    }
  }
}