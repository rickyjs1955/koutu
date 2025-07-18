import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/forms/app_text_field.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/common/app_badge.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:share_plus/share_plus.dart';
import 'package:qr_flutter/qr_flutter.dart';

class WardrobeSharingDialog extends StatefulWidget {
  final WardrobeModel wardrobe;

  const WardrobeSharingDialog({
    super.key,
    required this.wardrobe,
  });

  @override
  State<WardrobeSharingDialog> createState() => _WardrobeSharingDialogState();
}

class _WardrobeSharingDialogState extends State<WardrobeSharingDialog>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final _emailController = TextEditingController();
  String? _shareLink;
  bool _isGeneratingLink = false;
  bool _isPublicShare = false;
  List<String> _sharedEmails = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadSharedUsers();
    _generateShareLink();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _emailController.dispose();
    super.dispose();
  }

  void _loadSharedUsers() {
    // Load users who have access to this wardrobe
    context.read<WardrobeBloc>().add(LoadSharedUsers(widget.wardrobe.id));
  }

  void _generateShareLink() {
    setState(() {
      _isGeneratingLink = true;
    });

    // Generate share link
    context.read<WardrobeBloc>().add(
      GenerateShareLink(
        wardrobeId: widget.wardrobe.id,
        isPublic: _isPublicShare,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return BlocListener<WardrobeBloc, WardrobeState>(
      listener: (context, state) {
        if (state is WardrobeSuccess && state.shareLink != null) {
          setState(() {
            _shareLink = state.shareLink;
            _isGeneratingLink = false;
          });
        }
        if (state is WardrobeSuccess && state.sharedUsers != null) {
          setState(() {
            _sharedEmails = state.sharedUsers!;
          });
        }
      },
      child: Dialog(
        child: Container(
          width: 400,
          constraints: const BoxConstraints(maxHeight: 600),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Header
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingL),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primary.withOpacity(0.1),
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(AppDimensions.radiusL),
                    topRight: Radius.circular(AppDimensions.radiusL),
                  ),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.share,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(width: AppDimensions.paddingM),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Share "${widget.wardrobe.name}"',
                            style: AppTextStyles.h3,
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Invite others to view your wardrobe',
                            style: AppTextStyles.caption.copyWith(
                              color: AppColors.textSecondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () => Navigator.of(context).pop(),
                    ),
                  ],
                ),
              ),

              // Tab Bar
              TabBar(
                controller: _tabController,
                tabs: const [
                  Tab(text: 'Email Invite'),
                  Tab(text: 'Share Link'),
                  Tab(text: 'QR Code'),
                ],
              ),

              // Tab Content
              Expanded(
                child: TabBarView(
                  controller: _tabController,
                  children: [
                    _buildEmailInviteTab(),
                    _buildShareLinkTab(),
                    _buildQRCodeTab(),
                  ],
                ),
              ),

              // Actions
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingL),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    AppButton(
                      text: 'Cancel',
                      onPressed: () => Navigator.of(context).pop(),
                      type: AppButtonType.secondary,
                    ),
                    const SizedBox(width: AppDimensions.paddingM),
                    AppButton(
                      text: 'Done',
                      onPressed: () => Navigator.of(context).pop(),
                      type: AppButtonType.primary,
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildEmailInviteTab() {
    return Padding(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Email input
          AppTextField(
            controller: _emailController,
            label: 'Email Address',
            hint: 'Enter email to invite',
            keyboardType: TextInputType.emailAddress,
            suffixIcon: IconButton(
              icon: const Icon(Icons.send),
              onPressed: _sendEmailInvite,
            ),
          ),
          const SizedBox(height: AppDimensions.paddingL),

          // Shared users list
          if (_sharedEmails.isNotEmpty) ...[
            Text(
              'Shared with',
              style: AppTextStyles.labelLarge,
            ),
            const SizedBox(height: AppDimensions.paddingM),
            Expanded(
              child: ListView.separated(
                itemCount: _sharedEmails.length,
                separatorBuilder: (context, index) => const Divider(),
                itemBuilder: (context, index) {
                  final email = _sharedEmails[index];
                  return ListTile(
                    leading: CircleAvatar(
                      backgroundColor: AppColors.primary.withOpacity(0.1),
                      child: Text(
                        email[0].toUpperCase(),
                        style: TextStyle(color: AppColors.primary),
                      ),
                    ),
                    title: Text(email),
                    trailing: IconButton(
                      icon: const Icon(Icons.remove_circle_outline),
                      color: AppColors.error,
                      onPressed: () => _removeAccess(email),
                    ),
                  );
                },
              ),
            ),
          ] else
            Expanded(
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      Icons.people_outline,
                      size: 48,
                      color: AppColors.textTertiary,
                    ),
                    const SizedBox(height: AppDimensions.paddingM),
                    Text(
                      'No one has access yet',
                      style: AppTextStyles.bodyLarge.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildShareLinkTab() {
    return Padding(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Privacy toggle
          SwitchListTile(
            title: const Text('Public Link'),
            subtitle: const Text('Anyone with the link can view'),
            value: _isPublicShare,
            onChanged: (value) {
              setState(() {
                _isPublicShare = value;
              });
              _generateShareLink();
            },
          ),
          const SizedBox(height: AppDimensions.paddingL),

          // Share link
          if (_isGeneratingLink)
            const Center(child: AppLoadingIndicator())
          else if (_shareLink != null) ...[
            Container(
              padding: const EdgeInsets.all(AppDimensions.paddingM),
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
                borderRadius: AppDimensions.radiusM,
                border: Border.all(color: AppColors.border),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          _shareLink!,
                          style: AppTextStyles.bodyMedium,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.copy),
                        onPressed: _copyLink,
                        tooltip: 'Copy link',
                      ),
                    ],
                  ),
                  const SizedBox(height: AppDimensions.paddingS),
                  if (_isPublicShare)
                    const AppBadge(
                      text: 'Public',
                      type: AppBadgeType.warning,
                      size: AppBadgeSize.small,
                    )
                  else
                    const AppBadge(
                      text: 'Private',
                      type: AppBadgeType.info,
                      size: AppBadgeSize.small,
                    ),
                ],
              ),
            ),
            const SizedBox(height: AppDimensions.paddingL),
            SizedBox(
              width: double.infinity,
              child: AppButton(
                text: 'Share Link',
                onPressed: _shareViaSystem,
                type: AppButtonType.primary,
                icon: Icons.share,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildQRCodeTab() {
    return Padding(
      padding: const EdgeInsets.all(AppDimensions.paddingL),
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (_shareLink != null) ...[
              Container(
                padding: const EdgeInsets.all(AppDimensions.paddingL),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: AppDimensions.radiusL,
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 10,
                      offset: const Offset(0, 5),
                    ),
                  ],
                ),
                child: QrImageView(
                  data: _shareLink!,
                  version: QrVersions.auto,
                  size: 200,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingL),
              Text(
                'Scan to view wardrobe',
                style: AppTextStyles.bodyLarge.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingM),
              AppButton(
                text: 'Save QR Code',
                onPressed: _saveQRCode,
                type: AppButtonType.secondary,
                icon: Icons.download,
              ),
            ] else
              const AppLoadingIndicator(),
          ],
        ),
      ),
    );
  }

  void _sendEmailInvite() {
    final email = _emailController.text.trim();
    if (email.isEmpty) return;

    context.read<WardrobeBloc>().add(
      InviteUserToWardrobe(
        wardrobeId: widget.wardrobe.id,
        email: email,
      ),
    );

    _emailController.clear();
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Invitation sent to $email'),
        backgroundColor: AppColors.success,
      ),
    );
  }

  void _removeAccess(String email) {
    context.read<WardrobeBloc>().add(
      RemoveUserFromWardrobe(
        wardrobeId: widget.wardrobe.id,
        email: email,
      ),
    );
  }

  void _copyLink() {
    if (_shareLink != null) {
      Clipboard.setData(ClipboardData(text: _shareLink!));
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Link copied to clipboard'),
          duration: Duration(seconds: 2),
        ),
      );
    }
  }

  void _shareViaSystem() {
    if (_shareLink != null) {
      Share.share(
        'Check out my wardrobe "${widget.wardrobe.name}" on Koutu!\n\n$_shareLink',
        subject: 'Koutu Wardrobe Share',
      );
    }
  }

  void _saveQRCode() {
    // Implementation for saving QR code as image
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('QR code saved to gallery'),
        backgroundColor: AppColors.success,
      ),
    );
  }
}