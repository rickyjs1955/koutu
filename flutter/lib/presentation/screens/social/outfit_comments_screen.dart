import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/data/models/social/outfit_sharing_model.dart';
import 'package:koutu/services/social/outfit_sharing_service.dart';
import 'package:go_router/go_router.dart';

/// Screen for viewing and managing outfit comments
class OutfitCommentsScreen extends StatefulWidget {
  final String outfitId;
  
  const OutfitCommentsScreen({
    super.key,
    required this.outfitId,
  });

  @override
  State<OutfitCommentsScreen> createState() => _OutfitCommentsScreenState();
}

class _OutfitCommentsScreenState extends State<OutfitCommentsScreen> {
  final ScrollController _scrollController = ScrollController();
  final TextEditingController _commentController = TextEditingController();
  final FocusNode _commentFocusNode = FocusNode();
  
  List<OutfitComment> _comments = [];
  bool _isLoading = false;
  bool _isPosting = false;
  bool _hasMore = true;
  int _currentPage = 0;
  
  String? _replyingToCommentId;
  OutfitComment? _replyingToComment;
  
  @override
  void initState() {
    super.initState();
    _loadComments();
    _scrollController.addListener(_onScroll);
  }
  
  @override
  void dispose() {
    _scrollController.dispose();
    _commentController.dispose();
    _commentFocusNode.dispose();
    super.dispose();
  }
  
  void _onScroll() {
    if (_scrollController.position.pixels >= _scrollController.position.maxScrollExtent - 200) {
      _loadMoreComments();
    }
  }
  
  void _loadComments() async {
    if (_isLoading) return;
    
    setState(() {
      _isLoading = true;
      _currentPage = 0;
    });
    
    try {
      final result = await OutfitSharingService.getOutfitComments(
        widget.outfitId,
        page: _currentPage,
        limit: 20,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (comments) {
          setState(() {
            _comments = comments;
            _hasMore = comments.length >= 20;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _loadMoreComments() async {
    if (_isLoading || !_hasMore) return;
    
    setState(() => _isLoading = true);
    
    try {
      final result = await OutfitSharingService.getOutfitComments(
        widget.outfitId,
        page: _currentPage + 1,
        limit: 20,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Load Failed', failure.message);
        },
        (comments) {
          setState(() {
            _comments.addAll(comments);
            _currentPage++;
            _hasMore = comments.length >= 20;
          });
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _onPostComment() async {
    if (_commentController.text.trim().isEmpty || _isPosting) return;
    
    setState(() => _isPosting = true);
    
    try {
      final result = await OutfitSharingService.addComment(
        widget.outfitId,
        'current_user_id', // In real app, get from auth state
        _commentController.text.trim(),
        parentCommentId: _replyingToCommentId,
      );
      
      result.fold(
        (failure) {
          _showErrorDialog('Post Failed', failure.message);
        },
        (comment) {
          setState(() {
            if (_replyingToCommentId == null) {
              _comments.insert(0, comment);
            } else {
              // Add as reply (in real app, this would be handled differently)
              _comments.insert(0, comment);
            }
            _commentController.clear();
            _replyingToCommentId = null;
            _replyingToComment = null;
          });
          
          _commentFocusNode.unfocus();
        },
      );
    } catch (e) {
      _showErrorDialog('Error', e.toString());
    } finally {
      setState(() => _isPosting = false);
    }
  }
  
  void _onReplyToComment(OutfitComment comment) {
    setState(() {
      _replyingToCommentId = comment.id;
      _replyingToComment = comment;
    });
    _commentFocusNode.requestFocus();
  }
  
  void _onCancelReply() {
    setState(() {
      _replyingToCommentId = null;
      _replyingToComment = null;
    });
    _commentFocusNode.unfocus();
  }
  
  void _onLikeComment(OutfitComment comment) async {
    // Mock like comment
    setState(() {
      final index = _comments.indexWhere((c) => c.id == comment.id);
      if (index != -1) {
        _comments[index] = _comments[index].copyWith(
          likesCount: _comments[index].likesCount + 1,
        );
      }
    });
  }
  
  void _onUserTap(OutfitComment comment) {
    context.push('/social/profile/${comment.userId}');
  }
  
  void _showErrorDialog(String title, String message) {
    AppDialog.error(
      context,
      title: title,
      message: message,
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppCustomAppBar(
        title: 'Comments',
        actions: [
          IconButton(
            icon: const Icon(Icons.sort),
            onPressed: () {
              // TODO: Show sort options
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Comments list
          Expanded(
            child: _isLoading && _comments.isEmpty
                ? const Center(child: AppLoadingIndicator())
                : _comments.isEmpty
                    ? _buildEmptyState()
                    : _buildCommentsList(),
          ),
          
          // Comment input
          _buildCommentInput(),
        ],
      ),
    );
  }
  
  Widget _buildCommentsList() {
    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(vertical: AppDimensions.paddingS),
      itemCount: _comments.length + (_hasMore ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= _comments.length) {
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(AppDimensions.paddingL),
              child: AppLoadingIndicator(),
            ),
          );
        }
        
        final comment = _comments[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 50),
          child: _buildCommentItem(comment),
        );
      },
    );
  }
  
  Widget _buildCommentItem(OutfitComment comment) {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // User avatar
          GestureDetector(
            onTap: () => _onUserTap(comment),
            child: CircleAvatar(
              radius: 18,
              backgroundColor: AppColors.backgroundSecondary,
              backgroundImage: comment.author?.hasProfileImage == true
                  ? CachedNetworkImageProvider(comment.author!.profileImageUrl)
                  : null,
              child: comment.author?.hasProfileImage != true
                  ? Text(
                      comment.author?.displayName.isNotEmpty == true
                          ? comment.author!.displayName[0].toUpperCase()
                          : 'U',
                      style: AppTextStyles.caption,
                    )
                  : null,
            ),
          ),
          
          const SizedBox(width: AppDimensions.paddingS),
          
          // Comment content
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Header
                Row(
                  children: [
                    GestureDetector(
                      onTap: () => _onUserTap(comment),
                      child: Text(
                        comment.author?.displayName ?? 'Unknown User',
                        style: AppTextStyles.labelMedium,
                      ),
                    ),
                    if (comment.author?.isVerified == true) ...[
                      const SizedBox(width: 4),
                      Icon(
                        Icons.verified,
                        color: AppColors.primary,
                        size: 14,
                      ),
                    ],
                    const SizedBox(width: AppDimensions.paddingS),
                    Text(
                      _formatTimeAgo(comment.createdAt),
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                    if (comment.isEdited) ...[
                      const SizedBox(width: 4),
                      Text(
                        '(edited)',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                        ),
                      ),
                    ],
                  ],
                ),
                
                const SizedBox(height: 4),
                
                // Comment text
                Text(
                  comment.content,
                  style: AppTextStyles.bodyMedium,
                ),
                
                const SizedBox(height: AppDimensions.paddingS),
                
                // Actions
                Row(
                  children: [
                    // Like button
                    GestureDetector(
                      onTap: () => _onLikeComment(comment),
                      child: Row(
                        children: [
                          Icon(
                            Icons.favorite_border,
                            size: 16,
                            color: AppColors.textSecondary,
                          ),
                          if (comment.likesCount > 0) ...[
                            const SizedBox(width: 4),
                            Text(
                              comment.likesCount.toString(),
                              style: AppTextStyles.caption.copyWith(
                                color: AppColors.textSecondary,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                    
                    const SizedBox(width: AppDimensions.paddingL),
                    
                    // Reply button
                    GestureDetector(
                      onTap: () => _onReplyToComment(comment),
                      child: Text(
                        'Reply',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.textSecondary,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                    
                    const Spacer(),
                    
                    // More options
                    PopupMenuButton<String>(
                      onSelected: (value) {
                        switch (value) {
                          case 'report':
                            // TODO: Report comment
                            break;
                          case 'block':
                            // TODO: Block user
                            break;
                        }
                      },
                      itemBuilder: (context) => [
                        const PopupMenuItem(
                          value: 'report',
                          child: Text('Report'),
                        ),
                        const PopupMenuItem(
                          value: 'block',
                          child: Text('Block User'),
                        ),
                      ],
                      child: Icon(
                        Icons.more_vert,
                        size: 16,
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
                
                // Replies indicator
                if (comment.repliesCount > 0) ...[
                  const SizedBox(height: AppDimensions.paddingS),
                  GestureDetector(
                    onTap: () {
                      // TODO: Show replies
                    },
                    child: Text(
                      'View ${comment.repliesCount} replies',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.primary,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildCommentInput() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      decoration: BoxDecoration(
        color: AppColors.surface,
        border: Border(
          top: BorderSide(
            color: AppColors.backgroundSecondary,
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // Reply indicator
          if (_replyingToComment != null)
            Container(
              padding: const EdgeInsets.all(AppDimensions.paddingS),
              margin: const EdgeInsets.only(bottom: AppDimensions.paddingS),
              decoration: BoxDecoration(
                color: AppColors.backgroundSecondary,
                borderRadius: BorderRadius.circular(AppDimensions.radiusS),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.reply,
                    size: 16,
                    color: AppColors.textSecondary,
                  ),
                  const SizedBox(width: AppDimensions.paddingS),
                  Text(
                    'Replying to ${_replyingToComment!.author?.displayName ?? 'Unknown'}',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const Spacer(),
                  GestureDetector(
                    onTap: _onCancelReply,
                    child: Icon(
                      Icons.close,
                      size: 16,
                      color: AppColors.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
          
          // Comment input
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _commentController,
                  focusNode: _commentFocusNode,
                  decoration: InputDecoration(
                    hintText: _replyingToComment != null 
                        ? 'Write a reply...' 
                        : 'Add a comment...',
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(AppDimensions.radiusL),
                    ),
                    contentPadding: const EdgeInsets.symmetric(
                      horizontal: AppDimensions.paddingM,
                      vertical: AppDimensions.paddingS,
                    ),
                  ),
                  maxLines: null,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => _onPostComment(),
                ),
              ),
              const SizedBox(width: AppDimensions.paddingS),
              IconButton(
                onPressed: _isPosting ? null : _onPostComment,
                icon: _isPosting
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: AppLoadingIndicator(
                          size: LoadingIndicatorSize.small,
                        ),
                      )
                    : const Icon(Icons.send),
              ),
            ],
          ),
        ],
      ),
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.comment_outlined,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'No Comments Yet',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            'Be the first to comment on this outfit!',
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  String _formatTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h';
    } else if (difference.inDays < 7) {
      return '${difference.inDays}d';
    } else {
      return '${(difference.inDays / 7).floor()}w';
    }
  }
}