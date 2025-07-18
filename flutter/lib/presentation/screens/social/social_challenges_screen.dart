import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:go_router/go_router.dart';

/// Model for style challenges
class StyleChallenge {
  final String id;
  final String title;
  final String description;
  final String imageUrl;
  final DateTime startDate;
  final DateTime endDate;
  final int participantCount;
  final int submissionCount;
  final List<String> rules;
  final String prize;
  final bool isActive;
  final bool isJoined;
  final String difficulty;
  final List<String> tags;

  const StyleChallenge({
    required this.id,
    required this.title,
    required this.description,
    required this.imageUrl,
    required this.startDate,
    required this.endDate,
    required this.participantCount,
    required this.submissionCount,
    required this.rules,
    required this.prize,
    required this.isActive,
    required this.isJoined,
    required this.difficulty,
    required this.tags,
  });

  Duration get timeLeft => endDate.difference(DateTime.now());
  bool get isExpired => DateTime.now().isAfter(endDate);
  bool get isUpcoming => DateTime.now().isBefore(startDate);
}

/// Screen for social challenges and style competitions
class SocialChallengesScreen extends StatefulWidget {
  const SocialChallengesScreen({super.key});

  @override
  State<SocialChallengesScreen> createState() => _SocialChallengesScreenState();
}

class _SocialChallengesScreenState extends State<SocialChallengesScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  
  List<StyleChallenge> _activeChallenges = [];
  List<StyleChallenge> _upcomingChallenges = [];
  List<StyleChallenge> _myChallenges = [];
  
  bool _isLoading = true;
  
  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadChallenges();
  }
  
  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }
  
  void _loadChallenges() async {
    setState(() => _isLoading = true);
    
    try {
      // Mock loading challenges
      await Future.delayed(const Duration(seconds: 1));
      
      setState(() {
        _activeChallenges = _generateMockChallenges(isActive: true);
        _upcomingChallenges = _generateMockChallenges(isUpcoming: true);
        _myChallenges = _generateMockChallenges(isJoined: true);
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      _showErrorDialog('Error', 'Failed to load challenges');
    }
  }
  
  List<StyleChallenge> _generateMockChallenges({
    bool isActive = false,
    bool isUpcoming = false,
    bool isJoined = false,
  }) {
    final challenges = [
      StyleChallenge(
        id: 'challenge_1',
        title: 'Minimalist Monday',
        description: 'Create a stunning look using only 3 colors and clean lines. Show us how less can be more!',
        imageUrl: 'https://example.com/minimalist.jpg',
        startDate: DateTime.now().subtract(const Duration(days: 1)),
        endDate: DateTime.now().add(const Duration(days: 6)),
        participantCount: 1247,
        submissionCount: 892,
        rules: [
          'Use maximum 3 colors',
          'Clean, simple lines',
          'No patterns or prints',
          'Include at least one neutral color',
        ],
        prize: 'Featured on our main page + \$100 gift card',
        isActive: isActive,
        isJoined: isJoined,
        difficulty: 'Medium',
        tags: ['minimalist', 'clean', 'simple'],
      ),
      StyleChallenge(
        id: 'challenge_2',
        title: 'Vintage Vibes',
        description: 'Channel your inner retro fashionista with authentic vintage pieces or vintage-inspired looks.',
        imageUrl: 'https://example.com/vintage.jpg',
        startDate: DateTime.now().add(const Duration(days: 3)),
        endDate: DateTime.now().add(const Duration(days: 10)),
        participantCount: 856,
        submissionCount: 0,
        rules: [
          'Include at least one vintage piece',
          'Decade-appropriate styling',
          'Share the story behind your look',
          'No modern accessories',
        ],
        prize: 'Vintage clothing shopping spree worth \$250',
        isActive: !isUpcoming,
        isJoined: isJoined,
        difficulty: 'Hard',
        tags: ['vintage', 'retro', 'classic'],
      ),
      StyleChallenge(
        id: 'challenge_3',
        title: 'Sustainable Style',
        description: 'Show how sustainable fashion can be stylish! Use thrifted, upcycled, or eco-friendly pieces.',
        imageUrl: 'https://example.com/sustainable.jpg',
        startDate: DateTime.now().subtract(const Duration(days: 5)),
        endDate: DateTime.now().add(const Duration(days: 2)),
        participantCount: 2103,
        submissionCount: 1567,
        rules: [
          'All pieces must be sustainable',
          'Include sustainability story',
          'No fast fashion items',
          'Showcase creativity and style',
        ],
        prize: 'Sustainable fashion brand collaboration',
        isActive: isActive,
        isJoined: isJoined,
        difficulty: 'Easy',
        tags: ['sustainable', 'eco-friendly', 'thrifted'],
      ),
      StyleChallenge(
        id: 'challenge_4',
        title: 'Color Block Challenge',
        description: 'Master the art of color blocking with bold, contrasting colors that make a statement.',
        imageUrl: 'https://example.com/colorblock.jpg',
        startDate: DateTime.now().add(const Duration(days: 7)),
        endDate: DateTime.now().add(const Duration(days: 14)),
        participantCount: 0,
        submissionCount: 0,
        rules: [
          'Use at least 3 contrasting colors',
          'Bold, geometric shapes',
          'No patterns or prints',
          'Modern, contemporary styling',
        ],
        prize: 'Professional photoshoot + portfolio',
        isActive: false,
        isJoined: false,
        difficulty: 'Medium',
        tags: ['colorful', 'bold', 'modern'],
      ),
      StyleChallenge(
        id: 'challenge_5',
        title: 'Street Style Showdown',
        description: 'Bring your best street style game! Urban, edgy, and effortlessly cool.',
        imageUrl: 'https://example.com/street.jpg',
        startDate: DateTime.now().subtract(const Duration(days: 2)),
        endDate: DateTime.now().add(const Duration(days: 5)),
        participantCount: 3456,
        submissionCount: 2134,
        rules: [
          'Urban-inspired styling',
          'Streetwear or casual pieces',
          'Include statement accessories',
          'Show your personality',
        ],
        prize: 'Streetwear brand sponsorship',
        isActive: isActive,
        isJoined: isJoined,
        difficulty: 'Easy',
        tags: ['street', 'urban', 'casual'],
      ),
    ];
    
    return challenges.where((challenge) {
      if (isActive && !challenge.isActive) return false;
      if (isUpcoming && !challenge.isUpcoming) return false;
      if (isJoined && !challenge.isJoined) return false;
      return true;
    }).toList();
  }
  
  void _onChallengeJoin(StyleChallenge challenge) async {
    final confirmed = await AppDialog.confirm(
      context,
      title: 'Join Challenge',
      message: 'Are you sure you want to join "${challenge.title}"?',
      confirmText: 'Join',
    );
    
    if (!confirmed) return;
    
    try {
      // Mock join challenge
      await Future.delayed(const Duration(seconds: 1));
      
      setState(() {
        // Update challenge status
        final index = _activeChallenges.indexWhere((c) => c.id == challenge.id);
        if (index != -1) {
          _activeChallenges[index] = StyleChallenge(
            id: challenge.id,
            title: challenge.title,
            description: challenge.description,
            imageUrl: challenge.imageUrl,
            startDate: challenge.startDate,
            endDate: challenge.endDate,
            participantCount: challenge.participantCount + 1,
            submissionCount: challenge.submissionCount,
            rules: challenge.rules,
            prize: challenge.prize,
            isActive: challenge.isActive,
            isJoined: true,
            difficulty: challenge.difficulty,
            tags: challenge.tags,
          );
        }
      });
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Joined "${challenge.title}"!'),
          backgroundColor: AppColors.success,
        ),
      );
    } catch (e) {
      _showErrorDialog('Error', 'Failed to join challenge');
    }
  }
  
  void _onChallengeLeave(StyleChallenge challenge) async {
    final confirmed = await AppDialog.confirm(
      context,
      title: 'Leave Challenge',
      message: 'Are you sure you want to leave "${challenge.title}"?',
      confirmText: 'Leave',
      confirmIsDestructive: true,
    );
    
    if (!confirmed) return;
    
    try {
      // Mock leave challenge
      await Future.delayed(const Duration(seconds: 1));
      
      setState(() {
        _myChallenges.removeWhere((c) => c.id == challenge.id);
      });
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Left "${challenge.title}"'),
          backgroundColor: AppColors.warning,
        ),
      );
    } catch (e) {
      _showErrorDialog('Error', 'Failed to leave challenge');
    }
  }
  
  void _onChallengeSubmit(StyleChallenge challenge) {
    context.push('/social/challenge/${challenge.id}/submit');
  }
  
  void _onChallengeDetails(StyleChallenge challenge) {
    context.push('/social/challenge/${challenge.id}');
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
        title: 'Style Challenges',
        actions: [
          IconButton(
            icon: const Icon(Icons.emoji_events),
            onPressed: () {
              context.push('/social/challenges/leaderboard');
            },
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'Active'),
            Tab(text: 'Upcoming'),
            Tab(text: 'My Challenges'),
          ],
        ),
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator())
          : TabBarView(
              controller: _tabController,
              children: [
                _buildChallengesList(_activeChallenges, isActive: true),
                _buildChallengesList(_upcomingChallenges, isUpcoming: true),
                _buildChallengesList(_myChallenges, isMine: true),
              ],
            ),
    );
  }
  
  Widget _buildChallengesList(
    List<StyleChallenge> challenges, {
    bool isActive = false,
    bool isUpcoming = false,
    bool isMine = false,
  }) {
    if (challenges.isEmpty) {
      return _buildEmptyState(
        isActive: isActive,
        isUpcoming: isUpcoming,
        isMine: isMine,
      );
    }
    
    return ListView.builder(
      padding: const EdgeInsets.all(AppDimensions.paddingM),
      itemCount: challenges.length,
      itemBuilder: (context, index) {
        final challenge = challenges[index];
        return AppFadeAnimation(
          delay: Duration(milliseconds: index * 100),
          child: _buildChallengeCard(
            challenge,
            isActive: isActive,
            isUpcoming: isUpcoming,
            isMine: isMine,
          ),
        );
      },
    );
  }
  
  Widget _buildChallengeCard(
    StyleChallenge challenge, {
    bool isActive = false,
    bool isUpcoming = false,
    bool isMine = false,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: AppDimensions.paddingL),
      clipBehavior: Clip.antiAlias,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Challenge image and header
          Stack(
            children: [
              Container(
                height: 150,
                width: double.infinity,
                decoration: BoxDecoration(
                  color: AppColors.backgroundSecondary,
                  gradient: LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      AppColors.primary.withOpacity(0.1),
                      AppColors.primary.withOpacity(0.3),
                    ],
                  ),
                ),
                child: const Center(
                  child: Icon(
                    Icons.emoji_events,
                    size: 48,
                    color: AppColors.primary,
                  ),
                ),
              ),
              
              // Status badge
              Positioned(
                top: AppDimensions.paddingS,
                right: AppDimensions.paddingS,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppDimensions.paddingS,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: _getStatusColor(challenge),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                  child: Text(
                    _getStatusText(challenge),
                    style: AppTextStyles.caption.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
              
              // Difficulty badge
              Positioned(
                top: AppDimensions.paddingS,
                left: AppDimensions.paddingS,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppDimensions.paddingS,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: _getDifficultyColor(challenge.difficulty),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                  child: Text(
                    challenge.difficulty.toUpperCase(),
                    style: AppTextStyles.caption.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
            ],
          ),
          
          // Challenge details
          Padding(
            padding: const EdgeInsets.all(AppDimensions.paddingM),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Title and time
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        challenge.title,
                        style: AppTextStyles.h3,
                      ),
                    ),
                    if (isActive && !challenge.isExpired)
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: AppDimensions.paddingS,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.error.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                        ),
                        child: Text(
                          _formatTimeLeft(challenge.timeLeft),
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.error,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                  ],
                ),
                
                const SizedBox(height: AppDimensions.paddingS),
                
                // Description
                Text(
                  challenge.description,
                  style: AppTextStyles.bodyMedium,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                
                const SizedBox(height: AppDimensions.paddingS),
                
                // Tags
                Wrap(
                  spacing: AppDimensions.paddingXS,
                  children: challenge.tags.map((tag) => Chip(
                    label: Text(tag),
                    backgroundColor: AppColors.primary.withOpacity(0.1),
                    labelStyle: AppTextStyles.caption.copyWith(
                      color: AppColors.primary,
                    ),
                  )).toList(),
                ),
                
                const SizedBox(height: AppDimensions.paddingM),
                
                // Stats
                Row(
                  children: [
                    Icon(
                      Icons.people,
                      size: 16,
                      color: AppColors.textSecondary,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '${challenge.participantCount} participants',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                    const SizedBox(width: AppDimensions.paddingM),
                    Icon(
                      Icons.photo_library,
                      size: 16,
                      color: AppColors.textSecondary,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '${challenge.submissionCount} submissions',
                      style: AppTextStyles.caption.copyWith(
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ],
                ),
                
                const SizedBox(height: AppDimensions.paddingS),
                
                // Prize
                Container(
                  padding: const EdgeInsets.all(AppDimensions.paddingS),
                  decoration: BoxDecoration(
                    color: AppColors.success.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        Icons.stars,
                        color: AppColors.success,
                        size: 16,
                      ),
                      const SizedBox(width: AppDimensions.paddingS),
                      Expanded(
                        child: Text(
                          challenge.prize,
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.success,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                
                const SizedBox(height: AppDimensions.paddingM),
                
                // Actions
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton(
                        onPressed: () => _onChallengeDetails(challenge),
                        child: const Text('View Details'),
                      ),
                    ),
                    const SizedBox(width: AppDimensions.paddingS),
                    Expanded(
                      child: _buildActionButton(challenge, isMine: isMine),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildActionButton(StyleChallenge challenge, {bool isMine = false}) {
    if (isMine) {
      return Row(
        children: [
          Expanded(
            child: ElevatedButton(
              onPressed: () => _onChallengeSubmit(challenge),
              child: const Text('Submit'),
            ),
          ),
          const SizedBox(width: AppDimensions.paddingS),
          IconButton(
            onPressed: () => _onChallengeLeave(challenge),
            icon: const Icon(Icons.exit_to_app),
            color: AppColors.error,
          ),
        ],
      );
    }
    
    if (challenge.isJoined) {
      return ElevatedButton(
        onPressed: () => _onChallengeSubmit(challenge),
        child: const Text('Submit'),
      );
    }
    
    if (challenge.isUpcoming) {
      return ElevatedButton(
        onPressed: () => _onChallengeJoin(challenge),
        child: const Text('Join'),
      );
    }
    
    return ElevatedButton(
      onPressed: challenge.isExpired ? null : () => _onChallengeJoin(challenge),
      child: Text(challenge.isExpired ? 'Expired' : 'Join'),
    );
  }
  
  Widget _buildEmptyState({
    bool isActive = false,
    bool isUpcoming = false,
    bool isMine = false,
  }) {
    String title;
    String subtitle;
    IconData icon;
    
    if (isActive) {
      title = 'No Active Challenges';
      subtitle = 'Check back later for new challenges';
      icon = Icons.emoji_events_outlined;
    } else if (isUpcoming) {
      title = 'No Upcoming Challenges';
      subtitle = 'New challenges will appear here';
      icon = Icons.schedule;
    } else {
      title = 'No Joined Challenges';
      subtitle = 'Join a challenge to see it here';
      icon = Icons.people_outline;
    }
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            icon,
            size: 64,
            color: AppColors.textTertiary,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            title,
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingS),
          Text(
            subtitle,
            style: AppTextStyles.bodyMedium.copyWith(
              color: AppColors.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Color _getStatusColor(StyleChallenge challenge) {
    if (challenge.isExpired) return AppColors.textSecondary;
    if (challenge.isUpcoming) return AppColors.warning;
    return AppColors.success;
  }
  
  String _getStatusText(StyleChallenge challenge) {
    if (challenge.isExpired) return 'ENDED';
    if (challenge.isUpcoming) return 'UPCOMING';
    return 'ACTIVE';
  }
  
  Color _getDifficultyColor(String difficulty) {
    switch (difficulty.toLowerCase()) {
      case 'easy':
        return AppColors.success;
      case 'medium':
        return AppColors.warning;
      case 'hard':
        return AppColors.error;
      default:
        return AppColors.textSecondary;
    }
  }
  
  String _formatTimeLeft(Duration duration) {
    if (duration.inDays > 0) {
      return '${duration.inDays}d left';
    } else if (duration.inHours > 0) {
      return '${duration.inHours}h left';
    } else if (duration.inMinutes > 0) {
      return '${duration.inMinutes}m left';
    } else {
      return 'Ending soon';
    }
  }
}