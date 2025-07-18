import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/social_activity_provider.dart';
import 'package:koutu/services/notification/social_activity_service.dart';
import 'package:koutu/widgets/common/error_view.dart';
import 'package:koutu/widgets/common/loading_indicator.dart';
import 'package:intl/intl.dart';

class SocialActivityScreen extends ConsumerStatefulWidget {
  const SocialActivityScreen({super.key});

  @override
  ConsumerState<SocialActivityScreen> createState() => _SocialActivityScreenState();
}

class _SocialActivityScreenState extends ConsumerState<SocialActivityScreen> {
  final _dateFormat = DateFormat('MMM d');
  final _timeFormat = DateFormat('h:mm a');
  
  @override
  Widget build(BuildContext context) {
    final activities = ref.watch(pendingSocialActivitiesProvider);
    final unreadCount = ref.watch(unreadSocialActivitiesProvider).length;
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Activity'),
        actions: [
          if (unreadCount > 0)
            Center(
              child: Container(
                margin: const EdgeInsets.only(right: 8),
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primary,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  '$unreadCount',
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onPrimary,
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => const SocialActivitySettingsScreen(),
                ),
              );
            },
          ),
        ],
      ),
      body: activities.isEmpty
          ? _buildEmptyState()
          : ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: activities.length + 1,
              itemBuilder: (context, index) {
                if (index == 0) {
                  return _buildActivitySummary();
                }
                
                final activity = activities[index - 1];
                return _ActivityCard(
                  activity: activity,
                  onTap: () => _handleActivityTap(activity),
                );
              },
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _clearAllActivities,
        child: const Icon(Icons.clear_all),
      ),
    );
  }
  
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.notifications_none,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            'No activity yet',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          const Text('Your social activity will appear here'),
        ],
      ),
    );
  }
  
  Widget _buildActivitySummary() {
    final summaryAsync = ref.watch(
      activitySummaryProvider(const Duration(days: 7)),
    );
    
    return summaryAsync.when(
      data: (summary) {
        if (summary.totalActivities == 0) {
          return const SizedBox.shrink();
        }
        
        return Card(
          margin: const EdgeInsets.only(bottom: 16),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'This Week',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    Text(
                      '${summary.totalActivities} activities',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                ...summary.activityCounts.entries.map((entry) {
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      children: [
                        Icon(
                          _getActivityIcon(entry.key),
                          size: 20,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          '${entry.value} ${_getActivityLabel(entry.key)}',
                        ),
                      ],
                    ),
                  );
                }).toList(),
                if (summary.topContributors.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  const Divider(),
                  const SizedBox(height: 12),
                  Text(
                    'Most Active',
                    style: Theme.of(context).textTheme.labelLarge,
                  ),
                  const SizedBox(height: 8),
                  ...summary.topContributors.take(3).map((contributor) {
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 16,
                            child: Text(
                              contributor.username[0].toUpperCase(),
                              style: const TextStyle(fontSize: 12),
                            ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(contributor.username),
                          ),
                          Text(
                            '${contributor.activityCount}',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ),
                    );
                  }).toList(),
                ],
              ],
            ),
          ),
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (_, __) => const SizedBox.shrink(),
    );
  }
  
  void _handleActivityTap(SocialActivity activity) {
    if (!activity.isRead) {
      final service = ref.read(socialActivityServiceProvider);
      service.markActivitiesAsRead([activity.id]);
    }
    
    // Navigate to relevant screen based on activity type
    // Implementation depends on your navigation structure
  }
  
  Future<void> _clearAllActivities() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear All Activities'),
        content: const Text('Are you sure you want to clear all activities?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Clear'),
          ),
        ],
      ),
    );
    
    if (confirmed == true && mounted) {
      final service = ref.read(socialActivityServiceProvider);
      final result = await service.clearOldActivities(
        retention: const Duration(seconds: 0),
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to clear activities: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Activities cleared'),
            ),
          );
        },
      );
    }
  }
  
  IconData _getActivityIcon(SocialActivityType type) {
    switch (type) {
      case SocialActivityType.like:
        return Icons.favorite;
      case SocialActivityType.comment:
        return Icons.comment;
      case SocialActivityType.follow:
        return Icons.person_add;
      case SocialActivityType.share:
        return Icons.share;
      case SocialActivityType.mention:
        return Icons.alternate_email;
      case SocialActivityType.outfitCopy:
        return Icons.collections_bookmark;
    }
  }
  
  String _getActivityLabel(SocialActivityType type) {
    switch (type) {
      case SocialActivityType.like:
        return 'likes';
      case SocialActivityType.comment:
        return 'comments';
      case SocialActivityType.follow:
        return 'new followers';
      case SocialActivityType.share:
        return 'shares';
      case SocialActivityType.mention:
        return 'mentions';
      case SocialActivityType.outfitCopy:
        return 'saved outfits';
    }
  }
}

/// Activity card widget
class _ActivityCard extends StatelessWidget {
  final SocialActivity activity;
  final VoidCallback onTap;
  
  const _ActivityCard({
    required this.activity,
    required this.onTap,
  });
  
  @override
  Widget build(BuildContext context) {
    final timeAgo = _formatTimeAgo(activity.createdAt);
    
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              CircleAvatar(
                radius: 24,
                backgroundImage: activity.fromUserAvatar != null
                    ? NetworkImage(activity.fromUserAvatar!)
                    : null,
                child: activity.fromUserAvatar == null
                    ? Text(
                        activity.fromUsername[0].toUpperCase(),
                        style: const TextStyle(fontSize: 18),
                      )
                    : null,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    RichText(
                      text: TextSpan(
                        style: Theme.of(context).textTheme.bodyMedium,
                        children: [
                          TextSpan(
                            text: activity.fromUsername,
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                          TextSpan(
                            text: ' ${_getActivityText(activity)}',
                          ),
                        ],
                      ),
                    ),
                    if (activity.message != null) ...[
                      const SizedBox(height: 4),
                      Text(
                        activity.message!,
                        style: Theme.of(context).textTheme.bodySmall,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                    const SizedBox(height: 4),
                    Text(
                      timeAgo,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                    ),
                  ],
                ),
              ),
              Icon(
                _getActivityIcon(activity.type),
                color: activity.isRead
                    ? Theme.of(context).colorScheme.onSurfaceVariant
                    : Theme.of(context).colorScheme.primary,
              ),
              if (!activity.isRead)
                Container(
                  width: 8,
                  height: 8,
                  margin: const EdgeInsets.only(left: 8),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primary,
                    shape: BoxShape.circle,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
  
  String _getActivityText(SocialActivity activity) {
    switch (activity.type) {
      case SocialActivityType.like:
        return 'liked your outfit';
      case SocialActivityType.comment:
        return 'commented on your outfit';
      case SocialActivityType.follow:
        return 'started following you';
      case SocialActivityType.share:
        return 'shared your outfit';
      case SocialActivityType.mention:
        return 'mentioned you';
      case SocialActivityType.outfitCopy:
        return 'saved your outfit';
    }
  }
  
  IconData _getActivityIcon(SocialActivityType type) {
    switch (type) {
      case SocialActivityType.like:
        return Icons.favorite;
      case SocialActivityType.comment:
        return Icons.comment;
      case SocialActivityType.follow:
        return Icons.person_add;
      case SocialActivityType.share:
        return Icons.share;
      case SocialActivityType.mention:
        return Icons.alternate_email;
      case SocialActivityType.outfitCopy:
        return Icons.collections_bookmark;
    }
  }
  
  String _formatTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inDays > 7) {
      return DateFormat('MMM d').format(dateTime);
    } else if (difference.inDays > 0) {
      return '${difference.inDays}d ago';
    } else if (difference.inHours > 0) {
      return '${difference.inHours}h ago';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes}m ago';
    } else {
      return 'Just now';
    }
  }
}

/// Social activity settings screen
class SocialActivitySettingsScreen extends ConsumerStatefulWidget {
  const SocialActivitySettingsScreen({super.key});

  @override
  ConsumerState<SocialActivitySettingsScreen> createState() => 
      _SocialActivitySettingsScreenState();
}

class _SocialActivitySettingsScreenState 
    extends ConsumerState<SocialActivitySettingsScreen> {
  late SocialActivitySettings _settings;
  
  @override
  void initState() {
    super.initState();
    _settings = ref.read(socialActivityServiceProvider).getSettings();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Activity Settings'),
        actions: [
          TextButton(
            onPressed: _saveSettings,
            child: const Text('Save'),
          ),
        ],
      ),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Enable Activity Notifications'),
            subtitle: const Text('Get notified about social interactions'),
            value: _settings.enabled,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(enabled: value);
              });
            },
          ),
          const Divider(),
          const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Notification Strategy',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ),
          RadioListTile<NotificationStrategy>(
            title: const Text('Instant'),
            subtitle: const Text('Get notified immediately'),
            value: NotificationStrategy.instant,
            groupValue: _settings.notificationStrategy,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(notificationStrategy: value);
                });
              }
            },
          ),
          RadioListTile<NotificationStrategy>(
            title: const Text('Batched'),
            subtitle: const Text('Group notifications every 5 minutes'),
            value: NotificationStrategy.batched,
            groupValue: _settings.notificationStrategy,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(notificationStrategy: value);
                });
              }
            },
          ),
          RadioListTile<NotificationStrategy>(
            title: const Text('Smart'),
            subtitle: const Text('Intelligent notification grouping'),
            value: NotificationStrategy.smart,
            groupValue: _settings.notificationStrategy,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(notificationStrategy: value);
                });
              }
            },
          ),
          const Divider(),
          const Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Activity Types',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ),
          CheckboxListTile(
            title: const Text('Likes'),
            subtitle: const Text('When someone likes your outfit'),
            value: _settings.likeNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(likeNotifications: value);
                });
              }
            },
          ),
          CheckboxListTile(
            title: const Text('Comments'),
            subtitle: const Text('When someone comments on your outfit'),
            value: _settings.commentNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(commentNotifications: value);
                });
              }
            },
          ),
          CheckboxListTile(
            title: const Text('New Followers'),
            subtitle: const Text('When someone starts following you'),
            value: _settings.followNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(followNotifications: value);
                });
              }
            },
          ),
          CheckboxListTile(
            title: const Text('Shares'),
            subtitle: const Text('When someone shares your outfit'),
            value: _settings.shareNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(shareNotifications: value);
                });
              }
            },
          ),
          CheckboxListTile(
            title: const Text('Mentions'),
            subtitle: const Text('When someone mentions you'),
            value: _settings.mentionNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(mentionNotifications: value);
                });
              }
            },
          ),
          CheckboxListTile(
            title: const Text('Outfit Saves'),
            subtitle: const Text('When someone saves your outfit'),
            value: _settings.outfitCopyNotifications,
            onChanged: (value) {
              if (value != null) {
                setState(() {
                  _settings = _settings.copyWith(outfitCopyNotifications: value);
                });
              }
            },
          ),
          const Divider(),
          SwitchListTile(
            title: const Text('Daily Summary'),
            subtitle: const Text('Get a daily summary of your activity'),
            value: _settings.dailySummary,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(dailySummary: value);
              });
            },
          ),
          if (_settings.dailySummary)
            ListTile(
              title: const Text('Summary Time'),
              subtitle: Text(_settings.summaryTime.format(context)),
              trailing: const Icon(Icons.access_time),
              onTap: () async {
                final time = await showTimePicker(
                  context: context,
                  initialTime: _settings.summaryTime,
                );
                
                if (time != null) {
                  setState(() {
                    _settings = _settings.copyWith(summaryTime: time);
                  });
                }
              },
            ),
        ],
      ),
    );
  }
  
  Future<void> _saveSettings() async {
    final service = ref.read(socialActivityServiceProvider);
    final result = await service.updateSettings(_settings);
    
    if (mounted) {
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to save settings: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Settings saved'),
            ),
          );
          Navigator.pop(context);
        },
      );
    }
  }
}