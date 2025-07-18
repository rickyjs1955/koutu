import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/widgets/tablet/tablet_app_bar.dart';

/// iPad-specific profile screen
class TabletProfileScreen extends ConsumerWidget {
  const TabletProfileScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final screenSize = MediaQuery.of(context).size;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      appBar: const TabletAppBar(
        title: 'Profile',
        actions: [
          IconButton(
            icon: Icon(Icons.settings),
            onPressed: null, // TODO: Settings
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Profile header
              _buildProfileHeader(context, screenSize),
              
              const SizedBox(height: 32),
              
              // Statistics section
              _buildStatisticsSection(context),
              
              const SizedBox(height: 32),
              
              // Recent activity
              _buildRecentActivity(context),
              
              const SizedBox(height: 32),
              
              // Wardrobe insights
              _buildWardrobeInsights(context),
              
              const SizedBox(height: 32),
              
              // Settings and preferences
              _buildSettingsSection(context),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildProfileHeader(BuildContext context, Size screenSize) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final isLargeScreen = screenSize.width > 1200;

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            colorScheme.primaryContainer,
            colorScheme.secondaryContainer,
          ],
        ),
        borderRadius: BorderRadius.circular(16),
      ),
      child: isLargeScreen
          ? Row(
              children: [
                _buildProfileAvatar(context),
                const SizedBox(width: 32),
                Expanded(child: _buildProfileInfo(context)),
                const SizedBox(width: 32),
                _buildProfileActions(context),
              ],
            )
          : Column(
              children: [
                _buildProfileAvatar(context),
                const SizedBox(height: 24),
                _buildProfileInfo(context),
                const SizedBox(height: 24),
                _buildProfileActions(context),
              ],
            ),
    );
  }

  Widget _buildProfileAvatar(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    
    return Stack(
      children: [
        Container(
          width: 120,
          height: 120,
          decoration: BoxDecoration(
            color: colorScheme.surface,
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: colorScheme.shadow.withOpacity(0.2),
                blurRadius: 16,
                offset: const Offset(0, 8),
              ),
            ],
          ),
          child: const Icon(
            Icons.person,
            size: 60,
          ),
        ),
        Positioned(
          bottom: 0,
          right: 0,
          child: Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: colorScheme.primary,
              shape: BoxShape.circle,
              border: Border.all(
                color: colorScheme.surface,
                width: 3,
              ),
            ),
            child: Icon(
              Icons.camera_alt,
              color: colorScheme.onPrimary,
              size: 18,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildProfileInfo(BuildContext context) {
    final theme = Theme.of(context);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Fashion Enthusiast',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Passionate about sustainable fashion and minimalist style',
          style: theme.textTheme.bodyLarge?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Icon(
              Icons.location_on,
              size: 16,
              color: theme.colorScheme.onSurfaceVariant,
            ),
            const SizedBox(width: 4),
            Text(
              'New York, NY',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(width: 16),
            Icon(
              Icons.calendar_today,
              size: 16,
              color: theme.colorScheme.onSurfaceVariant,
            ),
            const SizedBox(width: 4),
            Text(
              'Member since 2023',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildProfileActions(BuildContext context) {
    return Column(
      children: [
        ElevatedButton.icon(
          onPressed: () {
            // TODO: Edit profile
          },
          icon: const Icon(Icons.edit),
          label: const Text('Edit Profile'),
          style: ElevatedButton.styleFrom(
            backgroundColor: Theme.of(context).colorScheme.surface,
            foregroundColor: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: () {
            // TODO: Share profile
          },
          icon: const Icon(Icons.share),
          label: const Text('Share'),
        ),
      ],
    );
  }

  Widget _buildStatisticsSection(BuildContext context) {
    final theme = Theme.of(context);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Statistics',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 16),
        GridView.count(
          crossAxisCount: 4,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          childAspectRatio: 1.5,
          mainAxisSpacing: 16,
          crossAxisSpacing: 16,
          children: [
            _buildStatCard(
              context,
              'Garments',
              '142',
              Icons.checkroom,
              Colors.blue,
            ),
            _buildStatCard(
              context,
              'Outfits',
              '42',
              Icons.style,
              Colors.purple,
            ),
            _buildStatCard(
              context,
              'Favorites',
              '23',
              Icons.favorite,
              Colors.red,
            ),
            _buildStatCard(
              context,
              'This Month',
              '8',
              Icons.calendar_today,
              Colors.green,
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStatCard(BuildContext context, String title, String value, IconData icon, Color color) {
    final theme = Theme.of(context);
    
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            icon,
            size: 24,
            color: color,
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: theme.textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            title,
            style: theme.textTheme.bodySmall?.copyWith(
              color: color,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildRecentActivity(BuildContext context) {
    final theme = Theme.of(context);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Recent Activity',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 16),
        ListView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          itemCount: 5,
          itemBuilder: (context, index) {
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: CircleAvatar(
                  backgroundColor: theme.colorScheme.primaryContainer,
                  child: Icon(
                    _getActivityIcon(index),
                    color: theme.colorScheme.onPrimaryContainer,
                  ),
                ),
                title: Text(_getActivityTitle(index)),
                subtitle: Text(_getActivitySubtitle(index)),
                trailing: Text(
                  _getActivityTime(index),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildWardrobeInsights(BuildContext context) {
    final theme = Theme.of(context);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Wardrobe Insights',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _buildInsightCard(
                context,
                'Most Worn',
                'Blue Jeans',
                '12 times this month',
                Icons.trending_up,
                Colors.blue,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: _buildInsightCard(
                context,
                'Trending Style',
                'Casual',
                '65% of outfits',
                Icons.star,
                Colors.orange,
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(
              child: _buildInsightCard(
                context,
                'Color Palette',
                'Neutral Tones',
                '45% of wardrobe',
                Icons.palette,
                Colors.brown,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: _buildInsightCard(
                context,
                'Underused',
                'Formal Wear',
                '8 items never worn',
                Icons.warning,
                Colors.amber,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildInsightCard(BuildContext context, String title, String value, String subtitle, IconData icon, Color color) {
    final theme = Theme.of(context);
    
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: theme.colorScheme.outlineVariant,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                icon,
                size: 20,
                color: color,
              ),
              const SizedBox(width: 8),
              Text(
                title,
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            value,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSettingsSection(BuildContext context) {
    final theme = Theme.of(context);
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Settings & Preferences',
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 16),
        GridView.count(
          crossAxisCount: 2,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          childAspectRatio: 3,
          mainAxisSpacing: 12,
          crossAxisSpacing: 12,
          children: [
            _buildSettingsTile(
              context,
              'Account Settings',
              'Privacy, security, and personal info',
              Icons.account_circle,
              () {
                // TODO: Account settings
              },
            ),
            _buildSettingsTile(
              context,
              'Notifications',
              'Manage alerts and reminders',
              Icons.notifications,
              () {
                // TODO: Notification settings
              },
            ),
            _buildSettingsTile(
              context,
              'Platform Integration',
              'iOS widgets, voice commands, wearables',
              Icons.devices,
              () {
                // TODO: Platform settings
              },
            ),
            _buildSettingsTile(
              context,
              'Data & Privacy',
              'Export data and privacy controls',
              Icons.security,
              () {
                // TODO: Privacy settings
              },
            ),
            _buildSettingsTile(
              context,
              'Backup & Sync',
              'Cloud storage and synchronization',
              Icons.cloud_sync,
              () {
                // TODO: Backup settings
              },
            ),
            _buildSettingsTile(
              context,
              'Help & Support',
              'Get help and contact support',
              Icons.help,
              () {
                // TODO: Help & support
              },
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildSettingsTile(BuildContext context, String title, String subtitle, IconData icon, VoidCallback onTap) {
    final theme = Theme.of(context);
    
    return Card(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              Icon(
                icon,
                size: 24,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: theme.textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      subtitle,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(
                Icons.chevron_right,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ],
          ),
        ),
      ),
    );
  }

  IconData _getActivityIcon(int index) {
    switch (index) {
      case 0:
        return Icons.add;
      case 1:
        return Icons.style;
      case 2:
        return Icons.favorite;
      case 3:
        return Icons.camera_alt;
      case 4:
        return Icons.share;
      default:
        return Icons.activity_zone;
    }
  }

  String _getActivityTitle(int index) {
    switch (index) {
      case 0:
        return 'Added new garment';
      case 1:
        return 'Created new outfit';
      case 2:
        return 'Favorited 3 items';
      case 3:
        return 'Took outfit photo';
      case 4:
        return 'Shared wardrobe';
      default:
        return 'Activity';
    }
  }

  String _getActivitySubtitle(int index) {
    switch (index) {
      case 0:
        return 'Blue denim jacket added to wardrobe';
      case 1:
        return 'Casual weekend outfit';
      case 2:
        return 'Marked favorite items';
      case 3:
        return 'Today\'s outfit photo';
      case 4:
        return 'Shared with friends';
      default:
        return 'Activity description';
    }
  }

  String _getActivityTime(int index) {
    switch (index) {
      case 0:
        return '2 hours ago';
      case 1:
        return '1 day ago';
      case 2:
        return '3 days ago';
      case 3:
        return '1 week ago';
      case 4:
        return '2 weeks ago';
      default:
        return 'Recently';
    }
  }
}