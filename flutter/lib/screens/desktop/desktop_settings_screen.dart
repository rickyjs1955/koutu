import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Desktop settings and preferences screen
class DesktopSettingsScreen extends ConsumerWidget {
  const DesktopSettingsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;

    return Scaffold(
      backgroundColor: colorScheme.surface,
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Text(
              'Settings',
              style: theme.textTheme.headlineMedium?.copyWith(
                fontWeight: FontWeight.bold,
              ),
            ),
            
            const SizedBox(height: 24),
            
            Expanded(
              child: Row(
                children: [
                  // Settings categories
                  SizedBox(
                    width: 200,
                    child: Card(
                      child: ListView(
                        padding: const EdgeInsets.all(8),
                        children: [
                          _buildSettingsCategory('General', Icons.settings, true),
                          _buildSettingsCategory('Sync & Backup', Icons.sync),
                          _buildSettingsCategory('Platform Integration', Icons.devices),
                          _buildSettingsCategory('Notifications', Icons.notifications),
                          _buildSettingsCategory('Privacy & Security', Icons.security),
                          _buildSettingsCategory('Data & Storage', Icons.storage),
                          _buildSettingsCategory('About', Icons.info),
                        ],
                      ),
                    ),
                  ),
                  
                  const SizedBox(width: 16),
                  
                  // Settings content
                  Expanded(
                    child: Card(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'General Settings',
                              style: theme.textTheme.titleLarge?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            
                            const SizedBox(height: 24),
                            
                            Expanded(
                              child: ListView(
                                children: [
                                  // App preferences
                                  _buildSettingsSection(
                                    'App Preferences',
                                    [
                                      _buildSwitchTile(
                                        'Dark Mode',
                                        'Use dark theme',
                                        false,
                                        (value) {
                                          // TODO: Toggle dark mode
                                        },
                                      ),
                                      _buildSwitchTile(
                                        'Startup with System',
                                        'Launch app when computer starts',
                                        true,
                                        (value) {
                                          // TODO: Toggle startup
                                        },
                                      ),
                                      _buildSwitchTile(
                                        'Minimize to Tray',
                                        'Keep app running in system tray',
                                        true,
                                        (value) {
                                          // TODO: Toggle minimize to tray
                                        },
                                      ),
                                    ],
                                  ),
                                  
                                  const SizedBox(height: 24),
                                  
                                  // Display preferences
                                  _buildSettingsSection(
                                    'Display',
                                    [
                                      _buildDropdownTile(
                                        'Default View',
                                        'Table',
                                        ['Table', 'Grid', 'List'],
                                        (value) {
                                          // TODO: Set default view
                                        },
                                      ),
                                      _buildDropdownTile(
                                        'Items per Page',
                                        '50',
                                        ['25', '50', '100', '200'],
                                        (value) {
                                          // TODO: Set items per page
                                        },
                                      ),
                                      _buildSwitchTile(
                                        'Show Thumbnails',
                                        'Display image thumbnails in lists',
                                        true,
                                        (value) {
                                          // TODO: Toggle thumbnails
                                        },
                                      ),
                                    ],
                                  ),
                                  
                                  const SizedBox(height: 24),
                                  
                                  // Sync preferences
                                  _buildSettingsSection(
                                    'Sync Settings',
                                    [
                                      _buildSwitchTile(
                                        'Auto Sync',
                                        'Automatically sync with mobile app',
                                        true,
                                        (value) {
                                          // TODO: Toggle auto sync
                                        },
                                      ),
                                      _buildDropdownTile(
                                        'Sync Frequency',
                                        'Every 5 minutes',
                                        ['Real-time', 'Every minute', 'Every 5 minutes', 'Every 15 minutes', 'Hourly'],
                                        (value) {
                                          // TODO: Set sync frequency
                                        },
                                      ),
                                      _buildSwitchTile(
                                        'Sync Photos',
                                        'Download high-resolution photos',
                                        false,
                                        (value) {
                                          // TODO: Toggle photo sync
                                        },
                                      ),
                                    ],
                                  ),
                                  
                                  const SizedBox(height: 24),
                                  
                                  // Storage preferences
                                  _buildSettingsSection(
                                    'Storage',
                                    [
                                      ListTile(
                                        title: const Text('Data Location'),
                                        subtitle: const Text('~/Documents/Koutu'),
                                        trailing: TextButton(
                                          onPressed: () {
                                            // TODO: Change data location
                                          },
                                          child: const Text('Change'),
                                        ),
                                      ),
                                      ListTile(
                                        title: const Text('Cache Size'),
                                        subtitle: const Text('245 MB'),
                                        trailing: TextButton(
                                          onPressed: () {
                                            // TODO: Clear cache
                                          },
                                          child: const Text('Clear'),
                                        ),
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSettingsCategory(String title, IconData icon, [bool isSelected = false]) {
    return Builder(
      builder: (context) {
        final theme = Theme.of(context);
        
        return Container(
          margin: const EdgeInsets.only(bottom: 4),
          child: ListTile(
            leading: Icon(icon, size: 20),
            title: Text(
              title,
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.w400,
              ),
            ),
            selected: isSelected,
            onTap: () {
              // TODO: Switch category
            },
          ),
        );
      },
    );
  }

  Widget _buildSettingsSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        ...children,
      ],
    );
  }

  Widget _buildSwitchTile(String title, String subtitle, bool value, ValueChanged<bool> onChanged) {
    return SwitchListTile(
      title: Text(title),
      subtitle: Text(subtitle),
      value: value,
      onChanged: onChanged,
    );
  }

  Widget _buildDropdownTile(String title, String value, List<String> options, ValueChanged<String> onChanged) {
    return ListTile(
      title: Text(title),
      trailing: DropdownButton<String>(
        value: value,
        items: options.map((option) {
          return DropdownMenuItem(
            value: option,
            child: Text(option),
          );
        }).toList(),
        onChanged: (newValue) {
          if (newValue != null) {
            onChanged(newValue);
          }
        },
      ),
    );
  }
}