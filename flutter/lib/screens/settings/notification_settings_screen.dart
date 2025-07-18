import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/screens/settings/weather_notification_settings_screen.dart';

class NotificationSettingsScreen extends ConsumerStatefulWidget {
  const NotificationSettingsScreen({super.key});

  @override
  ConsumerState<NotificationSettingsScreen> createState() => _NotificationSettingsScreenState();
}

class _NotificationSettingsScreenState extends ConsumerState<NotificationSettingsScreen> {
  bool _dailyReminder = true;
  bool _outfitSuggestions = true;
  bool _weatherAlerts = true;
  bool _socialNotifications = true;
  bool _promotions = false;
  TimeOfDay _reminderTime = const TimeOfDay(hour: 8, minute: 0);
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Notification Settings'),
      ),
      body: ListView(
        children: [
          // Daily Reminders
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'DAILY REMINDERS',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ),
          SwitchListTile(
            title: const Text('Daily Outfit Reminder'),
            subtitle: const Text('Get reminded to plan your outfit'),
            value: _dailyReminder,
            onChanged: (value) {
              setState(() => _dailyReminder = value);
            },
          ),
          ListTile(
            title: const Text('Reminder Time'),
            subtitle: Text(_reminderTime.format(context)),
            enabled: _dailyReminder,
            trailing: const Icon(Icons.chevron_right),
            onTap: _dailyReminder ? () => _selectTime(context) : null,
          ),
          
          const Divider(),
          
          // Smart Notifications
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'SMART NOTIFICATIONS',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ),
          SwitchListTile(
            title: const Text('Outfit Suggestions'),
            subtitle: const Text('Get AI-powered outfit recommendations'),
            value: _outfitSuggestions,
            onChanged: (value) {
              setState(() => _outfitSuggestions = value);
            },
          ),
          ListTile(
            title: const Text('Weather Notifications'),
            subtitle: const Text('Configure weather-based alerts'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => const WeatherNotificationSettingsScreen(),
                ),
              );
            },
          ),
          
          const Divider(),
          
          // Social Notifications
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'SOCIAL',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ),
          SwitchListTile(
            title: const Text('Social Notifications'),
            subtitle: const Text('Likes, comments, and follows'),
            value: _socialNotifications,
            onChanged: (value) {
              setState(() => _socialNotifications = value);
            },
          ),
          
          const Divider(),
          
          // Other
          const Padding(
            padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'OTHER',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ),
          SwitchListTile(
            title: const Text('Promotions & Tips'),
            subtitle: const Text('Updates and fashion tips'),
            value: _promotions,
            onChanged: (value) {
              setState(() => _promotions = value);
            },
          ),
          
          const SizedBox(height: 32),
        ],
      ),
    );
  }
  
  Future<void> _selectTime(BuildContext context) async {
    final time = await showTimePicker(
      context: context,
      initialTime: _reminderTime,
    );
    
    if (time != null) {
      setState(() => _reminderTime = time);
    }
  }
}