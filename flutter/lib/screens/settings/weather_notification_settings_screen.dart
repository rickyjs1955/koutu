import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/weather_provider.dart';
import 'package:koutu/services/notification/weather_notification_service.dart';

class WeatherNotificationSettingsScreen extends ConsumerStatefulWidget {
  const WeatherNotificationSettingsScreen({super.key});

  @override
  ConsumerState<WeatherNotificationSettingsScreen> createState() => 
      _WeatherNotificationSettingsScreenState();
}

class _WeatherNotificationSettingsScreenState 
    extends ConsumerState<WeatherNotificationSettingsScreen> {
  late WeatherNotificationSettings _settings;
  
  @override
  void initState() {
    super.initState();
    _settings = ref.read(weatherNotificationServiceProvider).getSettings();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Weather Notifications'),
        actions: [
          TextButton(
            onPressed: _saveSettings,
            child: const Text('Save'),
          ),
        ],
      ),
      body: ListView(
        children: [
          // Master switch
          Card(
            margin: const EdgeInsets.all(16),
            child: SwitchListTile(
              title: const Text('Enable Weather Notifications'),
              subtitle: const Text('Get outfit suggestions based on weather'),
              value: _settings.enabled,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(enabled: value);
                });
              },
            ),
          ),
          
          if (_settings.enabled) ...[
            // Daily notifications
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'DAILY NOTIFICATIONS',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
            SwitchListTile(
              title: const Text('Morning Weather Update'),
              subtitle: Text(
                'Daily at ${_settings.morningTime.format(context)}',
              ),
              value: _settings.morningNotification,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(morningNotification: value);
                });
              },
            ),
            if (_settings.morningNotification)
              ListTile(
                title: const Text('Morning Notification Time'),
                subtitle: Text(_settings.morningTime.format(context)),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _selectTime(
                  context,
                  _settings.morningTime,
                  (time) {
                    setState(() {
                      _settings = _settings.copyWith(morningTime: time);
                    });
                  },
                ),
              ),
            
            SwitchListTile(
              title: const Text('Evening Forecast'),
              subtitle: Text(
                'Tomorrow\'s weather at ${_settings.eveningTime.format(context)}',
              ),
              value: _settings.eveningNotification,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(eveningNotification: value);
                });
              },
            ),
            if (_settings.eveningNotification)
              ListTile(
                title: const Text('Evening Notification Time'),
                subtitle: Text(_settings.eveningTime.format(context)),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => _selectTime(
                  context,
                  _settings.eveningTime,
                  (time) {
                    setState(() {
                      _settings = _settings.copyWith(eveningTime: time);
                    });
                  },
                ),
              ),
            
            const Divider(),
            
            // Weather alerts
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'WEATHER ALERTS',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
            ),
            SwitchListTile(
              title: const Text('Extreme Weather Alerts'),
              subtitle: const Text('Notify about extreme temperatures or conditions'),
              value: _settings.extremeWeatherAlerts,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(extremeWeatherAlerts: value);
                });
              },
            ),
            SwitchListTile(
              title: const Text('Rain Alerts'),
              subtitle: const Text('Remind to bring umbrella and waterproof items'),
              value: _settings.rainAlerts,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(rainAlerts: value);
                });
              },
            ),
            SwitchListTile(
              title: const Text('Temperature Change Alerts'),
              subtitle: const Text('Notify about large temperature swings'),
              value: _settings.temperatureChangeAlerts,
              onChanged: (value) {
                setState(() {
                  _settings = _settings.copyWith(temperatureChangeAlerts: value);
                });
              },
            ),
            
            const Divider(),
            
            // Test notifications
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    'TEST NOTIFICATIONS',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: _testMorningNotification,
                    icon: const Icon(Icons.wb_sunny),
                    label: const Text('Test Morning Notification'),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: _testEveningNotification,
                    icon: const Icon(Icons.nights_stay),
                    label: const Text('Test Evening Notification'),
                  ),
                  const SizedBox(height: 8),
                  OutlinedButton.icon(
                    onPressed: _testExtremeWeatherAlert,
                    icon: const Icon(Icons.warning),
                    label: const Text('Test Weather Alert'),
                  ),
                ],
              ),
            ),
          ],
          
          // Current weather info
          Card(
            margin: const EdgeInsets.all(16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'CURRENT WEATHER',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  const SizedBox(height: 8),
                  Consumer(
                    builder: (context, ref, child) {
                      final weatherAsync = ref.watch(currentWeatherProvider);
                      
                      return weatherAsync.when(
                        data: (weather) => Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Icon(
                                  _getWeatherIcon(weather.conditions),
                                  size: 48,
                                  color: Theme.of(context).colorScheme.primary,
                                ),
                                const SizedBox(width: 16),
                                Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      '${weather.temperature.round()}°C',
                                      style: Theme.of(context).textTheme.headlineMedium,
                                    ),
                                    Text(
                                      weather.description,
                                      style: Theme.of(context).textTheme.bodyMedium,
                                    ),
                                  ],
                                ),
                              ],
                            ),
                            const SizedBox(height: 16),
                            Text(
                              weather.cityName,
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Feels like ${weather.feelsLike.round()}°C • '
                              'Wind ${weather.windSpeed} m/s • '
                              'Humidity ${weather.humidity}%',
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                          ],
                        ),
                        loading: () => const Center(
                          child: CircularProgressIndicator(),
                        ),
                        error: (error, stack) => Column(
                          children: [
                            const Icon(
                              Icons.cloud_off,
                              size: 48,
                              color: Colors.grey,
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Unable to load weather',
                              style: Theme.of(context).textTheme.bodyMedium,
                            ),
                            TextButton(
                              onPressed: () {
                                ref.refresh(currentWeatherProvider);
                              },
                              child: const Text('Retry'),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Future<void> _selectTime(
    BuildContext context,
    TimeOfDay initialTime,
    Function(TimeOfDay) onTimeSelected,
  ) async {
    final time = await showTimePicker(
      context: context,
      initialTime: initialTime,
    );
    
    if (time != null) {
      onTimeSelected(time);
    }
  }
  
  IconData _getWeatherIcon(String conditions) {
    final condition = conditions.toLowerCase();
    if (condition.contains('cloud')) return Icons.cloud;
    if (condition.contains('rain')) return Icons.grain;
    if (condition.contains('snow')) return Icons.ac_unit;
    if (condition.contains('thunder')) return Icons.flash_on;
    if (condition.contains('clear')) return Icons.wb_sunny;
    return Icons.wb_cloudy;
  }
  
  Future<void> _saveSettings() async {
    final service = ref.read(weatherNotificationServiceProvider);
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
  
  Future<void> _testMorningNotification() async {
    final service = ref.read(weatherNotificationServiceProvider);
    await service.sendMorningNotification();
    
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Test notification sent'),
        ),
      );
    }
  }
  
  Future<void> _testEveningNotification() async {
    final service = ref.read(weatherNotificationServiceProvider);
    await service.sendEveningNotification();
    
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Test notification sent'),
        ),
      );
    }
  }
  
  Future<void> _testExtremeWeatherAlert() async {
    final service = ref.read(weatherNotificationServiceProvider);
    await service.checkExtremeWeather();
    
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Weather check completed'),
        ),
      );
    }
  }
}