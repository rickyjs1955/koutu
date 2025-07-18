import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/session_provider.dart';
import 'package:koutu/services/session/session_manager.dart';
import 'package:intl/intl.dart';

/// Screen shown when device limit is reached
class DeviceLimitScreen extends ConsumerWidget {
  const DeviceLimitScreen({super.key});
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final activeSessionsAsync = ref.watch(activeSessionsProvider);
    final dateFormat = DateFormat('MMM d, yyyy');
    
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.devices_other,
                size: 80,
                color: Theme.of(context).colorScheme.error,
              ),
              const SizedBox(height: 24),
              Text(
                'Device Limit Reached',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              const SizedBox(height: 16),
              Text(
                'You\'ve reached the maximum number of devices (5) that can be logged in simultaneously.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyLarge,
              ),
              const SizedBox(height: 32),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Active Devices',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      activeSessionsAsync.when(
                        data: (sessions) => Column(
                          children: sessions.map((session) {
                            return ListTile(
                              dense: true,
                              leading: _getDeviceIcon(session.deviceType),
                              title: Text(session.deviceName),
                              subtitle: Text(
                                'Last active: ${dateFormat.format(session.lastActiveAt)}',
                              ),
                              trailing: IconButton(
                                icon: const Icon(Icons.close),
                                onPressed: () => _revokeSession(context, ref, session),
                              ),
                            );
                          }).toList(),
                        ),
                        loading: () => const Center(
                          child: CircularProgressIndicator(),
                        ),
                        error: (error, stack) => Text(
                          'Failed to load sessions: $error',
                          style: TextStyle(color: Theme.of(context).colorScheme.error),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 24),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  OutlinedButton(
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    child: const Text('Cancel'),
                  ),
                  ElevatedButton(
                    onPressed: () => _revokeAllAndContinue(context, ref),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.error,
                    ),
                    child: const Text('Remove All & Continue'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _getDeviceIcon(String deviceType) {
    IconData iconData;
    
    switch (deviceType) {
      case 'android':
        iconData = Icons.phone_android;
        break;
      case 'ios':
        iconData = Icons.phone_iphone;
        break;
      case 'web':
        iconData = Icons.computer;
        break;
      default:
        iconData = Icons.devices;
    }
    
    return Icon(iconData, size: 20);
  }
  
  Future<void> _revokeSession(
    BuildContext context,
    WidgetRef ref,
    SessionInfo session,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Remove Device'),
        content: Text('Remove ${session.deviceName} from your account?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    
    if (confirmed == true) {
      final sessionManager = ref.read(sessionManagerProvider);
      final result = await sessionManager.revokeSession(session.id);
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to remove device: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          // Check if we can now continue
          _checkAndContinue(context, ref);
        },
      );
    }
  }
  
  Future<void> _revokeAllAndContinue(BuildContext context, WidgetRef ref) async {
    final sessionManager = ref.read(sessionManagerProvider);
    final result = await sessionManager.revokeAllOtherSessions();
    
    result.fold(
      (failure) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to remove devices: ${failure.message}'),
            backgroundColor: Colors.red,
          ),
        );
      },
      (_) {
        Navigator.pop(context, true); // Continue with login
      },
    );
  }
  
  Future<void> _checkAndContinue(BuildContext context, WidgetRef ref) async {
    final sessionManager = ref.read(sessionManagerProvider);
    final limitResult = await sessionManager.isDeviceLimitReached();
    
    limitResult.fold(
      (failure) => null,
      (isReached) {
        if (!isReached) {
          Navigator.pop(context, true); // Continue with login
        }
      },
    );
  }
}