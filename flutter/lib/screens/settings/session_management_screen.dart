import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/session_provider.dart';
import 'package:koutu/services/session/session_manager.dart';
import 'package:koutu/widgets/common/error_view.dart';
import 'package:koutu/widgets/common/loading_indicator.dart';
import 'package:intl/intl.dart';

/// Screen for managing active sessions across devices
class SessionManagementScreen extends ConsumerStatefulWidget {
  const SessionManagementScreen({super.key});

  @override
  ConsumerState<SessionManagementScreen> createState() => _SessionManagementScreenState();
}

class _SessionManagementScreenState extends ConsumerState<SessionManagementScreen> {
  final _dateFormat = DateFormat('MMM d, yyyy h:mm a');
  
  @override
  void initState() {
    super.initState();
    // Refresh active sessions on screen load
    Future.microtask(() {
      ref.read(sessionManagerProvider).getActiveSessions();
    });
  }
  
  @override
  Widget build(BuildContext context) {
    final sessionManager = ref.watch(sessionManagerProvider);
    final currentSession = sessionManager.getCurrentSession();
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Active Sessions'),
        actions: [
          PopupMenuButton<String>(
            onSelected: (value) async {
              if (value == 'revoke_all') {
                await _showRevokeAllDialog();
              }
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'revoke_all',
                child: Text('Revoke All Other Sessions'),
              ),
            ],
          ),
        ],
      ),
      body: StreamBuilder<List<SessionInfo>>(
        stream: sessionManager.activeSessions,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: LoadingIndicator());
          }
          
          if (snapshot.hasError) {
            return ErrorView(
              error: snapshot.error.toString(),
              onRetry: () {
                sessionManager.getActiveSessions();
              },
            );
          }
          
          final sessions = snapshot.data ?? [];
          
          if (sessions.isEmpty) {
            return const Center(
              child: Text('No active sessions'),
            );
          }
          
          return RefreshIndicator(
            onRefresh: () async {
              await sessionManager.getActiveSessions();
            },
            child: ListView.builder(
              padding: const EdgeInsets.all(16),
              itemCount: sessions.length,
              itemBuilder: (context, index) {
                final session = sessions[index];
                final isCurrentSession = session.id == currentSession?.id;
                
                return Card(
                  margin: const EdgeInsets.only(bottom: 12),
                  child: ListTile(
                    leading: _getDeviceIcon(session.deviceType),
                    title: Text(
                      session.deviceName,
                      style: TextStyle(
                        fontWeight: isCurrentSession ? FontWeight.bold : FontWeight.normal,
                      ),
                    ),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(session.deviceOS),
                        Text(
                          'Last active: ${_dateFormat.format(session.lastActiveAt)}',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                        if (isCurrentSession)
                          Text(
                            'This device',
                            style: TextStyle(
                              color: Theme.of(context).colorScheme.primary,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                      ],
                    ),
                    trailing: isCurrentSession
                        ? null
                        : IconButton(
                            icon: const Icon(Icons.close),
                            onPressed: () => _revokeSession(session),
                          ),
                    isThreeLine: true,
                  ),
                );
              },
            ),
          );
        },
      ),
    );
  }
  
  Widget _getDeviceIcon(String deviceType) {
    IconData iconData;
    Color? color;
    
    switch (deviceType) {
      case 'android':
        iconData = Icons.phone_android;
        color = Colors.green;
        break;
      case 'ios':
        iconData = Icons.phone_iphone;
        color = Colors.grey;
        break;
      case 'web':
        iconData = Icons.computer;
        color = Colors.blue;
        break;
      default:
        iconData = Icons.devices;
        color = null;
    }
    
    return Icon(
      iconData,
      size: 32,
      color: color,
    );
  }
  
  Future<void> _revokeSession(SessionInfo session) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Revoke Session'),
        content: Text(
          'Are you sure you want to sign out of ${session.deviceName}?'
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Revoke'),
          ),
        ],
      ),
    );
    
    if (confirmed == true && mounted) {
      final sessionManager = ref.read(sessionManagerProvider);
      final result = await sessionManager.revokeSession(session.id);
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to revoke session: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Session revoked successfully'),
            ),
          );
        },
      );
    }
  }
  
  Future<void> _showRevokeAllDialog() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Revoke All Other Sessions'),
        content: const Text(
          'This will sign out all other devices. You\'ll remain signed in on this device.'
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
            ),
            child: const Text('Revoke All'),
          ),
        ],
      ),
    );
    
    if (confirmed == true && mounted) {
      final sessionManager = ref.read(sessionManagerProvider);
      final result = await sessionManager.revokeAllOtherSessions();
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to revoke sessions: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('All other sessions revoked successfully'),
            ),
          );
        },
      );
    }
  }
}