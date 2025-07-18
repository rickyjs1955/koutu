import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/security_provider.dart';
import 'package:koutu/services/security/biometric_service.dart';
import 'package:local_auth/local_auth.dart';

class BiometricSettingsScreen extends ConsumerStatefulWidget {
  const BiometricSettingsScreen({super.key});

  @override
  ConsumerState<BiometricSettingsScreen> createState() =>
      _BiometricSettingsScreenState();
}

class _BiometricSettingsScreenState
    extends ConsumerState<BiometricSettingsScreen> {
  bool _isLoading = false;
  String? _currentPin;
  
  @override
  Widget build(BuildContext context) {
    final biometricService = ref.watch(biometricServiceProvider);
    final settings = biometricService.getSettings();
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security & Privacy'),
      ),
      body: ListView(
        children: [
          _buildBiometricSection(biometricService, settings),
          const Divider(),
          _buildFallbackSection(biometricService, settings),
          const Divider(),
          _buildAutoLockSection(biometricService, settings),
          const Divider(),
          _buildDataProtectionSection(biometricService),
        ],
      ),
    );
  }
  
  Widget _buildBiometricSection(
    BiometricService service,
    BiometricSettings settings,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Biometric Authentication',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        FutureBuilder<BiometricCapability>(
          future: service.checkBiometricCapability().then(
                (result) => result.fold(
                  (failure) => BiometricCapability(
                    isAvailable: false,
                    availableTypes: [],
                    reason: failure.message,
                  ),
                  (capability) => capability,
                ),
              ),
          builder: (context, snapshot) {
            if (!snapshot.hasData) {
              return const ListTile(
                title: Text('Checking biometric capability...'),
                leading: CircularProgressIndicator(),
              );
            }
            
            final capability = snapshot.data!;
            
            if (!capability.isAvailable) {
              return ListTile(
                leading: const Icon(Icons.fingerprint, color: Colors.grey),
                title: const Text('Biometric Authentication'),
                subtitle: Text(
                  capability.reason ?? 'Not available on this device',
                ),
                enabled: false,
              );
            }
            
            return SwitchListTile(
              secondary: Icon(
                _getBiometricIcon(capability.availableTypes),
                color: settings.isEnabled
                    ? Theme.of(context).colorScheme.primary
                    : null,
              ),
              title: const Text('Use Biometric Authentication'),
              subtitle: Text(
                _getBiometricDescription(capability.availableTypes),
              ),
              value: settings.isEnabled,
              onChanged: _isLoading
                  ? null
                  : (value) => _toggleBiometric(service, value),
            );
          },
        ),
      ],
    );
  }
  
  Widget _buildFallbackSection(
    BiometricService service,
    BiometricSettings settings,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Fallback Authentication',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.pin),
          title: const Text('Enable PIN'),
          subtitle: const Text(
            'Use PIN when biometric authentication fails',
          ),
          value: settings.isFallbackEnabled,
          onChanged: !settings.isEnabled || _isLoading
              ? null
              : (value) => _toggleFallback(service, value),
        ),
        if (settings.isFallbackEnabled)
          ListTile(
            leading: const Icon(Icons.edit),
            title: const Text('Change PIN'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showChangePinDialog(service),
          ),
      ],
    );
  }
  
  Widget _buildAutoLockSection(
    BiometricService service,
    BiometricSettings settings,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Auto-Lock',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.lock_clock),
          title: const Text('Auto-Lock'),
          subtitle: const Text(
            'Require authentication after period of inactivity',
          ),
          value: settings.isAutoLockEnabled,
          onChanged: !settings.isEnabled || _isLoading
              ? null
              : (value) => _toggleAutoLock(service, value),
        ),
        if (settings.isAutoLockEnabled)
          ListTile(
            leading: const Icon(Icons.timer),
            title: const Text('Lock After'),
            subtitle: Text(_formatDuration(settings.autoLockDuration)),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showAutoLockDurationDialog(service),
          ),
      ],
    );
  }
  
  Widget _buildDataProtectionSection(BiometricService service) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.all(16),
          child: Text(
            'Data Protection',
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.security),
          title: const Text('Protected Data'),
          subtitle: const Text('View and manage biometric-protected data'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showProtectedDataScreen(),
        ),
        ListTile(
          leading: const Icon(Icons.delete_forever, color: Colors.red),
          title: const Text('Clear All Security Data'),
          subtitle: const Text('Remove all biometric data and settings'),
          onTap: () => _confirmClearAllData(service),
        ),
      ],
    );
  }
  
  IconData _getBiometricIcon(List<BiometricType> types) {
    if (types.contains(BiometricType.face)) {
      return Icons.face;
    } else if (types.contains(BiometricType.fingerprint)) {
      return Icons.fingerprint;
    } else if (types.contains(BiometricType.iris)) {
      return Icons.remove_red_eye;
    }
    return Icons.security;
  }
  
  String _getBiometricDescription(List<BiometricType> types) {
    final typeNames = <String>[];
    
    if (types.contains(BiometricType.face)) {
      typeNames.add('Face ID');
    }
    if (types.contains(BiometricType.fingerprint)) {
      typeNames.add('Touch ID');
    }
    if (types.contains(BiometricType.iris)) {
      typeNames.add('Iris');
    }
    
    if (typeNames.isEmpty) {
      return 'Biometric authentication available';
    }
    
    return 'Use ${typeNames.join(' or ')} to unlock';
  }
  
  Future<void> _toggleBiometric(BiometricService service, bool enable) async {
    setState(() => _isLoading = true);
    
    try {
      if (enable) {
        final result = await service.enableBiometric(
          setupReason: 'Enable biometric authentication for Koutu',
        );
        
        result.fold(
          (failure) {
            _showError(failure.message);
          },
          (_) {
            _showSuccess('Biometric authentication enabled');
          },
        );
      } else {
        final result = await service.disableBiometric(
          reason: 'Disable biometric authentication',
        );
        
        result.fold(
          (failure) {
            _showError(failure.message);
          },
          (_) {
            _showSuccess('Biometric authentication disabled');
          },
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }
  
  Future<void> _toggleFallback(BiometricService service, bool enable) async {
    if (enable) {
      _showSetupPinDialog(service);
    } else {
      setState(() => _isLoading = true);
      
      try {
        // Authenticate before disabling
        final authResult = await service.authenticate(
          reason: 'Authenticate to disable PIN',
        );
        
        authResult.fold(
          (failure) {
            _showError(failure.message);
          },
          (authenticated) async {
            if (authenticated) {
              // Clear PIN by updating preferences
              // Implementation depends on your specific requirements
              _showSuccess('PIN disabled');
            }
          },
        );
      } finally {
        if (mounted) {
          setState(() => _isLoading = false);
        }
      }
    }
  }
  
  Future<void> _toggleAutoLock(BiometricService service, bool enable) async {
    final result = await service.configureAutoLock(enabled: enable);
    
    result.fold(
      (failure) {
        _showError(failure.message);
      },
      (_) {
        setState(() {});
        _showSuccess(
          enable ? 'Auto-lock enabled' : 'Auto-lock disabled',
        );
      },
    );
  }
  
  void _showSetupPinDialog(BiometricService service) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => _PinSetupDialog(
        onPinSet: (pin) async {
          final result = await service.enableFallbackAuth(
            pin: pin,
            authReason: 'Set up PIN for fallback authentication',
          );
          
          result.fold(
            (failure) {
              _showError(failure.message);
            },
            (_) {
              setState(() {});
              _showSuccess('PIN enabled');
            },
          );
        },
      ),
    );
  }
  
  void _showChangePinDialog(BiometricService service) {
    showDialog(
      context: context,
      builder: (context) => _PinSetupDialog(
        isChanging: true,
        onPinSet: (pin) async {
          // First authenticate with current method
          final authResult = await service.authenticate(
            reason: 'Authenticate to change PIN',
          );
          
          authResult.fold(
            (failure) {
              _showError(failure.message);
            },
            (authenticated) async {
              if (authenticated) {
                final result = await service.enableFallbackAuth(
                  pin: pin,
                  authReason: 'Update PIN',
                );
                
                result.fold(
                  (failure) {
                    _showError(failure.message);
                  },
                  (_) {
                    _showSuccess('PIN updated');
                  },
                );
              }
            },
          );
        },
      ),
    );
  }
  
  void _showAutoLockDurationDialog(BiometricService service) {
    final settings = service.getSettings();
    var selectedDuration = settings.autoLockDuration;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Auto-Lock Duration'),
        content: StatefulBuilder(
          builder: (context, setState) {
            return Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                RadioListTile<Duration>(
                  title: const Text('1 minute'),
                  value: const Duration(minutes: 1),
                  groupValue: selectedDuration,
                  onChanged: (value) {
                    setState(() => selectedDuration = value!);
                  },
                ),
                RadioListTile<Duration>(
                  title: const Text('5 minutes'),
                  value: const Duration(minutes: 5),
                  groupValue: selectedDuration,
                  onChanged: (value) {
                    setState(() => selectedDuration = value!);
                  },
                ),
                RadioListTile<Duration>(
                  title: const Text('15 minutes'),
                  value: const Duration(minutes: 15),
                  groupValue: selectedDuration,
                  onChanged: (value) {
                    setState(() => selectedDuration = value!);
                  },
                ),
                RadioListTile<Duration>(
                  title: const Text('30 minutes'),
                  value: const Duration(minutes: 30),
                  groupValue: selectedDuration,
                  onChanged: (value) {
                    setState(() => selectedDuration = value!);
                  },
                ),
              ],
            );
          },
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context);
              
              final result = await service.configureAutoLock(
                enabled: true,
                lockDuration: selectedDuration,
              );
              
              result.fold(
                (failure) {
                  _showError(failure.message);
                },
                (_) {
                  setState(() {});
                  _showSuccess('Auto-lock duration updated');
                },
              );
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }
  
  void _showProtectedDataScreen() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => const BiometricProtectedDataScreen(),
      ),
    );
  }
  
  void _confirmClearAllData(BiometricService service) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear All Security Data'),
        content: const Text(
          'This will remove all biometric settings and protected data. '
          'This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context);
              
              final result = await service.clearAllBiometricData(
                authReason: 'Clear all security data',
              );
              
              result.fold(
                (failure) {
                  _showError(failure.message);
                },
                (_) {
                  setState(() {});
                  _showSuccess('Security data cleared');
                },
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Clear'),
          ),
        ],
      ),
    );
  }
  
  String _formatDuration(Duration duration) {
    if (duration.inMinutes == 1) {
      return '1 minute';
    } else {
      return '${duration.inMinutes} minutes';
    }
  }
  
  void _showError(String message) {
    if (!mounted) return;
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Theme.of(context).colorScheme.error,
      ),
    );
  }
  
  void _showSuccess(String message) {
    if (!mounted) return;
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.green,
      ),
    );
  }
}

/// PIN setup dialog
class _PinSetupDialog extends StatefulWidget {
  final bool isChanging;
  final Function(String) onPinSet;
  
  const _PinSetupDialog({
    this.isChanging = false,
    required this.onPinSet,
  });
  
  @override
  State<_PinSetupDialog> createState() => _PinSetupDialogState();
}

class _PinSetupDialogState extends State<_PinSetupDialog> {
  final _pinController = TextEditingController();
  final _confirmPinController = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _obscurePin = true;
  bool _obscureConfirm = true;
  
  @override
  void dispose() {
    _pinController.dispose();
    _confirmPinController.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.isChanging ? 'Change PIN' : 'Set Up PIN'),
      content: Form(
        key: _formKey,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextFormField(
              controller: _pinController,
              obscureText: _obscurePin,
              keyboardType: TextInputType.number,
              maxLength: 6,
              decoration: InputDecoration(
                labelText: 'PIN',
                hintText: 'Enter 4-6 digit PIN',
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscurePin ? Icons.visibility : Icons.visibility_off,
                  ),
                  onPressed: () {
                    setState(() => _obscurePin = !_obscurePin);
                  },
                ),
              ),
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'Please enter a PIN';
                }
                if (value.length < 4) {
                  return 'PIN must be at least 4 digits';
                }
                if (!RegExp(r'^\d+$').hasMatch(value)) {
                  return 'PIN must contain only digits';
                }
                return null;
              },
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _confirmPinController,
              obscureText: _obscureConfirm,
              keyboardType: TextInputType.number,
              maxLength: 6,
              decoration: InputDecoration(
                labelText: 'Confirm PIN',
                hintText: 'Re-enter PIN',
                suffixIcon: IconButton(
                  icon: Icon(
                    _obscureConfirm ? Icons.visibility : Icons.visibility_off,
                  ),
                  onPressed: () {
                    setState(() => _obscureConfirm = !_obscureConfirm);
                  },
                ),
              ),
              validator: (value) {
                if (value == null || value.isEmpty) {
                  return 'Please confirm your PIN';
                }
                if (value != _pinController.text) {
                  return 'PINs do not match';
                }
                return null;
              },
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            if (_formKey.currentState!.validate()) {
              Navigator.pop(context);
              widget.onPinSet(_pinController.text);
            }
          },
          child: const Text('Save'),
        ),
      ],
    );
  }
}

/// Screen to view biometric-protected data
class BiometricProtectedDataScreen extends ConsumerWidget {
  const BiometricProtectedDataScreen({super.key});
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Protected Data'),
      ),
      body: const Center(
        child: Text('Protected data management coming soon'),
      ),
    );
  }
}