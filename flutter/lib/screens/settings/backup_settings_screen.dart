import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/security/secure_backup_service.dart';
import 'package:koutu/services/security/data_sanitization_service.dart';
import 'package:koutu/providers/security_provider.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:file_picker/file_picker.dart';
import 'package:intl/intl.dart';
import 'dart:io';

class BackupSettingsScreen extends ConsumerStatefulWidget {
  const BackupSettingsScreen({super.key});

  @override
  ConsumerState<BackupSettingsScreen> createState() => _BackupSettingsScreenState();
}

class _BackupSettingsScreenState extends ConsumerState<BackupSettingsScreen> {
  final _dateFormat = DateFormat('MMM d, yyyy h:mm a');
  SecureBackupService? _backupService;
  bool _isLoading = false;
  BackupSettings? _settings;
  List<BackupInfo> _backupHistory = [];
  double _backupProgress = 0.0;
  String _backupStatus = '';

  @override
  void initState() {
    super.initState();
    _initializeService();
  }

  Future<void> _initializeService() async {
    try {
      final encryptionService = await ref.read(encryptionServiceProvider.future);
      final dataSanitizationService = ref.read(dataSanitizationServiceProvider);
      final preferences = await SharedPreferences.getInstance();
      
      _backupService = SecureBackupService(
        encryptionService: encryptionService,
        sanitizationService: dataSanitizationService,
        database: AppDatabase.instance,
        preferences: preferences,
      );
      
      _loadSettings();
      _loadBackupHistory();
    } catch (e) {
      _showError('Failed to initialize backup service: $e');
    }
  }

  void _loadSettings() {
    if (_backupService != null) {
      setState(() {
        _settings = _backupService!.getSettings();
      });
    }
  }

  Future<void> _loadBackupHistory() async {
    if (_backupService == null) return;
    
    final result = await _backupService!.getBackupHistory();
    result.fold(
      (failure) => _showError(failure.message),
      (history) => setState(() => _backupHistory = history),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_backupService == null || _settings == null) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Secure Backup & Restore'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: () => _showInfoDialog(context),
          ),
        ],
      ),
      body: ListView(
        children: [
          _buildBackupStatusCard(),
          _buildAutoBackupSection(),
          _buildBackupOptionsSection(),
          _buildBackupActionsSection(),
          _buildBackupHistorySection(),
        ],
      ),
    );
  }

  Widget _buildBackupStatusCard() {
    return Card(
      margin: const EdgeInsets.all(16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Backup Status',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                Icon(
                  _settings!.isEnabled ? Icons.shield : Icons.shield_outlined,
                  color: _settings!.isEnabled ? Colors.green : Colors.grey,
                ),
              ],
            ),
            const SizedBox(height: 8),
            if (_settings!.lastBackup != null) ...[
              Text(
                'Last backup: ${_dateFormat.format(_settings!.lastBackup!)}',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              Text(
                'Total size: ${_formatSize(_settings!.totalBackupSize)}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ] else ...[
              Text(
                'No backups created yet',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.error,
                ),
              ),
            ],
            const SizedBox(height: 16),
            if (_isLoading) ...[
              LinearProgressIndicator(value: _backupProgress),
              const SizedBox(height: 8),
              Text(
                _backupStatus,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ] else ...[
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _createManualBackup,
                      icon: const Icon(Icons.backup),
                      label: const Text('Create Backup'),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _exportBackup,
                      icon: const Icon(Icons.file_download),
                      label: const Text('Export'),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildAutoBackupSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'AUTO BACKUP',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.backup),
          title: const Text('Enable Backup'),
          subtitle: const Text('Automatically backup your data securely'),
          value: _settings!.isEnabled,
          onChanged: _isLoading ? null : _toggleBackup,
        ),
        SwitchListTile(
          secondary: const Icon(Icons.schedule),
          title: const Text('Auto Backup'),
          subtitle: const Text('Automatically create backups on schedule'),
          value: _settings!.autoBackup,
          onChanged: !_settings!.isEnabled || _isLoading ? null : _toggleAutoBackup,
        ),
        if (_settings!.autoBackup)
          ListTile(
            leading: const Icon(Icons.timer),
            title: const Text('Backup Frequency'),
            subtitle: Text(_getFrequencyName(_settings!.frequency)),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _showFrequencyDialog(),
          ),
      ],
    );
  }

  Widget _buildBackupOptionsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'BACKUP OPTIONS',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.security),
          title: const Text('Encryption'),
          subtitle: const Text('All backups are encrypted with AES-256'),
          trailing: const Icon(Icons.check_circle, color: Colors.green),
        ),
        ListTile(
          leading: const Icon(Icons.privacy_tip),
          title: const Text('Data Sanitization'),
          subtitle: const Text('Sensitive data is sanitized before backup'),
          trailing: const Icon(Icons.check_circle, color: Colors.green),
        ),
        ListTile(
          leading: const Icon(Icons.settings),
          title: const Text('What to Backup'),
          subtitle: const Text('Choose what data to include in backups'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showBackupOptionsDialog(),
        ),
      ],
    );
  }

  Widget _buildBackupActionsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'BACKUP ACTIONS',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.restore, color: Colors.orange),
          title: const Text('Restore from File'),
          subtitle: const Text('Restore data from backup file'),
          onTap: _isLoading ? null : _restoreFromFile,
        ),
      ],
    );
  }

  Widget _buildBackupHistorySection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'BACKUP HISTORY',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        if (_backupHistory.isEmpty)
          const Padding(
            padding: EdgeInsets.all(32),
            child: Center(
              child: Text('No backups yet'),
            ),
          )
        else
          ...List.generate(
            _backupHistory.length,
            (index) => _buildBackupHistoryItem(_backupHistory[index]),
          ),
        const SizedBox(height: 32),
      ],
    );
  }

  Widget _buildBackupHistoryItem(BackupInfo backup) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ListTile(
        leading: const Icon(Icons.backup),
        title: Text('Backup ${backup.id}'),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Created: ${_dateFormat.format(backup.createdAt)}'),
            Text('Size: ${_formatSize(backup.size)}'),
            Text('Data: ${backup.dataTypes.join(', ')}'),
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (value) => _handleBackupAction(value, backup),
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'restore',
              child: ListTile(
                leading: Icon(Icons.restore),
                title: Text('Restore'),
              ),
            ),
            const PopupMenuItem(
              value: 'export',
              child: ListTile(
                leading: Icon(Icons.file_download),
                title: Text('Export'),
              ),
            ),
            const PopupMenuItem(
              value: 'delete',
              child: ListTile(
                leading: Icon(Icons.delete, color: Colors.red),
                title: Text('Delete'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _getFrequencyName(BackupFrequency frequency) {
    switch (frequency) {
      case BackupFrequency.daily:
        return 'Daily';
      case BackupFrequency.weekly:
        return 'Weekly';
      case BackupFrequency.monthly:
        return 'Monthly';
    }
  }

  String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  Future<void> _toggleBackup(bool enabled) async {
    setState(() => _isLoading = true);

    try {
      final updatedSettings = BackupSettings(
        isEnabled: enabled,
        autoBackup: enabled ? _settings!.autoBackup : false,
        frequency: _settings!.frequency,
        lastBackup: _settings!.lastBackup,
        totalBackupSize: _settings!.totalBackupSize,
      );

      final result = await _backupService!.updateSettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          _loadSettings();
          _showSuccess(enabled ? 'Backup enabled' : 'Backup disabled');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _toggleAutoBackup(bool enabled) async {
    setState(() => _isLoading = true);

    try {
      if (enabled) {
        const options = BackupOptions();
        final result = await _backupService!.scheduleAutoBackup(
          frequency: _settings!.frequency,
          options: options,
        );
        
        result.fold(
          (failure) => _showError(failure.message),
          (_) {
            _loadSettings();
            _showSuccess('Auto backup enabled');
          },
        );
      } else {
        final updatedSettings = BackupSettings(
          isEnabled: _settings!.isEnabled,
          autoBackup: false,
          frequency: _settings!.frequency,
          lastBackup: _settings!.lastBackup,
          totalBackupSize: _settings!.totalBackupSize,
        );

        final result = await _backupService!.updateSettings(updatedSettings);
        result.fold(
          (failure) => _showError(failure.message),
          (_) {
            _loadSettings();
            _showSuccess('Auto backup disabled');
          },
        );
      }
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _createManualBackup() async {
    setState(() => _isLoading = true);

    try {
      const options = BackupOptions();
      final result = await _backupService!.createBackup(
        options: options,
        onProgress: (progress) {
          setState(() {
            _backupProgress = progress;
            _backupStatus = 'Creating backup... ${(progress * 100).toInt()}%';
          });
        },
      );

      result.fold(
        (failure) => _showError(failure.message),
        (backupResult) {
          _showSuccess('Backup created successfully');
          _loadSettings();
          _loadBackupHistory();
        },
      );
    } finally {
      setState(() {
        _isLoading = false;
        _backupProgress = 0.0;
        _backupStatus = '';
      });
    }
  }

  Future<void> _exportBackup() async {
    setState(() => _isLoading = true);

    try {
      const options = BackupOptions();
      final result = await _backupService!.exportBackup(options: options);

      result.fold(
        (failure) => _showError(failure.message),
        (backupFile) {
          _showSuccess('Backup exported to ${backupFile.path}');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _restoreFromFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['backup'],
    );

    if (result != null && result.files.single.path != null) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Restore Backup'),
          content: const Text(
            'This will replace your current data with the backup. Continue?'
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
              child: const Text('Restore'),
            ),
          ],
        ),
      );

      if (confirmed == true) {
        setState(() => _isLoading = true);

        try {
          const options = BackupOptions();
          final backupFile = File(result.files.single.path!);
          final restoreResult = await _backupService!.restoreBackup(
            backupFile: backupFile,
            options: options,
            onProgress: (progress) {
              setState(() {
                _backupProgress = progress;
                _backupStatus = 'Restoring backup... ${(progress * 100).toInt()}%';
              });
            },
          );

          restoreResult.fold(
            (failure) => _showError(failure.message),
            (result) {
              _showSuccess('Data restored successfully');
              _loadSettings();
            },
          );
        } finally {
          setState(() {
            _isLoading = false;
            _backupProgress = 0.0;
            _backupStatus = '';
          });
        }
      }
    }
  }

  void _showFrequencyDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Backup Frequency'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: BackupFrequency.values.map((frequency) {
            return RadioListTile<BackupFrequency>(
              title: Text(_getFrequencyName(frequency)),
              value: frequency,
              groupValue: _settings!.frequency,
              onChanged: (value) {
                Navigator.pop(context);
                _updateFrequency(value!);
              },
            );
          }).toList(),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  Future<void> _updateFrequency(BackupFrequency frequency) async {
    final updatedSettings = BackupSettings(
      isEnabled: _settings!.isEnabled,
      autoBackup: _settings!.autoBackup,
      frequency: frequency,
      lastBackup: _settings!.lastBackup,
      totalBackupSize: _settings!.totalBackupSize,
    );

    final result = await _backupService!.updateSettings(updatedSettings);
    result.fold(
      (failure) => _showError(failure.message),
      (_) {
        _loadSettings();
        _showSuccess('Backup frequency updated');
      },
    );
  }

  void _showBackupOptionsDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Backup Options'),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: Icon(Icons.checkroom),
              title: Text('Garments'),
              subtitle: Text('Always included'),
              trailing: Icon(Icons.check_circle, color: Colors.green),
            ),
            ListTile(
              leading: Icon(Icons.style),
              title: Text('Outfits'),
              subtitle: Text('Always included'),
              trailing: Icon(Icons.check_circle, color: Colors.green),
            ),
            ListTile(
              leading: Icon(Icons.settings),
              title: Text('Preferences'),
              subtitle: Text('Always included'),
              trailing: Icon(Icons.check_circle, color: Colors.green),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  void _handleBackupAction(String action, BackupInfo backup) {
    switch (action) {
      case 'restore':
        _restoreSpecificBackup(backup);
        break;
      case 'export':
        _exportSpecificBackup(backup);
        break;
      case 'delete':
        _deleteBackup(backup);
        break;
    }
  }

  Future<void> _restoreSpecificBackup(BackupInfo backup) async {
    _showSuccess('Restore from ${backup.id} coming soon');
  }

  Future<void> _exportSpecificBackup(BackupInfo backup) async {
    _showSuccess('Export of ${backup.id} coming soon');
  }

  Future<void> _deleteBackup(BackupInfo backup) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Backup'),
        content: Text('Are you sure you want to delete backup ${backup.id}?'),
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
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final result = await _backupService!.deleteBackup(backup.id);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          _showSuccess('Backup deleted');
          _loadBackupHistory();
        },
      );
    }
  }

  void _showInfoDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('About Secure Backups'),
        content: const SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Secure backups protect your wardrobe data with military-grade encryption.',
              ),
              SizedBox(height: 16),
              Text(
                '• All backups are encrypted with AES-256\n'
                '• Sensitive data is sanitized before backup\n'
                '• Backups include checksums for integrity\n'
                '• Auto backups run on schedule\n'
                '• Export backups to external storage',
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Got it'),
          ),
        ],
      ),
    );
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: Colors.red,
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