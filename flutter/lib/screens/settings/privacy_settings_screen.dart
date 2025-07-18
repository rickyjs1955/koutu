import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/services/security/privacy_service.dart';
import 'package:koutu/providers/security_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';

class PrivacySettingsScreen extends ConsumerStatefulWidget {
  const PrivacySettingsScreen({super.key});

  @override
  ConsumerState<PrivacySettingsScreen> createState() => _PrivacySettingsScreenState();
}

class _PrivacySettingsScreenState extends ConsumerState<PrivacySettingsScreen> {
  final _dateFormat = DateFormat('MMM d, yyyy h:mm a');
  PrivacyService? _privacyService;
  PrivacySettings? _settings;
  bool _isLoading = false;
  
  @override
  void initState() {
    super.initState();
    _initializeService();
  }
  
  Future<void> _initializeService() async {
    try {
      final sanitizationService = ref.read(dataSanitizationServiceProvider);
      final secureStorageService = await ref.read(secureStorageServiceProvider.future);
      final preferences = await SharedPreferences.getInstance();
      
      _privacyService = PrivacyService(
        sanitizationService: sanitizationService,
        secureStorage: secureStorageService,
        database: null as dynamic, // Will be replaced with actual database
        preferences: preferences,
      );
      
      _loadSettings();
    } catch (e) {
      _showError('Failed to initialize privacy service: $e');
    }
  }
  
  void _loadSettings() {
    if (_privacyService != null) {
      setState(() {
        _settings = _privacyService!.getPrivacySettings();
      });
    }
  }
  
  @override
  Widget build(BuildContext context) {
    if (_privacyService == null || _settings == null) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Privacy & Data'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: () => _showPrivacyInfoDialog(),
          ),
        ],
      ),
      body: ListView(
        children: [
          _buildPrivacyPolicySection(),
          _buildDataConsentSection(),
          _buildDataRetentionSection(),
          _buildDataRightsSection(),
          _buildPrivacyAuditSection(),
          _buildDangerZone(),
        ],
      ),
    );
  }
  
  Widget _buildPrivacyPolicySection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'PRIVACY POLICY',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: Icon(
            _settings!.privacyPolicyAccepted ? Icons.check_circle : Icons.warning,
            color: _settings!.privacyPolicyAccepted ? Colors.green : Colors.orange,
          ),
          title: const Text('Privacy Policy'),
          subtitle: Text(
            _settings!.privacyPolicyAccepted
                ? 'Accepted ${_settings!.lastPrivacyUpdate != null ? _dateFormat.format(_settings!.lastPrivacyUpdate!) : 'recently'}'
                : 'Review and accept our privacy policy',
          ),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showPrivacyPolicyDialog(),
        ),
      ],
    );
  }
  
  Widget _buildDataConsentSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'DATA CONSENT',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.data_usage),
          title: const Text('Data Collection'),
          subtitle: const Text('Allow collection of usage data for app improvement'),
          value: _settings!.dataCollectionConsent,
          onChanged: _isLoading ? null : (value) => _updateConsent(dataCollection: value),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.analytics),
          title: const Text('Analytics'),
          subtitle: const Text('Help us improve with anonymous usage analytics'),
          value: _settings!.analyticsConsent,
          onChanged: _isLoading ? null : (value) => _updateConsent(analytics: value),
        ),
        SwitchListTile(
          secondary: const Icon(Icons.campaign),
          title: const Text('Marketing'),
          subtitle: const Text('Receive promotional content and updates'),
          value: _settings!.marketingConsent,
          onChanged: _isLoading ? null : (value) => _updateConsent(marketing: value),
        ),
      ],
    );
  }
  
  Widget _buildDataRetentionSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'DATA RETENTION',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.schedule),
          title: const Text('Data Retention Period'),
          subtitle: Text('Keep my data for ${_formatRetentionPeriod(_settings!.dataRetentionPeriod)}'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showRetentionPeriodDialog(),
        ),
        ListTile(
          leading: const Icon(Icons.cleaning_services),
          title: const Text('Check Data Retention'),
          subtitle: const Text('Review data that may be deleted'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _checkDataRetention(),
        ),
      ],
    );
  }
  
  Widget _buildDataRightsSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'YOUR DATA RIGHTS',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.download, color: Colors.blue),
          title: const Text('Export My Data'),
          subtitle: const Text('Download all your data (GDPR Article 20)'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showDataExportDialog(),
        ),
        ListTile(
          leading: const Icon(Icons.delete_forever, color: Colors.red),
          title: const Text('Delete My Data'),
          subtitle: const Text('Right to be forgotten (GDPR Article 17)'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showDataDeletionDialog(),
        ),
      ],
    );
  }
  
  Widget _buildPrivacyAuditSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'PRIVACY AUDIT',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.history),
          title: const Text('Privacy Activity Log'),
          subtitle: const Text('View your privacy-related activities'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showPrivacyAuditDialog(),
        ),
      ],
    );
  }
  
  Widget _buildDangerZone() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Padding(
          padding: EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Text(
            'DANGER ZONE',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 12,
              color: Colors.red,
            ),
          ),
        ),
        ListTile(
          leading: const Icon(Icons.clear_all, color: Colors.red),
          title: const Text('Clear All Privacy Data'),
          subtitle: const Text('Reset all privacy settings and audit logs'),
          trailing: const Icon(Icons.chevron_right),
          onTap: () => _showClearAllDataDialog(),
        ),
        const SizedBox(height: 32),
      ],
    );
  }
  
  Future<void> _updateConsent({
    bool? dataCollection,
    bool? analytics,
    bool? marketing,
  }) async {
    setState(() => _isLoading = true);
    
    try {
      final updatedSettings = PrivacySettings(
        privacyPolicyAccepted: _settings!.privacyPolicyAccepted,
        dataCollectionConsent: dataCollection ?? _settings!.dataCollectionConsent,
        analyticsConsent: analytics ?? _settings!.analyticsConsent,
        marketingConsent: marketing ?? _settings!.marketingConsent,
        dataRetentionPeriod: _settings!.dataRetentionPeriod,
        lastPrivacyUpdate: _settings!.lastPrivacyUpdate,
      );
      
      final result = await _privacyService!.updatePrivacySettings(updatedSettings);
      result.fold(
        (failure) => _showError(failure.message),
        (_) {
          _loadSettings();
          _showSuccess('Privacy settings updated');
        },
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _showPrivacyPolicyDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Privacy Policy'),
        content: const SingleChildScrollView(
          child: Text(
            'This is where the privacy policy content would be displayed. '
            'It should include information about data collection, usage, '
            'storage, and user rights under GDPR and other privacy laws.',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context);
              final result = await _privacyService!.acceptPrivacyPolicy('1.0');
              result.fold(
                (failure) => _showError(failure.message),
                (_) {
                  _loadSettings();
                  _showSuccess('Privacy policy accepted');
                },
              );
            },
            child: const Text('Accept'),
          ),
        ],
      ),
    );
  }
  
  void _showRetentionPeriodDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Data Retention Period'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: DataRetentionPeriod.values.map((period) {
            return RadioListTile<DataRetentionPeriod>(
              title: Text(_formatRetentionPeriod(period)),
              value: period,
              groupValue: _settings!.dataRetentionPeriod,
              onChanged: (value) async {
                Navigator.pop(context);
                if (value != null) {
                  await _updateRetentionPeriod(value);
                }
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
  
  Future<void> _updateRetentionPeriod(DataRetentionPeriod period) async {
    final updatedSettings = PrivacySettings(
      privacyPolicyAccepted: _settings!.privacyPolicyAccepted,
      dataCollectionConsent: _settings!.dataCollectionConsent,
      analyticsConsent: _settings!.analyticsConsent,
      marketingConsent: _settings!.marketingConsent,
      dataRetentionPeriod: period,
      lastPrivacyUpdate: _settings!.lastPrivacyUpdate,
    );
    
    final result = await _privacyService!.updatePrivacySettings(updatedSettings);
    result.fold(
      (failure) => _showError(failure.message),
      (_) {
        _loadSettings();
        _showSuccess('Data retention period updated');
      },
    );
  }
  
  Future<void> _checkDataRetention() async {
    setState(() => _isLoading = true);
    
    try {
      final result = await _privacyService!.checkDataRetentionCompliance();
      result.fold(
        (failure) => _showError(failure.message),
        (report) => _showDataRetentionReport(report),
      );
    } finally {
      setState(() => _isLoading = false);
    }
  }
  
  void _showDataRetentionReport(DataRetentionReport report) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Data Retention Report'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Status: ${report.complianceStatus.name}'),
              Text('Retention Period: ${_formatRetentionPeriod(report.retentionPeriod)}'),
              Text('Cutoff Date: ${_dateFormat.format(report.cutoffDate)}'),
              const SizedBox(height: 16),
              if (report.itemsToDelete.isNotEmpty) ...[
                const Text('Items to be deleted:'),
                const SizedBox(height: 8),
                ...report.itemsToDelete.map((item) => 
                  Text('• ${item.type}: ${item.description}'),
                ),
              ] else ...[
                const Text('No items need to be deleted.'),
              ],
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
          if (report.itemsToDelete.isNotEmpty)
            ElevatedButton(
              onPressed: () async {
                Navigator.pop(context);
                await _enforceDataRetention();
              },
              child: const Text('Enforce Policy'),
            ),
        ],
      ),
    );
  }
  
  Future<void> _enforceDataRetention() async {
    final result = await _privacyService!.enforceDataRetentionPolicy();
    result.fold(
      (failure) => _showError(failure.message),
      (result) => _showSuccess('Data retention policy enforced. Deleted ${result.deletedItems} items.'),
    );
  }
  
  void _showDataExportDialog() {
    showDialog(
      context: context,
      builder: (context) => _DataExportDialog(
        onExport: (request) async {
          final result = await _privacyService!.requestDataExport(request);
          result.fold(
            (failure) => _showError(failure.message),
            (exportResult) => _showSuccess('Data export completed. Size: ${exportResult.size} bytes'),
          );
        },
      ),
    );
  }
  
  void _showDataDeletionDialog() {
    showDialog(
      context: context,
      builder: (context) => _DataDeletionDialog(
        onDelete: (request) async {
          final result = await _privacyService!.requestDataDeletion(request);
          result.fold(
            (failure) => _showError(failure.message),
            (deletionResult) => _showSuccess('Data deletion completed. Deleted ${deletionResult.deletedItems.values.fold(0, (a, b) => a + b)} items.'),
          );
        },
      ),
    );
  }
  
  void _showPrivacyAuditDialog() async {
    final result = await _privacyService!.getPrivacyAuditLog();
    result.fold(
      (failure) => _showError(failure.message),
      (auditLog) => showDialog(
        context: context,
        builder: (context) => _PrivacyAuditDialog(auditLog: auditLog),
      ),
    );
  }
  
  void _showClearAllDataDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear All Privacy Data'),
        content: const Text(
          'This will reset all privacy settings and delete audit logs. This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context);
              final result = await _privacyService!.clearAllPrivacyData();
              result.fold(
                (failure) => _showError(failure.message),
                (_) {
                  _loadSettings();
                  _showSuccess('All privacy data cleared');
                },
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
            ),
            child: const Text('Clear All'),
          ),
        ],
      ),
    );
  }
  
  void _showPrivacyInfoDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Privacy & Data Protection'),
        content: const SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Your privacy is important to us. This screen allows you to:',
              ),
              SizedBox(height: 16),
              Text(
                '• Control what data we collect\n'
                '• Set how long we keep your data\n'
                '• Export your data (GDPR Article 20)\n'
                '• Request data deletion (GDPR Article 17)\n'
                '• View privacy activity logs\n'
                '• Manage consent preferences',
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
  
  String _formatRetentionPeriod(DataRetentionPeriod period) {
    switch (period) {
      case DataRetentionPeriod.oneYear:
        return '1 year';
      case DataRetentionPeriod.twoYears:
        return '2 years';
      case DataRetentionPeriod.threeYears:
        return '3 years';
      case DataRetentionPeriod.indefinite:
        return 'Indefinite';
    }
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

class _DataExportDialog extends StatefulWidget {
  final Function(DataExportRequest) onExport;
  
  const _DataExportDialog({required this.onExport});
  
  @override
  State<_DataExportDialog> createState() => _DataExportDialogState();
}

class _DataExportDialogState extends State<_DataExportDialog> {
  DataExportFormat _format = DataExportFormat.json;
  bool _includePersonalData = true;
  bool _includeAnalytics = false;
  bool _includePurchaseHistory = false;
  
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Export My Data'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Choose what data to export:'),
            const SizedBox(height: 16),
            CheckboxListTile(
              title: const Text('Personal Data'),
              value: _includePersonalData,
              onChanged: (value) => setState(() => _includePersonalData = value!),
            ),
            CheckboxListTile(
              title: const Text('Analytics'),
              value: _includeAnalytics,
              onChanged: (value) => setState(() => _includeAnalytics = value!),
            ),
            CheckboxListTile(
              title: const Text('Purchase History'),
              value: _includePurchaseHistory,
              onChanged: (value) => setState(() => _includePurchaseHistory = value!),
            ),
            const SizedBox(height: 16),
            const Text('Export format:'),
            ...DataExportFormat.values.map((format) => 
              RadioListTile<DataExportFormat>(
                title: Text(format.name.toUpperCase()),
                value: format,
                groupValue: _format,
                onChanged: (value) => setState(() => _format = value!),
              ),
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
            Navigator.pop(context);
            widget.onExport(DataExportRequest(
              format: _format,
              includePersonalData: _includePersonalData,
              includeAnalytics: _includeAnalytics,
              includePurchaseHistory: _includePurchaseHistory,
            ));
          },
          child: const Text('Export'),
        ),
      ],
    );
  }
}

class _DataDeletionDialog extends StatefulWidget {
  final Function(DataDeletionRequest) onDelete;
  
  const _DataDeletionDialog({required this.onDelete});
  
  @override
  State<_DataDeletionDialog> createState() => _DataDeletionDialogState();
}

class _DataDeletionDialogState extends State<_DataDeletionDialog> {
  bool _deletePersonalData = false;
  bool _deleteAppData = false;
  bool _deleteAnalytics = false;
  final _reasonController = TextEditingController();
  
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Delete My Data'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Choose what data to delete:'),
            const SizedBox(height: 16),
            CheckboxListTile(
              title: const Text('Personal Data'),
              subtitle: const Text('Profile information, preferences'),
              value: _deletePersonalData,
              onChanged: (value) => setState(() => _deletePersonalData = value!),
            ),
            CheckboxListTile(
              title: const Text('App Data'),
              subtitle: const Text('Garments, outfits, wardrobe data'),
              value: _deleteAppData,
              onChanged: (value) => setState(() => _deleteAppData = value!),
            ),
            CheckboxListTile(
              title: const Text('Analytics'),
              subtitle: const Text('Usage statistics, crash reports'),
              value: _deleteAnalytics,
              onChanged: (value) => setState(() => _deleteAnalytics = value!),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _reasonController,
              decoration: const InputDecoration(
                labelText: 'Reason for deletion',
                hintText: 'Optional',
              ),
              maxLines: 3,
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
            Navigator.pop(context);
            widget.onDelete(DataDeletionRequest(
              deletePersonalData: _deletePersonalData,
              deleteAppData: _deleteAppData,
              deleteAnalytics: _deleteAnalytics,
              reason: _reasonController.text.trim(),
            ));
          },
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.red,
          ),
          child: const Text('Delete'),
        ),
      ],
    );
  }
}

class _PrivacyAuditDialog extends StatelessWidget {
  final List<PrivacyAuditEntry> auditLog;
  final DateFormat _dateFormat = DateFormat('MMM d, yyyy h:mm a');
  
  _PrivacyAuditDialog({required this.auditLog});
  
  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Privacy Activity Log'),
      content: SizedBox(
        width: double.maxFinite,
        child: ListView.builder(
          shrinkWrap: true,
          itemCount: auditLog.length,
          itemBuilder: (context, index) {
            final entry = auditLog[index];
            return ListTile(
              title: Text(entry.description),
              subtitle: Text(_dateFormat.format(entry.timestamp)),
              leading: _getActionIcon(entry.action),
            );
          },
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Close'),
        ),
      ],
    );
  }
  
  Widget _getActionIcon(PrivacyAction action) {
    switch (action) {
      case PrivacyAction.privacyPolicyAccepted:
        return const Icon(Icons.check_circle, color: Colors.green);
      case PrivacyAction.settingsUpdated:
        return const Icon(Icons.settings, color: Colors.blue);
      case PrivacyAction.dataExportRequested:
        return const Icon(Icons.download, color: Colors.orange);
      case PrivacyAction.dataDeletionRequested:
        return const Icon(Icons.delete, color: Colors.red);
      case PrivacyAction.dataRetentionEnforced:
        return const Icon(Icons.cleaning_services, color: Colors.purple);
      case PrivacyAction.consentWithdrawn:
        return const Icon(Icons.cancel, color: Colors.red);
      case PrivacyAction.consentGranted:
        return const Icon(Icons.check, color: Colors.green);
    }
  }
}