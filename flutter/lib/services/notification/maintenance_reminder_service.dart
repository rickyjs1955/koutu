import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/services/notification/push_notification_service.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:async';
import 'dart:convert';

/// Service for garment maintenance and cleaning reminders
class MaintenanceReminderService {
  final PushNotificationService _notificationService;
  final AppDatabase _database;
  
  // Settings
  MaintenanceSettings _settings = const MaintenanceSettings();
  
  // Active maintenance records
  final Map<String, MaintenanceRecord> _maintenanceRecords = {};
  
  // Timers
  Timer? _dailyCheckTimer;
  final Map<String, Timer> _reminderTimers = {};
  
  MaintenanceReminderService({
    required PushNotificationService notificationService,
    required AppDatabase database,
  })  : _notificationService = notificationService,
        _database = database;
  
  /// Initialize maintenance reminder service
  Future<void> initialize() async {
    await _loadSettings();
    await _loadMaintenanceRecords();
    
    if (_settings.enabled) {
      _startDailyCheck();
      _scheduleAllReminders();
    }
  }
  
  /// Record garment wear
  Future<Either<Failure, void>> recordWear({
    required String garmentId,
    DateTime? wearDate,
  }) async {
    try {
      final date = wearDate ?? DateTime.now();
      
      // Update garment wear count and last worn date
      final garment = await (_database.select(_database.garments)
        ..where((tbl) => tbl.id.equals(garmentId)))
        .getSingleOrNull();
      
      if (garment == null) {
        return Left(DatabaseFailure('Garment not found'));
      }
      
      // Update wear count
      await (_database.update(_database.garments)
        ..where((tbl) => tbl.id.equals(garmentId)))
        .write(GarmentsCompanion(
          wearCount: Value((garment.wearCount ?? 0) + 1),
          lastWornDate: Value(date),
        ));
      
      // Update maintenance record
      final record = _maintenanceRecords[garmentId] ?? MaintenanceRecord(
        garmentId: garmentId,
        lastCleanedDate: garment.createdAt,
        wearsSinceLastClean: 0,
        lastWornDate: date,
        needsCleaning: false,
        needsMaintenance: false,
      );
      
      final updatedRecord = record.copyWith(
        wearsSinceLastClean: record.wearsSinceLastClean + 1,
        lastWornDate: date,
      );
      
      _maintenanceRecords[garmentId] = updatedRecord;
      await _saveMaintenanceRecords();
      
      // Check if cleaning needed
      await _checkCleaningNeeded(garmentId);
      
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to record wear: $e'));
    }
  }
  
  /// Record garment cleaning
  Future<Either<Failure, void>> recordCleaning({
    required String garmentId,
    CleaningType cleaningType = CleaningType.regular,
    DateTime? cleaningDate,
  }) async {
    try {
      final date = cleaningDate ?? DateTime.now();
      
      // Update maintenance record
      final record = _maintenanceRecords[garmentId];
      if (record == null) {
        return Left(DatabaseFailure('No maintenance record found'));
      }
      
      final updatedRecord = record.copyWith(
        lastCleanedDate: date,
        wearsSinceLastClean: 0,
        needsCleaning: false,
        lastCleaningType: cleaningType,
      );
      
      _maintenanceRecords[garmentId] = updatedRecord;
      await _saveMaintenanceRecords();
      
      // Cancel any active cleaning reminders
      _cancelReminder('clean_$garmentId');
      
      // Schedule next maintenance check if needed
      if (cleaningType == CleaningType.deepClean || 
          cleaningType == CleaningType.professionalCare) {
        await _scheduleMaintenanceCheck(garmentId, date);
      }
      
      return const Right(null);
    } catch (e) {
      return Left(DatabaseFailure('Failed to record cleaning: $e'));
    }
  }
  
  /// Get maintenance status for garment
  Future<Either<Failure, MaintenanceStatus>> getMaintenanceStatus(
    String garmentId,
  ) async {
    try {
      final garment = await (_database.select(_database.garments)
        ..where((tbl) => tbl.id.equals(garmentId)))
        .getSingleOrNull();
      
      if (garment == null) {
        return Left(DatabaseFailure('Garment not found'));
      }
      
      final record = _maintenanceRecords[garmentId];
      if (record == null) {
        // Create new record
        final newRecord = MaintenanceRecord(
          garmentId: garmentId,
          lastCleanedDate: garment.createdAt,
          wearsSinceLastClean: 0,
          lastWornDate: garment.lastWornDate,
          needsCleaning: false,
          needsMaintenance: false,
        );
        _maintenanceRecords[garmentId] = newRecord;
        await _saveMaintenanceRecords();
        
        return Right(MaintenanceStatus(
          garment: garment,
          record: newRecord,
          recommendations: [],
        ));
      }
      
      // Generate recommendations
      final recommendations = _generateMaintenanceRecommendations(garment, record);
      
      return Right(MaintenanceStatus(
        garment: garment,
        record: record,
        recommendations: recommendations,
      ));
    } catch (e) {
      return Left(DatabaseFailure('Failed to get maintenance status: $e'));
    }
  }
  
  /// Get garments needing maintenance
  Future<Either<Failure, List<MaintenanceItem>>> getMaintenanceQueue() async {
    try {
      final items = <MaintenanceItem>[];
      
      // Check all garments
      final garments = await _database.select(_database.garments).get();
      
      for (final garment in garments) {
        final record = _maintenanceRecords[garment.id];
        if (record != null && (record.needsCleaning || record.needsMaintenance)) {
          final priority = _calculateMaintenancePriority(garment, record);
          
          items.add(MaintenanceItem(
            garment: garment,
            record: record,
            priority: priority,
            recommendations: _generateMaintenanceRecommendations(garment, record),
          ));
        }
      }
      
      // Sort by priority
      items.sort((a, b) => b.priority.index.compareTo(a.priority.index));
      
      return Right(items);
    } catch (e) {
      return Left(DatabaseFailure('Failed to get maintenance queue: $e'));
    }
  }
  
  /// Schedule maintenance reminder
  Future<Either<Failure, void>> scheduleMaintenanceReminder({
    required String garmentId,
    required MaintenanceType type,
    required DateTime reminderDate,
  }) async {
    try {
      final garment = await (_database.select(_database.garments)
        ..where((tbl) => tbl.id.equals(garmentId)))
        .getSingleOrNull();
      
      if (garment == null) {
        return Left(DatabaseFailure('Garment not found'));
      }
      
      // Cancel existing reminder
      _cancelReminder('${type.name}_$garmentId');
      
      // Schedule new reminder
      final now = DateTime.now();
      if (reminderDate.isAfter(now)) {
        final duration = reminderDate.difference(now);
        
        _reminderTimers['${type.name}_$garmentId'] = Timer(duration, () async {
          await _sendMaintenanceReminder(garment, type);
        });
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to schedule reminder: $e'));
    }
  }
  
  /// Update settings
  Future<Either<Failure, void>> updateSettings(MaintenanceSettings settings) async {
    try {
      _settings = settings;
      await _saveSettings();
      
      // Restart services if needed
      _dailyCheckTimer?.cancel();
      _cancelAllReminders();
      
      if (settings.enabled) {
        _startDailyCheck();
        _scheduleAllReminders();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to update settings: $e'));
    }
  }
  
  /// Get current settings
  MaintenanceSettings getSettings() => _settings;
  
  // Private methods
  
  void _startDailyCheck() {
    // Check every day at 10 AM
    final now = DateTime.now();
    final checkTime = DateTime(now.year, now.month, now.day, 10, 0);
    
    var nextCheck = checkTime;
    if (now.isAfter(checkTime)) {
      nextCheck = checkTime.add(const Duration(days: 1));
    }
    
    final duration = nextCheck.difference(now);
    
    Timer(duration, () {
      _performDailyCheck();
      
      // Schedule next daily check
      _dailyCheckTimer = Timer.periodic(
        const Duration(days: 1),
        (_) => _performDailyCheck(),
      );
    });
  }
  
  Future<void> _performDailyCheck() async {
    if (!_settings.enabled) return;
    
    // Check all garments
    final garments = await _database.select(_database.garments).get();
    
    for (final garment in garments) {
      await _checkCleaningNeeded(garment.id);
      await _checkMaintenanceNeeded(garment.id);
    }
    
    // Send summary notification if needed
    await _sendMaintenanceSummary();
  }
  
  Future<void> _checkCleaningNeeded(String garmentId) async {
    final record = _maintenanceRecords[garmentId];
    if (record == null) return;
    
    final garment = await (_database.select(_database.garments)
      ..where((tbl) => tbl.id.equals(garmentId)))
      .getSingleOrNull();
    
    if (garment == null) return;
    
    // Determine cleaning frequency based on garment type
    final cleaningFrequency = _getCleaningFrequency(garment);
    
    bool needsCleaning = false;
    
    // Check wear count
    if (record.wearsSinceLastClean >= cleaningFrequency.wearCount) {
      needsCleaning = true;
    }
    
    // Check time since last clean
    final daysSinceClean = DateTime.now().difference(record.lastCleanedDate).inDays;
    if (daysSinceClean >= cleaningFrequency.maxDays) {
      needsCleaning = true;
    }
    
    if (needsCleaning != record.needsCleaning) {
      final updatedRecord = record.copyWith(needsCleaning: needsCleaning);
      _maintenanceRecords[garmentId] = updatedRecord;
      await _saveMaintenanceRecords();
      
      if (needsCleaning && _settings.cleaningReminders) {
        await _sendCleaningReminder(garment);
      }
    }
  }
  
  Future<void> _checkMaintenanceNeeded(String garmentId) async {
    final record = _maintenanceRecords[garmentId];
    if (record == null) return;
    
    final garment = await (_database.select(_database.garments)
      ..where((tbl) => tbl.id.equals(garmentId)))
      .getSingleOrNull();
    
    if (garment == null) return;
    
    bool needsMaintenance = false;
    
    // Check special care items
    if (_requiresSpecialCare(garment)) {
      final daysSinceLastMaintenance = DateTime.now()
          .difference(record.lastMaintenanceDate ?? record.lastCleanedDate)
          .inDays;
      
      if (daysSinceLastMaintenance >= 90) {
        // 3 months
        needsMaintenance = true;
      }
    }
    
    if (needsMaintenance != record.needsMaintenance) {
      final updatedRecord = record.copyWith(needsMaintenance: needsMaintenance);
      _maintenanceRecords[garmentId] = updatedRecord;
      await _saveMaintenanceRecords();
      
      if (needsMaintenance && _settings.maintenanceReminders) {
        await _sendMaintenanceReminder(garment, MaintenanceType.specialCare);
      }
    }
  }
  
  CleaningFrequency _getCleaningFrequency(Garment garment) {
    // Determine based on category and material
    final category = garment.category?.toLowerCase() ?? '';
    final material = garment.material?.toLowerCase() ?? '';
    
    // Underwear and socks - after each wear
    if (category.contains('underwear') || category.contains('socks')) {
      return const CleaningFrequency(wearCount: 1, maxDays: 1);
    }
    
    // T-shirts and tops - after 1-2 wears
    if (category.contains('shirt') || category.contains('top')) {
      return const CleaningFrequency(wearCount: 2, maxDays: 7);
    }
    
    // Jeans and pants - after 5-7 wears
    if (category.contains('jeans') || category.contains('pants')) {
      return const CleaningFrequency(wearCount: 7, maxDays: 30);
    }
    
    // Sweaters - after 5-7 wears
    if (category.contains('sweater') || category.contains('cardigan')) {
      return const CleaningFrequency(wearCount: 7, maxDays: 30);
    }
    
    // Suits and formal wear - after 3-5 wears
    if (category.contains('suit') || category.contains('formal')) {
      return const CleaningFrequency(wearCount: 5, maxDays: 60);
    }
    
    // Outerwear - seasonal
    if (category.contains('coat') || category.contains('jacket')) {
      return const CleaningFrequency(wearCount: 20, maxDays: 180);
    }
    
    // Default
    return const CleaningFrequency(wearCount: 3, maxDays: 14);
  }
  
  bool _requiresSpecialCare(Garment garment) {
    final material = garment.material?.toLowerCase() ?? '';
    final specialCareMaterials = [
      'leather',
      'suede',
      'silk',
      'cashmere',
      'wool',
      'velvet',
      'fur',
    ];
    
    return specialCareMaterials.any((m) => material.contains(m));
  }
  
  List<String> _generateMaintenanceRecommendations(
    Garment garment,
    MaintenanceRecord record,
  ) {
    final recommendations = <String>[];
    
    if (record.needsCleaning) {
      if (_requiresSpecialCare(garment)) {
        recommendations.add('Professional cleaning recommended');
      } else {
        recommendations.add('Regular washing needed');
      }
    }
    
    if (record.needsMaintenance) {
      final material = garment.material?.toLowerCase() ?? '';
      
      if (material.contains('leather')) {
        recommendations.add('Apply leather conditioner');
      } else if (material.contains('suede')) {
        recommendations.add('Brush and protect suede');
      } else if (material.contains('wool') || material.contains('cashmere')) {
        recommendations.add('Check for pilling and moths');
      }
    }
    
    // Seasonal recommendations
    if (_settings.seasonalCareReminders) {
      final season = _getCurrentSeason();
      if (season == 'Summer' && garment.material?.toLowerCase().contains('wool') == true) {
        recommendations.add('Store with moth protection');
      } else if (season == 'Winter' && garment.material?.toLowerCase().contains('leather') == true) {
        recommendations.add('Protect from salt and moisture');
      }
    }
    
    return recommendations;
  }
  
  MaintenancePriority _calculateMaintenancePriority(
    Garment garment,
    MaintenanceRecord record,
  ) {
    // High priority for frequently worn items needing cleaning
    if (record.needsCleaning && record.wearsSinceLastClean > 10) {
      return MaintenancePriority.high;
    }
    
    // High priority for special care items
    if (record.needsMaintenance && _requiresSpecialCare(garment)) {
      return MaintenancePriority.high;
    }
    
    // Medium priority for regular cleaning
    if (record.needsCleaning) {
      return MaintenancePriority.medium;
    }
    
    // Low priority for preventive maintenance
    return MaintenancePriority.low;
  }
  
  Future<void> _sendCleaningReminder(Garment garment) async {
    final title = 'Time to clean: ${garment.name}';
    final body = 'Worn ${_maintenanceRecords[garment.id]?.wearsSinceLastClean ?? 0} times since last cleaning';
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'cleaning_reminder',
        'garmentId': garment.id,
        'garmentName': garment.name,
      },
    );
  }
  
  Future<void> _sendMaintenanceReminder(
    Garment garment,
    MaintenanceType type,
  ) async {
    String title;
    String body;
    
    switch (type) {
      case MaintenanceType.cleaning:
        title = 'Cleaning reminder: ${garment.name}';
        body = 'Regular cleaning helps maintain garment quality';
        break;
      case MaintenanceType.specialCare:
        title = 'Special care needed: ${garment.name}';
        body = _generateSpecialCareMessage(garment);
        break;
      case MaintenanceType.seasonal:
        title = 'Seasonal care: ${garment.name}';
        body = 'Prepare your garment for the season';
        break;
    }
    
    await _notificationService.sendOutfitSuggestion(
      title: title,
      body: body,
      data: {
        'type': 'maintenance_reminder',
        'maintenanceType': type.name,
        'garmentId': garment.id,
        'garmentName': garment.name,
      },
    );
  }
  
  String _generateSpecialCareMessage(Garment garment) {
    final material = garment.material?.toLowerCase() ?? '';
    
    if (material.contains('leather')) {
      return 'Clean and condition your leather item';
    } else if (material.contains('suede')) {
      return 'Brush and protect your suede item';
    } else if (material.contains('silk')) {
      return 'Professional cleaning recommended for silk';
    } else if (material.contains('wool') || material.contains('cashmere')) {
      return 'Check for pilling and store properly';
    }
    
    return 'Special care recommended for this material';
  }
  
  Future<void> _sendMaintenanceSummary() async {
    final queueResult = await getMaintenanceQueue();
    
    queueResult.fold(
      (failure) => null,
      (items) async {
        if (items.isEmpty) return;
        
        final highPriorityCount = items.where((i) => i.priority == MaintenancePriority.high).length;
        final totalCount = items.length;
        
        if (highPriorityCount > 0 || totalCount > 5) {
          await _notificationService.sendOutfitSuggestion(
            title: 'Wardrobe Maintenance Needed',
            body: '$totalCount items need attention ($highPriorityCount high priority)',
            data: {
              'type': 'maintenance_summary',
              'totalCount': totalCount,
              'highPriorityCount': highPriorityCount,
            },
          );
        }
      },
    );
  }
  
  Future<void> _scheduleMaintenanceCheck(String garmentId, DateTime lastCleaned) async {
    // Schedule check in 3 months for special care items
    final checkDate = lastCleaned.add(const Duration(days: 90));
    
    await scheduleMaintenanceReminder(
      garmentId: garmentId,
      type: MaintenanceType.specialCare,
      reminderDate: checkDate,
    );
  }
  
  void _scheduleAllReminders() {
    // Reschedule all active reminders
    _maintenanceRecords.forEach((garmentId, record) async {
      if (record.needsCleaning && _settings.cleaningReminders) {
        final garment = await (_database.select(_database.garments)
          ..where((tbl) => tbl.id.equals(garmentId)))
          .getSingleOrNull();
        
        if (garment != null) {
          await _sendCleaningReminder(garment);
        }
      }
    });
  }
  
  void _cancelReminder(String reminderId) {
    _reminderTimers[reminderId]?.cancel();
    _reminderTimers.remove(reminderId);
  }
  
  void _cancelAllReminders() {
    for (final timer in _reminderTimers.values) {
      timer.cancel();
    }
    _reminderTimers.clear();
  }
  
  String _getCurrentSeason() {
    final month = DateTime.now().month;
    
    if (month >= 3 && month <= 5) {
      return 'Spring';
    } else if (month >= 6 && month <= 8) {
      return 'Summer';
    } else if (month >= 9 && month <= 11) {
      return 'Fall';
    } else {
      return 'Winter';
    }
  }
  
  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final settingsJson = prefs.getString('maintenance_settings');
    
    if (settingsJson != null) {
      _settings = MaintenanceSettings.fromJson(json.decode(settingsJson));
    }
  }
  
  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      'maintenance_settings',
      json.encode(_settings.toJson()),
    );
  }
  
  Future<void> _loadMaintenanceRecords() async {
    final prefs = await SharedPreferences.getInstance();
    final recordsJson = prefs.getString('maintenance_records');
    
    if (recordsJson != null) {
      final Map<String, dynamic> recordsMap = json.decode(recordsJson);
      recordsMap.forEach((key, value) {
        _maintenanceRecords[key] = MaintenanceRecord.fromJson(value);
      });
    }
  }
  
  Future<void> _saveMaintenanceRecords() async {
    final prefs = await SharedPreferences.getInstance();
    final recordsMap = <String, dynamic>{};
    
    _maintenanceRecords.forEach((key, value) {
      recordsMap[key] = value.toJson();
    });
    
    await prefs.setString('maintenance_records', json.encode(recordsMap));
  }
  
  void dispose() {
    _dailyCheckTimer?.cancel();
    _cancelAllReminders();
  }
}

/// Maintenance settings
class MaintenanceSettings {
  final bool enabled;
  final bool cleaningReminders;
  final bool maintenanceReminders;
  final bool seasonalCareReminders;
  final bool stainAlerts;
  
  const MaintenanceSettings({
    this.enabled = true,
    this.cleaningReminders = true,
    this.maintenanceReminders = true,
    this.seasonalCareReminders = true,
    this.stainAlerts = true,
  });
  
  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'cleaningReminders': cleaningReminders,
    'maintenanceReminders': maintenanceReminders,
    'seasonalCareReminders': seasonalCareReminders,
    'stainAlerts': stainAlerts,
  };
  
  factory MaintenanceSettings.fromJson(Map<String, dynamic> json) {
    return MaintenanceSettings(
      enabled: json['enabled'] ?? true,
      cleaningReminders: json['cleaningReminders'] ?? true,
      maintenanceReminders: json['maintenanceReminders'] ?? true,
      seasonalCareReminders: json['seasonalCareReminders'] ?? true,
      stainAlerts: json['stainAlerts'] ?? true,
    );
  }
  
  MaintenanceSettings copyWith({
    bool? enabled,
    bool? cleaningReminders,
    bool? maintenanceReminders,
    bool? seasonalCareReminders,
    bool? stainAlerts,
  }) {
    return MaintenanceSettings(
      enabled: enabled ?? this.enabled,
      cleaningReminders: cleaningReminders ?? this.cleaningReminders,
      maintenanceReminders: maintenanceReminders ?? this.maintenanceReminders,
      seasonalCareReminders: seasonalCareReminders ?? this.seasonalCareReminders,
      stainAlerts: stainAlerts ?? this.stainAlerts,
    );
  }
}

/// Maintenance record
class MaintenanceRecord {
  final String garmentId;
  final DateTime lastCleanedDate;
  final int wearsSinceLastClean;
  final DateTime? lastWornDate;
  final bool needsCleaning;
  final bool needsMaintenance;
  final DateTime? lastMaintenanceDate;
  final CleaningType? lastCleaningType;
  
  const MaintenanceRecord({
    required this.garmentId,
    required this.lastCleanedDate,
    required this.wearsSinceLastClean,
    this.lastWornDate,
    required this.needsCleaning,
    required this.needsMaintenance,
    this.lastMaintenanceDate,
    this.lastCleaningType,
  });
  
  Map<String, dynamic> toJson() => {
    'garmentId': garmentId,
    'lastCleanedDate': lastCleanedDate.toIso8601String(),
    'wearsSinceLastClean': wearsSinceLastClean,
    'lastWornDate': lastWornDate?.toIso8601String(),
    'needsCleaning': needsCleaning,
    'needsMaintenance': needsMaintenance,
    'lastMaintenanceDate': lastMaintenanceDate?.toIso8601String(),
    'lastCleaningType': lastCleaningType?.name,
  };
  
  factory MaintenanceRecord.fromJson(Map<String, dynamic> json) {
    return MaintenanceRecord(
      garmentId: json['garmentId'],
      lastCleanedDate: DateTime.parse(json['lastCleanedDate']),
      wearsSinceLastClean: json['wearsSinceLastClean'],
      lastWornDate: json['lastWornDate'] != null 
          ? DateTime.parse(json['lastWornDate']) 
          : null,
      needsCleaning: json['needsCleaning'],
      needsMaintenance: json['needsMaintenance'],
      lastMaintenanceDate: json['lastMaintenanceDate'] != null
          ? DateTime.parse(json['lastMaintenanceDate'])
          : null,
      lastCleaningType: json['lastCleaningType'] != null
          ? CleaningType.values.firstWhere((t) => t.name == json['lastCleaningType'])
          : null,
    );
  }
  
  MaintenanceRecord copyWith({
    DateTime? lastCleanedDate,
    int? wearsSinceLastClean,
    DateTime? lastWornDate,
    bool? needsCleaning,
    bool? needsMaintenance,
    DateTime? lastMaintenanceDate,
    CleaningType? lastCleaningType,
  }) {
    return MaintenanceRecord(
      garmentId: garmentId,
      lastCleanedDate: lastCleanedDate ?? this.lastCleanedDate,
      wearsSinceLastClean: wearsSinceLastClean ?? this.wearsSinceLastClean,
      lastWornDate: lastWornDate ?? this.lastWornDate,
      needsCleaning: needsCleaning ?? this.needsCleaning,
      needsMaintenance: needsMaintenance ?? this.needsMaintenance,
      lastMaintenanceDate: lastMaintenanceDate ?? this.lastMaintenanceDate,
      lastCleaningType: lastCleaningType ?? this.lastCleaningType,
    );
  }
}

/// Maintenance status
class MaintenanceStatus {
  final Garment garment;
  final MaintenanceRecord record;
  final List<String> recommendations;
  
  const MaintenanceStatus({
    required this.garment,
    required this.record,
    required this.recommendations,
  });
}

/// Maintenance item
class MaintenanceItem {
  final Garment garment;
  final MaintenanceRecord record;
  final MaintenancePriority priority;
  final List<String> recommendations;
  
  const MaintenanceItem({
    required this.garment,
    required this.record,
    required this.priority,
    required this.recommendations,
  });
}

/// Cleaning frequency
class CleaningFrequency {
  final int wearCount;
  final int maxDays;
  
  const CleaningFrequency({
    required this.wearCount,
    required this.maxDays,
  });
}

/// Cleaning types
enum CleaningType {
  regular,
  delicate,
  handWash,
  dryClean,
  deepClean,
  professionalCare,
}

/// Maintenance types
enum MaintenanceType {
  cleaning,
  specialCare,
  seasonal,
}

/// Maintenance priority
enum MaintenancePriority {
  high,
  medium,
  low,
}