import 'package:flutter/services.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:typed_data';

/// Service for Android widgets and shortcuts
class AndroidWidgetService {
  final SharedPreferences _preferences;
  final MethodChannel _channel;
  
  // Widget settings keys
  static const String _widgetsEnabledKey = 'android_widgets_enabled';
  static const String _shortcutsEnabledKey = 'android_shortcuts_enabled';
  static const String _widgetConfigKey = 'android_widget_config';
  static const String _shortcutConfigKey = 'android_shortcut_config';
  static const String _widgetDataKey = 'android_widget_data';
  static const String _lastWidgetUpdateKey = 'android_last_widget_update';
  
  AndroidWidgetService({
    required SharedPreferences preferences,
    MethodChannel? channel,
  }) : _preferences = preferences,
       _channel = channel ?? const MethodChannel('koutu/android_widgets');
  
  /// Initialize Android widget service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Check if Android widgets are available
      final isAvailable = await _channel.invokeMethod<bool>('isWidgetAvailable') ?? false;
      
      if (!isAvailable) {
        return Left(ServiceFailure('Android widgets are not available'));
      }
      
      // Set up widget data handler
      _channel.setMethodCallHandler(_handleWidgetRequest);
      
      // Initialize shortcuts
      await _initializeShortcuts();
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize Android widgets: $e'));
    }
  }
  
  /// Get Android widget settings
  AndroidWidgetSettings getWidgetSettings() {
    final widgetConfig = _getWidgetConfig();
    final shortcutConfig = _getShortcutConfig();
    
    return AndroidWidgetSettings(
      widgetsEnabled: _preferences.getBool(_widgetsEnabledKey) ?? false,
      shortcutsEnabled: _preferences.getBool(_shortcutsEnabledKey) ?? false,
      outfitWidgetEnabled: widgetConfig['outfitWidget'] ?? true,
      weatherWidgetEnabled: widgetConfig['weatherWidget'] ?? true,
      quickActionsEnabled: widgetConfig['quickActions'] ?? true,
      updateInterval: Duration(minutes: widgetConfig['updateInterval'] ?? 30),
      showOutfitSuggestions: widgetConfig['showOutfitSuggestions'] ?? true,
      showWeatherInfo: widgetConfig['showWeatherInfo'] ?? true,
      maxOutfitsShown: widgetConfig['maxOutfitsShown'] ?? 4,
      dynamicShortcuts: shortcutConfig['dynamicShortcuts'] ?? true,
      staticShortcuts: shortcutConfig['staticShortcuts'] ?? true,
      maxShortcuts: shortcutConfig['maxShortcuts'] ?? 4,
    );
  }
  
  /// Update Android widget settings
  Future<Either<Failure, void>> updateWidgetSettings(
    AndroidWidgetSettings settings,
  ) async {
    try {
      await _preferences.setBool(_widgetsEnabledKey, settings.widgetsEnabled);
      await _preferences.setBool(_shortcutsEnabledKey, settings.shortcutsEnabled);
      
      final widgetConfig = {
        'outfitWidget': settings.outfitWidgetEnabled,
        'weatherWidget': settings.weatherWidgetEnabled,
        'quickActions': settings.quickActionsEnabled,
        'updateInterval': settings.updateInterval.inMinutes,
        'showOutfitSuggestions': settings.showOutfitSuggestions,
        'showWeatherInfo': settings.showWeatherInfo,
        'maxOutfitsShown': settings.maxOutfitsShown,
      };
      
      final shortcutConfig = {
        'dynamicShortcuts': settings.dynamicShortcuts,
        'staticShortcuts': settings.staticShortcuts,
        'maxShortcuts': settings.maxShortcuts,
      };
      
      await _preferences.setString(_widgetConfigKey, json.encode(widgetConfig));
      await _preferences.setString(_shortcutConfigKey, json.encode(shortcutConfig));
      
      // Update widgets and shortcuts
      if (settings.widgetsEnabled) {
        await _updateAllWidgets();
      }
      
      if (settings.shortcutsEnabled) {
        await _updateShortcuts();
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update widget settings: $e'));
    }
  }
  
  /// Create Android app widget
  Future<Either<Failure, void>> createAppWidget(
    AndroidWidgetData data,
  ) async {
    try {
      final settings = getWidgetSettings();
      
      if (!settings.widgetsEnabled) {
        return Left(ServiceFailure('Android widgets are disabled'));
      }
      
      final widgetData = {
        'type': data.type,
        'title': data.title,
        'content': data.content,
        'actions': data.actions.map((action) => action.toJson()).toList(),
        'layout': data.layout,
        'lastUpdated': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('createAppWidget', {
        'widgetId': data.widgetId,
        'className': data.className,
        'data': widgetData,
      });
      
      await _storeWidgetData(data.type, widgetData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create app widget: $e'));
    }
  }
  
  /// Update app widget
  Future<Either<Failure, void>> updateAppWidget(
    int widgetId,
    AndroidWidgetData data,
  ) async {
    try {
      final widgetData = {
        'type': data.type,
        'title': data.title,
        'content': data.content,
        'actions': data.actions.map((action) => action.toJson()).toList(),
        'layout': data.layout,
        'lastUpdated': DateTime.now().toIso8601String(),
      };
      
      await _channel.invokeMethod('updateAppWidget', {
        'widgetId': widgetId,
        'data': widgetData,
      });
      
      await _storeWidgetData(data.type, widgetData);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update app widget: $e'));
    }
  }
  
  /// Create dynamic shortcuts
  Future<Either<Failure, void>> createDynamicShortcuts(
    List<AndroidShortcut> shortcuts,
  ) async {
    try {
      final settings = getWidgetSettings();
      
      if (!settings.shortcutsEnabled || !settings.dynamicShortcuts) {
        return Left(ServiceFailure('Dynamic shortcuts are disabled'));
      }
      
      final shortcutData = shortcuts.map((shortcut) => shortcut.toJson()).toList();
      
      await _channel.invokeMethod('createDynamicShortcuts', {
        'shortcuts': shortcutData,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create dynamic shortcuts: $e'));
    }
  }
  
  /// Update dynamic shortcuts
  Future<Either<Failure, void>> updateDynamicShortcuts(
    List<AndroidShortcut> shortcuts,
  ) async {
    try {
      final settings = getWidgetSettings();
      
      if (!settings.shortcutsEnabled || !settings.dynamicShortcuts) {
        return Left(ServiceFailure('Dynamic shortcuts are disabled'));
      }
      
      final shortcutData = shortcuts.map((shortcut) => shortcut.toJson()).toList();
      
      await _channel.invokeMethod('updateDynamicShortcuts', {
        'shortcuts': shortcutData,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to update dynamic shortcuts: $e'));
    }
  }
  
  /// Remove app widget
  Future<Either<Failure, void>> removeAppWidget(int widgetId) async {
    try {
      await _channel.invokeMethod('removeAppWidget', {
        'widgetId': widgetId,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to remove app widget: $e'));
    }
  }
  
  /// Get widget provider info
  Future<Either<Failure, List<AndroidWidgetProvider>>> getWidgetProviders() async {
    try {
      final providers = await _channel.invokeMethod<List<dynamic>>('getWidgetProviders');
      
      if (providers == null) {
        return const Right([]);
      }
      
      final widgetProviders = providers.map((provider) => AndroidWidgetProvider.fromJson(provider)).toList();
      return Right(widgetProviders);
    } catch (e) {
      return Left(ServiceFailure('Failed to get widget providers: $e'));
    }
  }
  
  /// Configure widget provider
  Future<Either<Failure, void>> configureWidgetProvider(
    String className,
    AndroidWidgetProviderConfig config,
  ) async {
    try {
      await _channel.invokeMethod('configureWidgetProvider', {
        'className': className,
        'config': config.toJson(),
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to configure widget provider: $e'));
    }
  }
  
  /// Handle widget resize
  Future<Either<Failure, void>> handleWidgetResize(
    int widgetId,
    int width,
    int height,
  ) async {
    try {
      await _channel.invokeMethod('handleWidgetResize', {
        'widgetId': widgetId,
        'width': width,
        'height': height,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to handle widget resize: $e'));
    }
  }
  
  /// Get active widgets
  Future<Either<Failure, List<AndroidActiveWidget>>> getActiveWidgets() async {
    try {
      final widgets = await _channel.invokeMethod<List<dynamic>>('getActiveWidgets');
      
      if (widgets == null) {
        return const Right([]);
      }
      
      final activeWidgets = widgets.map((widget) => AndroidActiveWidget.fromJson(widget)).toList();
      return Right(activeWidgets);
    } catch (e) {
      return Left(ServiceFailure('Failed to get active widgets: $e'));
    }
  }
  
  /// Setup notification channels for widgets
  Future<Either<Failure, void>> setupNotificationChannels() async {
    try {
      await _channel.invokeMethod('setupNotificationChannels', {
        'channels': [
          {
            'id': 'widget_updates',
            'name': 'Widget Updates',
            'description': 'Notifications for widget updates',
            'importance': 'LOW',
          },
          {
            'id': 'outfit_suggestions',
            'name': 'Outfit Suggestions',
            'description': 'Daily outfit suggestions',
            'importance': 'DEFAULT',
          },
        ],
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to setup notification channels: $e'));
    }
  }
  
  /// Create adaptive icon
  Future<Either<Failure, void>> createAdaptiveIcon(
    String iconName,
    Uint8List foregroundImage,
    Uint8List backgroundImage,
  ) async {
    try {
      await _channel.invokeMethod('createAdaptiveIcon', {
        'iconName': iconName,
        'foregroundImage': foregroundImage,
        'backgroundImage': backgroundImage,
      });
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to create adaptive icon: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _handleWidgetRequest(MethodCall call) async {
    switch (call.method) {
      case 'requestWidgetData':
        final widgetId = call.arguments['widgetId'] as int;
        final widgetType = call.arguments['type'] as String;
        await _handleWidgetDataRequest(widgetId, widgetType);
        break;
        
      case 'widgetClicked':
        final widgetId = call.arguments['widgetId'] as int;
        final action = call.arguments['action'] as String;
        await _handleWidgetClick(widgetId, action);
        break;
        
      case 'widgetDeleted':
        final widgetId = call.arguments['widgetId'] as int;
        await _handleWidgetDeleted(widgetId);
        break;
        
      case 'widgetEnabled':
        final widgetId = call.arguments['widgetId'] as int;
        await _handleWidgetEnabled(widgetId);
        break;
        
      case 'widgetDisabled':
        final widgetId = call.arguments['widgetId'] as int;
        await _handleWidgetDisabled(widgetId);
        break;
        
      case 'shortcutClicked':
        final shortcutId = call.arguments['shortcutId'] as String;
        await _handleShortcutClick(shortcutId);
        break;
    }
  }
  
  Future<void> _handleWidgetDataRequest(int widgetId, String widgetType) async {
    // Get widget data based on type
    final widgetData = await _getWidgetDataForType(widgetType);
    
    await _channel.invokeMethod('widgetDataResponse', {
      'widgetId': widgetId,
      'data': widgetData,
    });
  }
  
  Future<void> _handleWidgetClick(int widgetId, String action) async {
    // Handle widget click actions
    switch (action) {
      case 'open_app':
        await _channel.invokeMethod('openMainApp');
        break;
      case 'open_wardrobe':
        await _channel.invokeMethod('openScreen', {'screen': 'wardrobe'});
        break;
      case 'open_camera':
        await _channel.invokeMethod('openScreen', {'screen': 'camera'});
        break;
      case 'open_outfits':
        await _channel.invokeMethod('openScreen', {'screen': 'outfits'});
        break;
    }
  }
  
  Future<void> _handleWidgetDeleted(int widgetId) async {
    // Clean up widget data
    await _removeWidgetData(widgetId.toString());
  }
  
  Future<void> _handleWidgetEnabled(int widgetId) async {
    // Update widget when enabled
    await _updateSpecificWidget(widgetId);
  }
  
  Future<void> _handleWidgetDisabled(int widgetId) async {
    // Handle widget disabled
  }
  
  Future<void> _handleShortcutClick(String shortcutId) async {
    // Handle shortcut clicks
    switch (shortcutId) {
      case 'quick_photo':
        await _channel.invokeMethod('openScreen', {'screen': 'camera'});
        break;
      case 'view_wardrobe':
        await _channel.invokeMethod('openScreen', {'screen': 'wardrobe'});
        break;
      case 'today_outfit':
        await _channel.invokeMethod('openScreen', {'screen': 'outfits'});
        break;
      case 'search_garments':
        await _channel.invokeMethod('openScreen', {'screen': 'search'});
        break;
    }
  }
  
  Future<void> _initializeShortcuts() async {
    final settings = getWidgetSettings();
    
    if (!settings.shortcutsEnabled) {
      return;
    }
    
    final staticShortcuts = [
      AndroidShortcut(
        id: 'quick_photo',
        shortLabel: 'Quick Photo',
        longLabel: 'Take a quick photo',
        icon: 'ic_camera',
        intent: 'QUICK_PHOTO',
      ),
      AndroidShortcut(
        id: 'view_wardrobe',
        shortLabel: 'Wardrobe',
        longLabel: 'View my wardrobe',
        icon: 'ic_wardrobe',
        intent: 'VIEW_WARDROBE',
      ),
      AndroidShortcut(
        id: 'today_outfit',
        shortLabel: 'Today\'s Outfit',
        longLabel: 'See today\'s outfit suggestions',
        icon: 'ic_outfit',
        intent: 'TODAY_OUTFIT',
      ),
      AndroidShortcut(
        id: 'search_garments',
        shortLabel: 'Search',
        longLabel: 'Search garments',
        icon: 'ic_search',
        intent: 'SEARCH_GARMENTS',
      ),
    ];
    
    await createDynamicShortcuts(staticShortcuts);
  }
  
  Future<void> _updateAllWidgets() async {
    final activeWidgets = await getActiveWidgets();
    
    activeWidgets.fold(
      (failure) => null,
      (widgets) async {
        for (final widget in widgets) {
          await _updateSpecificWidget(widget.widgetId);
        }
      },
    );
  }
  
  Future<void> _updateSpecificWidget(int widgetId) async {
    // This would fetch current data and update the specific widget
    // For now, we'll create a placeholder implementation
    final widgetData = AndroidWidgetData(
      widgetId: widgetId,
      type: 'outfit',
      title: 'Today\'s Outfits',
      content: {},
      actions: [
        AndroidWidgetAction(
          id: 'open_app',
          label: 'Open App',
          intent: 'OPEN_MAIN_APP',
        ),
      ],
      layout: 'outfit_widget_layout',
      className: 'OutfitWidgetProvider',
    );
    
    await updateAppWidget(widgetId, widgetData);
  }
  
  Future<void> _updateShortcuts() async {
    // Update dynamic shortcuts with current data
    await _initializeShortcuts();
  }
  
  Future<Map<String, dynamic>> _getWidgetDataForType(String widgetType) async {
    // This would fetch actual widget data based on type
    // For now, return placeholder data
    switch (widgetType) {
      case 'outfit':
        return {
          'title': 'Today\'s Outfits',
          'outfits': [],
          'weather': null,
        };
      case 'weather':
        return {
          'title': 'Weather & Outfits',
          'weather': {
            'temperature': 22,
            'condition': 'Sunny',
          },
          'suggestions': [],
        };
      default:
        return {};
    }
  }
  
  Map<String, dynamic> _getWidgetConfig() {
    final configJson = _preferences.getString(_widgetConfigKey);
    if (configJson == null) {
      return {};
    }
    
    try {
      return json.decode(configJson);
    } catch (e) {
      return {};
    }
  }
  
  Map<String, dynamic> _getShortcutConfig() {
    final configJson = _preferences.getString(_shortcutConfigKey);
    if (configJson == null) {
      return {};
    }
    
    try {
      return json.decode(configJson);
    } catch (e) {
      return {};
    }
  }
  
  Future<void> _storeWidgetData(String widgetType, Map<String, dynamic> data) async {
    final widgetData = _getStoredWidgetData();
    widgetData[widgetType] = data;
    
    await _preferences.setString(_widgetDataKey, json.encode(widgetData));
  }
  
  Future<void> _removeWidgetData(String widgetId) async {
    final widgetData = _getStoredWidgetData();
    widgetData.remove(widgetId);
    
    await _preferences.setString(_widgetDataKey, json.encode(widgetData));
  }
  
  Map<String, dynamic> _getStoredWidgetData() {
    final dataJson = _preferences.getString(_widgetDataKey);
    if (dataJson == null) {
      return {};
    }
    
    try {
      return json.decode(dataJson);
    } catch (e) {
      return {};
    }
  }
}

// Data classes

class AndroidWidgetSettings {
  final bool widgetsEnabled;
  final bool shortcutsEnabled;
  final bool outfitWidgetEnabled;
  final bool weatherWidgetEnabled;
  final bool quickActionsEnabled;
  final Duration updateInterval;
  final bool showOutfitSuggestions;
  final bool showWeatherInfo;
  final int maxOutfitsShown;
  final bool dynamicShortcuts;
  final bool staticShortcuts;
  final int maxShortcuts;
  
  const AndroidWidgetSettings({
    required this.widgetsEnabled,
    required this.shortcutsEnabled,
    required this.outfitWidgetEnabled,
    required this.weatherWidgetEnabled,
    required this.quickActionsEnabled,
    required this.updateInterval,
    required this.showOutfitSuggestions,
    required this.showWeatherInfo,
    required this.maxOutfitsShown,
    required this.dynamicShortcuts,
    required this.staticShortcuts,
    required this.maxShortcuts,
  });
}

class AndroidWidgetData {
  final int widgetId;
  final String type;
  final String title;
  final Map<String, dynamic> content;
  final List<AndroidWidgetAction> actions;
  final String layout;
  final String className;
  
  const AndroidWidgetData({
    required this.widgetId,
    required this.type,
    required this.title,
    required this.content,
    required this.actions,
    required this.layout,
    required this.className,
  });
}

class AndroidWidgetAction {
  final String id;
  final String label;
  final String intent;
  final Map<String, dynamic>? extras;
  
  const AndroidWidgetAction({
    required this.id,
    required this.label,
    required this.intent,
    this.extras,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'label': label,
    'intent': intent,
    'extras': extras,
  };
  
  factory AndroidWidgetAction.fromJson(Map<String, dynamic> json) {
    return AndroidWidgetAction(
      id: json['id'],
      label: json['label'],
      intent: json['intent'],
      extras: json['extras'],
    );
  }
}

class AndroidShortcut {
  final String id;
  final String shortLabel;
  final String longLabel;
  final String icon;
  final String intent;
  final Map<String, dynamic>? extras;
  final bool enabled;
  
  const AndroidShortcut({
    required this.id,
    required this.shortLabel,
    required this.longLabel,
    required this.icon,
    required this.intent,
    this.extras,
    this.enabled = true,
  });
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'shortLabel': shortLabel,
    'longLabel': longLabel,
    'icon': icon,
    'intent': intent,
    'extras': extras,
    'enabled': enabled,
  };
  
  factory AndroidShortcut.fromJson(Map<String, dynamic> json) {
    return AndroidShortcut(
      id: json['id'],
      shortLabel: json['shortLabel'],
      longLabel: json['longLabel'],
      icon: json['icon'],
      intent: json['intent'],
      extras: json['extras'],
      enabled: json['enabled'] ?? true,
    );
  }
}

class AndroidWidgetProvider {
  final String className;
  final String label;
  final int minWidth;
  final int minHeight;
  final int updatePeriodMillis;
  final String? previewImage;
  final String? description;
  final bool resizeMode;
  final List<String> supportedSizes;
  
  const AndroidWidgetProvider({
    required this.className,
    required this.label,
    required this.minWidth,
    required this.minHeight,
    required this.updatePeriodMillis,
    this.previewImage,
    this.description,
    this.resizeMode = false,
    this.supportedSizes = const [],
  });
  
  factory AndroidWidgetProvider.fromJson(Map<String, dynamic> json) {
    return AndroidWidgetProvider(
      className: json['className'],
      label: json['label'],
      minWidth: json['minWidth'],
      minHeight: json['minHeight'],
      updatePeriodMillis: json['updatePeriodMillis'],
      previewImage: json['previewImage'],
      description: json['description'],
      resizeMode: json['resizeMode'] ?? false,
      supportedSizes: List<String>.from(json['supportedSizes'] ?? []),
    );
  }
}

class AndroidWidgetProviderConfig {
  final int updatePeriodMillis;
  final bool enabled;
  final String? category;
  final List<String> supportedSizes;
  final bool autoAdvanceViewId;
  
  const AndroidWidgetProviderConfig({
    required this.updatePeriodMillis,
    required this.enabled,
    this.category,
    this.supportedSizes = const [],
    this.autoAdvanceViewId = false,
  });
  
  Map<String, dynamic> toJson() => {
    'updatePeriodMillis': updatePeriodMillis,
    'enabled': enabled,
    'category': category,
    'supportedSizes': supportedSizes,
    'autoAdvanceViewId': autoAdvanceViewId,
  };
}

class AndroidActiveWidget {
  final int widgetId;
  final String className;
  final String packageName;
  final int width;
  final int height;
  final DateTime lastUpdated;
  
  const AndroidActiveWidget({
    required this.widgetId,
    required this.className,
    required this.packageName,
    required this.width,
    required this.height,
    required this.lastUpdated,
  });
  
  factory AndroidActiveWidget.fromJson(Map<String, dynamic> json) {
    return AndroidActiveWidget(
      widgetId: json['widgetId'],
      className: json['className'],
      packageName: json['packageName'],
      width: json['width'],
      height: json['height'],
      lastUpdated: DateTime.parse(json['lastUpdated']),
    );
  }
}