import 'package:flutter/material.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:intl/date_symbol_data_local.dart';

/// Service for multi-language support and RTL languages
class MultiLanguageService {
  final SharedPreferences _preferences;
  
  // Language settings keys
  static const String _currentLanguageKey = 'current_language';
  static const String _supportedLanguagesKey = 'supported_languages';
  static const String _rtlLanguagesKey = 'rtl_languages';
  static const String _dateFormatKey = 'date_format';
  static const String _numberFormatKey = 'number_format';
  static const String _currencyCodeKey = 'currency_code';
  static const String _translationCacheKey = 'translation_cache';
  
  // Built-in language support
  static const Map<String, LanguageInfo> _supportedLanguages = {
    'en': LanguageInfo(
      code: 'en',
      name: 'English',
      nativeName: 'English',
      isRtl: false,
      countryCode: 'US',
    ),
    'es': LanguageInfo(
      code: 'es',
      name: 'Spanish',
      nativeName: 'Español',
      isRtl: false,
      countryCode: 'ES',
    ),
    'fr': LanguageInfo(
      code: 'fr',
      name: 'French',
      nativeName: 'Français',
      isRtl: false,
      countryCode: 'FR',
    ),
    'de': LanguageInfo(
      code: 'de',
      name: 'German',
      nativeName: 'Deutsch',
      isRtl: false,
      countryCode: 'DE',
    ),
    'it': LanguageInfo(
      code: 'it',
      name: 'Italian',
      nativeName: 'Italiano',
      isRtl: false,
      countryCode: 'IT',
    ),
    'pt': LanguageInfo(
      code: 'pt',
      name: 'Portuguese',
      nativeName: 'Português',
      isRtl: false,
      countryCode: 'PT',
    ),
    'ru': LanguageInfo(
      code: 'ru',
      name: 'Russian',
      nativeName: 'Русский',
      isRtl: false,
      countryCode: 'RU',
    ),
    'ja': LanguageInfo(
      code: 'ja',
      name: 'Japanese',
      nativeName: '日本語',
      isRtl: false,
      countryCode: 'JP',
    ),
    'ko': LanguageInfo(
      code: 'ko',
      name: 'Korean',
      nativeName: '한국어',
      isRtl: false,
      countryCode: 'KR',
    ),
    'zh': LanguageInfo(
      code: 'zh',
      name: 'Chinese',
      nativeName: '中文',
      isRtl: false,
      countryCode: 'CN',
    ),
    'ar': LanguageInfo(
      code: 'ar',
      name: 'Arabic',
      nativeName: 'العربية',
      isRtl: true,
      countryCode: 'SA',
    ),
    'he': LanguageInfo(
      code: 'he',
      name: 'Hebrew',
      nativeName: 'עברית',
      isRtl: true,
      countryCode: 'IL',
    ),
    'fa': LanguageInfo(
      code: 'fa',
      name: 'Persian',
      nativeName: 'فارسی',
      isRtl: true,
      countryCode: 'IR',
    ),
    'ur': LanguageInfo(
      code: 'ur',
      name: 'Urdu',
      nativeName: 'اردو',
      isRtl: true,
      countryCode: 'PK',
    ),
    'hi': LanguageInfo(
      code: 'hi',
      name: 'Hindi',
      nativeName: 'हिन्दी',
      isRtl: false,
      countryCode: 'IN',
    ),
  };
  
  MultiLanguageService({
    required SharedPreferences preferences,
  }) : _preferences = preferences;
  
  /// Initialize multi-language service
  Future<Either<Failure, void>> initialize() async {
    try {
      // Initialize date formatting for all supported locales
      for (final language in _supportedLanguages.values) {
        await initializeDateFormatting(language.code, null);
      }
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to initialize multi-language service: $e'));
    }
  }
  
  /// Get current language settings
  LanguageSettings getLanguageSettings() {
    final currentLanguage = _preferences.getString(_currentLanguageKey) ?? 'en';
    final languageInfo = _supportedLanguages[currentLanguage]!;
    
    return LanguageSettings(
      currentLanguage: languageInfo,
      dateFormat: _preferences.getString(_dateFormatKey) ?? 'yyyy-MM-dd',
      numberFormat: _preferences.getString(_numberFormatKey) ?? 'en_US',
      currencyCode: _preferences.getString(_currencyCodeKey) ?? 'USD',
    );
  }
  
  /// Set current language
  Future<Either<Failure, void>> setCurrentLanguage(String languageCode) async {
    try {
      if (!_supportedLanguages.containsKey(languageCode)) {
        return Left(ServiceFailure('Language not supported: $languageCode'));
      }
      
      await _preferences.setString(_currentLanguageKey, languageCode);
      
      // Update locale-specific settings
      final languageInfo = _supportedLanguages[languageCode]!;
      await _updateLocaleSettings(languageInfo);
      
      return const Right(null);
    } catch (e) {
      return Left(ServiceFailure('Failed to set current language: $e'));
    }
  }
  
  /// Get supported languages
  List<LanguageInfo> getSupportedLanguages() {
    return _supportedLanguages.values.toList();
  }
  
  /// Get RTL languages
  List<LanguageInfo> getRtlLanguages() {
    return _supportedLanguages.values
        .where((lang) => lang.isRtl)
        .toList();
  }
  
  /// Check if current language is RTL
  bool isCurrentLanguageRtl() {
    final settings = getLanguageSettings();
    return settings.currentLanguage.isRtl;
  }
  
  /// Get text direction for current language
  TextDirection getTextDirection() {
    return isCurrentLanguageRtl() ? TextDirection.rtl : TextDirection.ltr;
  }
  
  /// Format date according to current locale
  String formatDate(DateTime date, {String? pattern}) {
    final settings = getLanguageSettings();
    final locale = settings.currentLanguage.code;
    
    final formatter = DateFormat(
      pattern ?? settings.dateFormat,
      locale,
    );
    
    return formatter.format(date);
  }
  
  /// Format number according to current locale
  String formatNumber(num number, {int? decimalDigits}) {
    final settings = getLanguageSettings();
    final formatter = NumberFormat.decimalPattern(settings.numberFormat);
    
    if (decimalDigits != null) {
      formatter.minimumFractionDigits = decimalDigits;
      formatter.maximumFractionDigits = decimalDigits;
    }
    
    return formatter.format(number);
  }
  
  /// Format currency according to current locale
  String formatCurrency(num amount, {String? currencyCode}) {
    final settings = getLanguageSettings();
    final currency = currencyCode ?? settings.currencyCode;
    
    final formatter = NumberFormat.currency(
      locale: settings.numberFormat,
      symbol: _getCurrencySymbol(currency),
    );
    
    return formatter.format(amount);
  }
  
  /// Get localized string
  String getString(String key, {Map<String, String>? params}) {
    final settings = getLanguageSettings();
    final translations = _getTranslations(settings.currentLanguage.code);
    
    String text = translations[key] ?? key;
    
    // Replace parameters
    if (params != null) {
      params.forEach((paramKey, paramValue) {
        text = text.replaceAll('{$paramKey}', paramValue);
      });
    }
    
    return text;
  }
  
  /// Get localized plural string
  String getPlural(String key, int count, {Map<String, String>? params}) {
    final settings = getLanguageSettings();
    final translations = _getTranslations(settings.currentLanguage.code);
    
    String pluralKey;
    if (count == 0) {
      pluralKey = '${key}_zero';
    } else if (count == 1) {
      pluralKey = '${key}_one';
    } else {
      pluralKey = '${key}_other';
    }
    
    String text = translations[pluralKey] ?? translations[key] ?? key;
    
    // Replace count parameter
    text = text.replaceAll('{count}', count.toString());
    
    // Replace other parameters
    if (params != null) {
      params.forEach((paramKey, paramValue) {
        text = text.replaceAll('{$paramKey}', paramValue);
      });
    }
    
    return text;
  }
  
  /// Get app bar title based on text direction
  Widget getAppBarTitle(String title) {
    return Text(
      title,
      textDirection: getTextDirection(),
    );
  }
  
  /// Get padding for RTL support
  EdgeInsets getPadding({
    double? start,
    double? end,
    double? top,
    double? bottom,
  }) {
    if (isCurrentLanguageRtl()) {
      return EdgeInsets.only(
        left: end ?? 0,
        right: start ?? 0,
        top: top ?? 0,
        bottom: bottom ?? 0,
      );
    } else {
      return EdgeInsets.only(
        left: start ?? 0,
        right: end ?? 0,
        top: top ?? 0,
        bottom: bottom ?? 0,
      );
    }
  }
  
  /// Get margin for RTL support
  EdgeInsets getMargin({
    double? start,
    double? end,
    double? top,
    double? bottom,
  }) {
    return getPadding(
      start: start,
      end: end,
      top: top,
      bottom: bottom,
    );
  }
  
  /// Get alignment for RTL support
  Alignment getAlignment(Alignment ltrAlignment) {
    if (!isCurrentLanguageRtl()) {
      return ltrAlignment;
    }
    
    // Flip horizontal alignment for RTL
    if (ltrAlignment == Alignment.centerLeft) {
      return Alignment.centerRight;
    } else if (ltrAlignment == Alignment.centerRight) {
      return Alignment.centerLeft;
    } else if (ltrAlignment == Alignment.topLeft) {
      return Alignment.topRight;
    } else if (ltrAlignment == Alignment.topRight) {
      return Alignment.topLeft;
    } else if (ltrAlignment == Alignment.bottomLeft) {
      return Alignment.bottomRight;
    } else if (ltrAlignment == Alignment.bottomRight) {
      return Alignment.bottomLeft;
    }
    
    return ltrAlignment;
  }
  
  /// Get cross axis alignment for RTL support
  CrossAxisAlignment getCrossAxisAlignment(CrossAxisAlignment ltrAlignment) {
    if (!isCurrentLanguageRtl()) {
      return ltrAlignment;
    }
    
    // Flip horizontal alignment for RTL
    if (ltrAlignment == CrossAxisAlignment.start) {
      return CrossAxisAlignment.end;
    } else if (ltrAlignment == CrossAxisAlignment.end) {
      return CrossAxisAlignment.start;
    }
    
    return ltrAlignment;
  }
  
  /// Get main axis alignment for RTL support
  MainAxisAlignment getMainAxisAlignment(MainAxisAlignment ltrAlignment) {
    if (!isCurrentLanguageRtl()) {
      return ltrAlignment;
    }
    
    // Flip horizontal alignment for RTL
    if (ltrAlignment == MainAxisAlignment.start) {
      return MainAxisAlignment.end;
    } else if (ltrAlignment == MainAxisAlignment.end) {
      return MainAxisAlignment.start;
    }
    
    return ltrAlignment;
  }
  
  /// Generate language report
  Future<Either<Failure, LanguageReport>> generateLanguageReport() async {
    try {
      final settings = getLanguageSettings();
      final translations = _getTranslations(settings.currentLanguage.code);
      
      return Right(LanguageReport(
        currentLanguage: settings.currentLanguage,
        supportedLanguages: getSupportedLanguages(),
        rtlLanguages: getRtlLanguages(),
        translationCoverage: _calculateTranslationCoverage(translations),
        isRtlEnabled: isCurrentLanguageRtl(),
        dateFormat: settings.dateFormat,
        numberFormat: settings.numberFormat,
        currencyCode: settings.currencyCode,
        generatedAt: DateTime.now(),
      ));
    } catch (e) {
      return Left(ServiceFailure('Failed to generate language report: $e'));
    }
  }
  
  // Private methods
  
  Future<void> _updateLocaleSettings(LanguageInfo languageInfo) async {
    // Update date format
    await _preferences.setString(_dateFormatKey, _getDateFormat(languageInfo.code));
    
    // Update number format
    await _preferences.setString(_numberFormatKey, _getNumberFormat(languageInfo.code));
    
    // Update currency code
    await _preferences.setString(_currencyCodeKey, _getCurrencyCode(languageInfo.countryCode));
  }
  
  String _getDateFormat(String languageCode) {
    switch (languageCode) {
      case 'en':
        return 'MM/dd/yyyy';
      case 'de':
      case 'fr':
      case 'es':
      case 'it':
        return 'dd/MM/yyyy';
      case 'ja':
        return 'yyyy/MM/dd';
      case 'ko':
        return 'yyyy. MM. dd';
      case 'zh':
        return 'yyyy年MM月dd日';
      case 'ar':
      case 'he':
      case 'fa':
      case 'ur':
        return 'dd/MM/yyyy';
      default:
        return 'yyyy-MM-dd';
    }
  }
  
  String _getNumberFormat(String languageCode) {
    switch (languageCode) {
      case 'en':
        return 'en_US';
      case 'es':
        return 'es_ES';
      case 'fr':
        return 'fr_FR';
      case 'de':
        return 'de_DE';
      case 'it':
        return 'it_IT';
      case 'pt':
        return 'pt_PT';
      case 'ru':
        return 'ru_RU';
      case 'ja':
        return 'ja_JP';
      case 'ko':
        return 'ko_KR';
      case 'zh':
        return 'zh_CN';
      case 'ar':
        return 'ar_SA';
      case 'he':
        return 'he_IL';
      case 'fa':
        return 'fa_IR';
      case 'ur':
        return 'ur_PK';
      case 'hi':
        return 'hi_IN';
      default:
        return 'en_US';
    }
  }
  
  String _getCurrencyCode(String countryCode) {
    switch (countryCode) {
      case 'US':
        return 'USD';
      case 'ES':
      case 'FR':
      case 'DE':
      case 'IT':
        return 'EUR';
      case 'PT':
        return 'EUR';
      case 'RU':
        return 'RUB';
      case 'JP':
        return 'JPY';
      case 'KR':
        return 'KRW';
      case 'CN':
        return 'CNY';
      case 'SA':
        return 'SAR';
      case 'IL':
        return 'ILS';
      case 'IR':
        return 'IRR';
      case 'PK':
        return 'PKR';
      case 'IN':
        return 'INR';
      default:
        return 'USD';
    }
  }
  
  String _getCurrencySymbol(String currencyCode) {
    switch (currencyCode) {
      case 'USD':
        return '\$';
      case 'EUR':
        return '€';
      case 'RUB':
        return '₽';
      case 'JPY':
        return '¥';
      case 'KRW':
        return '₩';
      case 'CNY':
        return '¥';
      case 'SAR':
        return 'ر.س';
      case 'ILS':
        return '₪';
      case 'IRR':
        return '﷼';
      case 'PKR':
        return 'Rs';
      case 'INR':
        return '₹';
      default:
        return currencyCode;
    }
  }
  
  Map<String, String> _getTranslations(String languageCode) {
    // This would load translations from assets or API
    // For now, return basic English translations
    return {
      'app_name': 'Koutu',
      'wardrobe': 'Wardrobe',
      'garments': 'Garments',
      'outfits': 'Outfits',
      'settings': 'Settings',
      'search': 'Search',
      'filter': 'Filter',
      'add': 'Add',
      'edit': 'Edit',
      'delete': 'Delete',
      'save': 'Save',
      'cancel': 'Cancel',
      'ok': 'OK',
      'back': 'Back',
      'next': 'Next',
      'previous': 'Previous',
      'loading': 'Loading...',
      'error': 'Error',
      'success': 'Success',
      'warning': 'Warning',
      'info': 'Information',
      'confirm': 'Confirm',
      'yes': 'Yes',
      'no': 'No',
      'retry': 'Retry',
    };
  }
  
  double _calculateTranslationCoverage(Map<String, String> translations) {
    // Calculate percentage of translated strings
    // This is a simplified calculation
    final totalKeys = 100; // Would be actual count of all translatable strings
    final translatedKeys = translations.length;
    
    return (translatedKeys / totalKeys) * 100.0;
  }
}

// Data classes

class LanguageInfo {
  final String code;
  final String name;
  final String nativeName;
  final bool isRtl;
  final String countryCode;
  
  const LanguageInfo({
    required this.code,
    required this.name,
    required this.nativeName,
    required this.isRtl,
    required this.countryCode,
  });
}

class LanguageSettings {
  final LanguageInfo currentLanguage;
  final String dateFormat;
  final String numberFormat;
  final String currencyCode;
  
  const LanguageSettings({
    required this.currentLanguage,
    required this.dateFormat,
    required this.numberFormat,
    required this.currencyCode,
  });
}

class LanguageReport {
  final LanguageInfo currentLanguage;
  final List<LanguageInfo> supportedLanguages;
  final List<LanguageInfo> rtlLanguages;
  final double translationCoverage;
  final bool isRtlEnabled;
  final String dateFormat;
  final String numberFormat;
  final String currencyCode;
  final DateTime generatedAt;
  
  const LanguageReport({
    required this.currentLanguage,
    required this.supportedLanguages,
    required this.rtlLanguages,
    required this.translationCoverage,
    required this.isRtlEnabled,
    required this.dateFormat,
    required this.numberFormat,
    required this.currencyCode,
    required this.generatedAt,
  });
}