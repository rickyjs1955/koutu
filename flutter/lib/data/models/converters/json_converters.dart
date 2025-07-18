import 'package:freezed_annotation/freezed_annotation.dart';

/// DateTime converter for handling ISO 8601 date strings
class DateTimeConverter implements JsonConverter<DateTime, String> {
  const DateTimeConverter();

  @override
  DateTime fromJson(String json) => DateTime.parse(json);

  @override
  String toJson(DateTime object) => object.toIso8601String();
}

/// Nullable DateTime converter
class NullableDateTimeConverter implements JsonConverter<DateTime?, String?> {
  const NullableDateTimeConverter();

  @override
  DateTime? fromJson(String? json) => json != null ? DateTime.parse(json) : null;

  @override
  String? toJson(DateTime? object) => object?.toIso8601String();
}

/// Color converter for handling hex color strings
class ColorConverter implements JsonConverter<int, String> {
  const ColorConverter();

  @override
  int fromJson(String json) {
    final hex = json.replaceAll('#', '');
    return int.parse('FF$hex', radix: 16);
  }

  @override
  String toJson(int object) {
    return '#${object.toRadixString(16).substring(2).toUpperCase()}';
  }
}

/// Nullable color converter
class NullableColorConverter implements JsonConverter<int?, String?> {
  const NullableColorConverter();

  @override
  int? fromJson(String? json) {
    if (json == null) return null;
    final hex = json.replaceAll('#', '');
    return int.parse('FF$hex', radix: 16);
  }

  @override
  String? toJson(int? object) {
    if (object == null) return null;
    return '#${object.toRadixString(16).substring(2).toUpperCase()}';
  }
}

/// Duration converter for handling duration in seconds
class DurationSecondsConverter implements JsonConverter<Duration, int> {
  const DurationSecondsConverter();

  @override
  Duration fromJson(int json) => Duration(seconds: json);

  @override
  int toJson(Duration object) => object.inSeconds;
}

/// Nullable duration converter
class NullableDurationSecondsConverter implements JsonConverter<Duration?, int?> {
  const NullableDurationSecondsConverter();

  @override
  Duration? fromJson(int? json) => json != null ? Duration(seconds: json) : null;

  @override
  int? toJson(Duration? object) => object?.inSeconds;
}

/// Uri converter for handling URL strings
class UriConverter implements JsonConverter<Uri, String> {
  const UriConverter();

  @override
  Uri fromJson(String json) => Uri.parse(json);

  @override
  String toJson(Uri object) => object.toString();
}

/// Nullable Uri converter
class NullableUriConverter implements JsonConverter<Uri?, String?> {
  const NullableUriConverter();

  @override
  Uri? fromJson(String? json) => json != null ? Uri.parse(json) : null;

  @override
  String? toJson(Uri? object) => object?.toString();
}

/// Double converter for handling string numbers
class DoubleStringConverter implements JsonConverter<double, dynamic> {
  const DoubleStringConverter();

  @override
  double fromJson(dynamic json) {
    if (json is double) return json;
    if (json is int) return json.toDouble();
    if (json is String) return double.parse(json);
    throw ArgumentError('Cannot convert $json to double');
  }

  @override
  dynamic toJson(double object) => object;
}

/// Nullable double converter for handling string numbers
class NullableDoubleStringConverter implements JsonConverter<double?, dynamic> {
  const NullableDoubleStringConverter();

  @override
  double? fromJson(dynamic json) {
    if (json == null) return null;
    if (json is double) return json;
    if (json is int) return json.toDouble();
    if (json is String) return double.parse(json);
    throw ArgumentError('Cannot convert $json to double');
  }

  @override
  dynamic toJson(double? object) => object;
}

/// Boolean converter for handling various boolean representations
class BooleanConverter implements JsonConverter<bool, dynamic> {
  const BooleanConverter();

  @override
  bool fromJson(dynamic json) {
    if (json is bool) return json;
    if (json is int) return json != 0;
    if (json is String) {
      final lower = json.toLowerCase();
      return lower == 'true' || lower == '1' || lower == 'yes';
    }
    return false;
  }

  @override
  dynamic toJson(bool object) => object;
}

/// List converter for handling comma-separated strings
class StringListConverter implements JsonConverter<List<String>, dynamic> {
  const StringListConverter();

  @override
  List<String> fromJson(dynamic json) {
    if (json is List) return json.map((e) => e.toString()).toList();
    if (json is String) {
      if (json.isEmpty) return [];
      return json.split(',').map((e) => e.trim()).toList();
    }
    return [];
  }

  @override
  dynamic toJson(List<String> object) => object;
}