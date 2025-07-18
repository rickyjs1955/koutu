import 'package:freezed_annotation/freezed_annotation.dart';

part 'api_response.freezed.dart';
part 'api_response.g.dart';

/// Generic API response wrapper
@freezed
class ApiResponse<T> with _$ApiResponse<T> {
  const factory ApiResponse({
    required bool success,
    T? data,
    String? message,
    ApiError? error,
    ApiMeta? meta,
  }) = _ApiResponse<T>;

  factory ApiResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object?) fromJsonT,
  ) =>
      _$ApiResponseFromJson<T>(json, fromJsonT);
}

/// API error details
@freezed
class ApiError with _$ApiError {
  const factory ApiError({
    required String code,
    required String message,
    String? field,
    Map<String, dynamic>? details,
  }) = _ApiError;

  factory ApiError.fromJson(Map<String, dynamic> json) =>
      _$ApiErrorFromJson(json);
}

/// API response metadata
@freezed
class ApiMeta with _$ApiMeta {
  const factory ApiMeta({
    int? page,
    int? perPage,
    int? total,
    int? totalPages,
    String? nextCursor,
    String? previousCursor,
    Map<String, dynamic>? extra,
  }) = _ApiMeta;

  factory ApiMeta.fromJson(Map<String, dynamic> json) =>
      _$ApiMetaFromJson(json);
}

/// Paginated API response
@freezed
class PaginatedResponse<T> with _$PaginatedResponse<T> {
  const factory PaginatedResponse({
    required List<T> items,
    required ApiMeta meta,
    String? message,
  }) = _PaginatedResponse<T>;

  factory PaginatedResponse.fromJson(
    Map<String, dynamic> json,
    T Function(Object?) fromJsonT,
  ) =>
      _$PaginatedResponseFromJson<T>(json, fromJsonT);
}

/// Extension methods for API responses
extension ApiResponseX<T> on ApiResponse<T> {
  /// Check if response is successful with data
  bool get hasData => success && data != null;

  /// Check if response has error
  bool get hasError => !success || error != null;

  /// Get data or throw exception
  T get dataOrThrow {
    if (hasData) {
      return data as T;
    }
    throw Exception(error?.message ?? message ?? 'No data available');
  }

  /// Map data to another type
  ApiResponse<R> mapData<R>(R Function(T) mapper) {
    return ApiResponse<R>(
      success: success,
      data: data != null ? mapper(data as T) : null,
      message: message,
      error: error,
      meta: meta,
    );
  }
}