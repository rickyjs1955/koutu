import 'package:freezed_annotation/freezed_annotation.dart';

part 'error_response_model.freezed.dart';
part 'error_response_model.g.dart';

@freezed
class ErrorResponseModel with _$ErrorResponseModel {
  const ErrorResponseModel._();

  const factory ErrorResponseModel({
    required String message,
    String? code,
    @JsonKey(name: 'status_code') int? statusCode,
    String? field,
    Map<String, dynamic>? details,
    @JsonKey(name: 'field_errors') Map<String, List<String>>? fieldErrors,
    @JsonKey(name: 'request_id') String? requestId,
    DateTime? timestamp,
  }) = _ErrorResponseModel;

  factory ErrorResponseModel.fromJson(Map<String, dynamic> json) =>
      _$ErrorResponseModelFromJson(json);

  /// Check if error is a validation error
  bool get isValidationError => fieldErrors != null && fieldErrors!.isNotEmpty;

  /// Check if error is a server error
  bool get isServerError => statusCode != null && statusCode! >= 500;

  /// Check if error is a client error
  bool get isClientError => statusCode != null && statusCode! >= 400 && statusCode! < 500;

  /// Check if error is an authentication error
  bool get isAuthError => statusCode == 401 || code == 'UNAUTHORIZED';

  /// Check if error is a permission error
  bool get isPermissionError => statusCode == 403 || code == 'FORBIDDEN';

  /// Check if error is a not found error
  bool get isNotFoundError => statusCode == 404 || code == 'NOT_FOUND';

  /// Get all validation errors as a single string
  String? get validationErrorsAsString {
    if (!isValidationError) return null;
    
    final errors = <String>[];
    fieldErrors!.forEach((field, messages) {
      errors.addAll(messages.map((msg) => '$field: $msg'));
    });
    
    return errors.join('\n');
  }

  /// Get error message for a specific field
  List<String>? getFieldErrors(String field) {
    return fieldErrors?[field];
  }

  /// Get first error message for a specific field
  String? getFirstFieldError(String field) {
    final errors = getFieldErrors(field);
    return errors?.isNotEmpty == true ? errors!.first : null;
  }

  /// Create a generic error response
  static ErrorResponseModel generic({
    String message = 'An unexpected error occurred',
    int? statusCode,
  }) {
    return ErrorResponseModel(
      message: message,
      code: 'GENERIC_ERROR',
      statusCode: statusCode,
      timestamp: DateTime.now(),
    );
  }

  /// Create a validation error response
  static ErrorResponseModel validation({
    required Map<String, List<String>> fieldErrors,
    String message = 'Validation failed',
  }) {
    return ErrorResponseModel(
      message: message,
      code: 'VALIDATION_ERROR',
      statusCode: 422,
      fieldErrors: fieldErrors,
      timestamp: DateTime.now(),
    );
  }

  /// Create a network error response
  static ErrorResponseModel network({
    String message = 'Network connection error',
  }) {
    return ErrorResponseModel(
      message: message,
      code: 'NETWORK_ERROR',
      timestamp: DateTime.now(),
    );
  }
}