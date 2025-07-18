import 'package:freezed_annotation/freezed_annotation.dart';

part 'failures.freezed.dart';

@freezed
class Failure with _$Failure {
  const factory Failure.serverError({
    required String message,
    int? statusCode,
  }) = ServerError;

  const factory Failure.networkError({
    required String message,
  }) = NetworkError;

  const factory Failure.cacheError({
    required String message,
  }) = CacheError;

  const factory Failure.validationError({
    required String message,
    Map<String, String>? fieldErrors,
  }) = ValidationError;

  const factory Failure.authenticationError({
    required String message,
  }) = AuthenticationError;

  const factory Failure.permissionDenied({
    required String message,
  }) = PermissionDenied;

  const factory Failure.notFound({
    required String message,
    String? resourceType,
    String? resourceId,
  }) = NotFound;

  const factory Failure.unexpected({
    required String message,
    Object? error,
    StackTrace? stackTrace,
  }) = UnexpectedError;
}