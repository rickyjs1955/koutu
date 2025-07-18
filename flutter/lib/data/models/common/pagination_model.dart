import 'package:freezed_annotation/freezed_annotation.dart';

part 'pagination_model.freezed.dart';
part 'pagination_model.g.dart';

@Freezed(genericArgumentFactories: true)
class PaginationModel<T> with _$PaginationModel<T> {
  const PaginationModel._();

  const factory PaginationModel({
    required List<T> items,
    @JsonKey(name: 'current_page') required int currentPage,
    @JsonKey(name: 'per_page') required int perPage,
    @JsonKey(name: 'total_items') required int totalItems,
    @JsonKey(name: 'total_pages') required int totalPages,
    @JsonKey(name: 'has_next') required bool hasNext,
    @JsonKey(name: 'has_previous') required bool hasPrevious,
    @JsonKey(name: 'next_cursor') String? nextCursor,
    @JsonKey(name: 'previous_cursor') String? previousCursor,
  }) = _PaginationModel<T>;

  factory PaginationModel.fromJson(
    Map<String, dynamic> json,
    T Function(Object?) fromJsonT,
  ) =>
      _$PaginationModelFromJson<T>(json, fromJsonT);

  /// Check if this is the first page
  bool get isFirstPage => currentPage == 1 || !hasPrevious;

  /// Check if this is the last page
  bool get isLastPage => currentPage == totalPages || !hasNext;

  /// Check if pagination is empty
  bool get isEmpty => items.isEmpty;

  /// Get item count on current page
  int get itemCount => items.length;

  /// Calculate the starting index for items on this page
  int get startIndex => (currentPage - 1) * perPage + 1;

  /// Calculate the ending index for items on this page
  int get endIndex => startIndex + itemCount - 1;

  /// Create an empty pagination
  static PaginationModel<T> empty<T>() {
    return PaginationModel<T>(
      items: [],
      currentPage: 1,
      perPage: 20,
      totalItems: 0,
      totalPages: 0,
      hasNext: false,
      hasPrevious: false,
    );
  }

  /// Map items to a different type
  PaginationModel<R> map<R>(R Function(T) mapper) {
    return PaginationModel<R>(
      items: items.map(mapper).toList(),
      currentPage: currentPage,
      perPage: perPage,
      totalItems: totalItems,
      totalPages: totalPages,
      hasNext: hasNext,
      hasPrevious: hasPrevious,
      nextCursor: nextCursor,
      previousCursor: previousCursor,
    );
  }

  /// Append items from another pagination (for infinite scroll)
  PaginationModel<T> append(PaginationModel<T> other) {
    return PaginationModel<T>(
      items: [...items, ...other.items],
      currentPage: other.currentPage,
      perPage: perPage,
      totalItems: other.totalItems,
      totalPages: other.totalPages,
      hasNext: other.hasNext,
      hasPrevious: true,
      nextCursor: other.nextCursor,
      previousCursor: previousCursor,
    );
  }
}