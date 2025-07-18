import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/domain/entities/image.dart';

part 'image_model.freezed.dart';
part 'image_model.g.dart';

@freezed
class ImageModel with _$ImageModel {
  const ImageModel._();

  const factory ImageModel({
    required String id,
    @JsonKey(name: 'user_id') required String userId,
    @JsonKey(name: 'garment_id') String? garmentId,
    @JsonKey(name: 'wardrobe_id') String? wardrobeId,
    @JsonKey(name: 'original_url') required String originalUrl,
    @JsonKey(name: 'thumbnail_url') String? thumbnailUrl,
    @JsonKey(name: 'processed_url') String? processedUrl,
    @JsonKey(name: 'background_removed_url') String? backgroundRemovedUrl,
    required String filename,
    @JsonKey(name: 'mime_type') required String mimeType,
    @JsonKey(name: 'file_size') required int fileSize,
    required int width,
    required int height,
    @JsonKey(name: 'is_primary') @Default(false) bool isPrimary,
    @JsonKey(name: 'is_processed') @Default(false) bool isProcessed,
    @JsonKey(name: 'is_background_removed') @Default(false) bool isBackgroundRemoved,
    @JsonKey(name: 'processing_status') String? processingStatus,
    @JsonKey(name: 'processing_error') String? processingError,
    @Default({}) Map<String, dynamic> metadata,
    @JsonKey(name: 'created_at') required DateTime createdAt,
    @JsonKey(name: 'updated_at') required DateTime updatedAt,
    @JsonKey(name: 'deleted_at') DateTime? deletedAt,
    @JsonKey(name: 'color_palette') List<String>? colorPalette,
    @JsonKey(name: 'dominant_color') String? dominantColor,
    @JsonKey(name: 'ai_tags') List<String>? aiTags,
    @JsonKey(name: 'ai_description') String? aiDescription,
  }) = _ImageModel;

  factory ImageModel.fromJson(Map<String, dynamic> json) =>
      _$ImageModelFromJson(json);

  /// Convert to domain entity
  Image toEntity() {
    return Image(
      id: id,
      userId: userId,
      garmentId: garmentId,
      wardrobeId: wardrobeId,
      originalUrl: originalUrl,
      thumbnailUrl: thumbnailUrl,
      processedUrl: processedUrl,
      backgroundRemovedUrl: backgroundRemovedUrl,
      filename: filename,
      mimeType: mimeType,
      fileSize: fileSize,
      width: width,
      height: height,
      isPrimary: isPrimary,
      isProcessed: isProcessed,
      isBackgroundRemoved: isBackgroundRemoved,
      metadata: metadata,
      createdAt: createdAt,
      updatedAt: updatedAt,
    );
  }

  /// Create from domain entity
  factory ImageModel.fromEntity(Image image) {
    return ImageModel(
      id: image.id,
      userId: image.userId,
      garmentId: image.garmentId,
      wardrobeId: image.wardrobeId,
      originalUrl: image.originalUrl,
      thumbnailUrl: image.thumbnailUrl,
      processedUrl: image.processedUrl,
      backgroundRemovedUrl: image.backgroundRemovedUrl,
      filename: image.filename,
      mimeType: image.mimeType,
      fileSize: image.fileSize,
      width: image.width,
      height: image.height,
      isPrimary: image.isPrimary,
      isProcessed: image.isProcessed,
      isBackgroundRemoved: image.isBackgroundRemoved,
      metadata: image.metadata,
      createdAt: image.createdAt,
      updatedAt: image.updatedAt,
    );
  }

  /// Get display URL (prioritize processed versions)
  String get displayUrl {
    if (backgroundRemovedUrl != null) return backgroundRemovedUrl!;
    if (processedUrl != null) return processedUrl!;
    return originalUrl;
  }

  /// Get thumbnail URL with fallback
  String get thumbUrl => thumbnailUrl ?? originalUrl;

  /// Get aspect ratio
  double get aspectRatio => width / height;

  /// Check if image is portrait
  bool get isPortrait => height > width;

  /// Check if image is landscape
  bool get isLandscape => width > height;

  /// Check if image is square
  bool get isSquare => width == height;

  /// Get file size in MB
  double get fileSizeInMB => fileSize / (1024 * 1024);

  /// Get human readable file size
  String get readableFileSize {
    if (fileSize < 1024) return '$fileSize B';
    if (fileSize < 1024 * 1024) return '${(fileSize / 1024).toStringAsFixed(1)} KB';
    return '${fileSizeInMB.toStringAsFixed(1)} MB';
  }

  /// Check if processing is in progress
  bool get isProcessing => processingStatus == 'processing';

  /// Check if processing failed
  bool get hasProcessingError => processingError != null;

  /// Get image type from mime type
  String get imageType {
    if (mimeType.contains('jpeg') || mimeType.contains('jpg')) return 'JPEG';
    if (mimeType.contains('png')) return 'PNG';
    if (mimeType.contains('webp')) return 'WebP';
    if (mimeType.contains('gif')) return 'GIF';
    return 'Unknown';
  }
}