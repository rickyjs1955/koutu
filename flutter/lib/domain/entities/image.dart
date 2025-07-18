import 'package:equatable/equatable.dart';

/// Image entity representing an image in the domain layer
class Image extends Equatable {
  final String id;
  final String userId;
  final String? garmentId;
  final String? wardrobeId;
  final String originalUrl;
  final String? thumbnailUrl;
  final String? processedUrl;
  final String? backgroundRemovedUrl;
  final String filename;
  final String mimeType;
  final int fileSize;
  final int width;
  final int height;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isProcessed;
  final bool hasBackgroundRemoved;

  const Image({
    required this.id,
    required this.userId,
    this.garmentId,
    this.wardrobeId,
    required this.originalUrl,
    this.thumbnailUrl,
    this.processedUrl,
    this.backgroundRemovedUrl,
    required this.filename,
    required this.mimeType,
    required this.fileSize,
    required this.width,
    required this.height,
    this.metadata,
    required this.createdAt,
    required this.updatedAt,
    this.isProcessed = false,
    this.hasBackgroundRemoved = false,
  });

  /// Get the display URL (prioritize processed URL over original)
  String get displayUrl => processedUrl ?? originalUrl;

  /// Get the aspect ratio of the image
  double get aspectRatio => width > 0 && height > 0 ? width / height : 1.0;

  /// Check if the image is portrait orientation
  bool get isPortrait => height > width;

  /// Check if the image is landscape orientation
  bool get isLandscape => width > height;

  /// Check if the image is square
  bool get isSquare => width == height;

  /// Get file size in MB
  double get fileSizeInMB => fileSize / (1024 * 1024);

  /// Get a human-readable file size
  String get readableFileSize {
    if (fileSize < 1024) {
      return '$fileSize B';
    } else if (fileSize < 1024 * 1024) {
      return '${(fileSize / 1024).toStringAsFixed(2)} KB';
    } else {
      return '${fileSizeInMB.toStringAsFixed(2)} MB';
    }
  }

  /// Create a copy of Image with updated fields
  Image copyWith({
    String? id,
    String? userId,
    String? garmentId,
    String? wardrobeId,
    String? originalUrl,
    String? thumbnailUrl,
    String? processedUrl,
    String? backgroundRemovedUrl,
    String? filename,
    String? mimeType,
    int? fileSize,
    int? width,
    int? height,
    Map<String, dynamic>? metadata,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isProcessed,
    bool? hasBackgroundRemoved,
  }) {
    return Image(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      garmentId: garmentId ?? this.garmentId,
      wardrobeId: wardrobeId ?? this.wardrobeId,
      originalUrl: originalUrl ?? this.originalUrl,
      thumbnailUrl: thumbnailUrl ?? this.thumbnailUrl,
      processedUrl: processedUrl ?? this.processedUrl,
      backgroundRemovedUrl: backgroundRemovedUrl ?? this.backgroundRemovedUrl,
      filename: filename ?? this.filename,
      mimeType: mimeType ?? this.mimeType,
      fileSize: fileSize ?? this.fileSize,
      width: width ?? this.width,
      height: height ?? this.height,
      metadata: metadata ?? this.metadata,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isProcessed: isProcessed ?? this.isProcessed,
      hasBackgroundRemoved: hasBackgroundRemoved ?? this.hasBackgroundRemoved,
    );
  }

  @override
  List<Object?> get props => [
        id,
        userId,
        garmentId,
        wardrobeId,
        originalUrl,
        thumbnailUrl,
        processedUrl,
        backgroundRemovedUrl,
        filename,
        mimeType,
        fileSize,
        width,
        height,
        metadata,
        createdAt,
        updatedAt,
        isProcessed,
        hasBackgroundRemoved,
      ];
}