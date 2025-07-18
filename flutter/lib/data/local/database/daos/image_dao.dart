import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/images_table.dart';
import 'package:koutu/data/models/image/image_model.dart';

part 'image_dao.g.dart';

@DriftAccessor(tables: [Images])
class ImageDao extends DatabaseAccessor<AppDatabase> with _$ImageDaoMixin {
  ImageDao(AppDatabase db) : super(db);

  /// Get all images for a garment
  Future<List<Image>> getImagesForGarment(String garmentId) async {
    return await (select(images)
          ..where((i) => i.garmentId.equals(garmentId))
          ..orderBy([(i) => OrderingTerm(expression: i.isPrimary, mode: OrderingMode.desc)]))
        .get();
  }

  /// Get all images for a wardrobe
  Future<List<Image>> getImagesForWardrobe(String wardrobeId) async {
    return await (select(images)..where((i) => i.wardrobeId.equals(wardrobeId))).get();
  }

  /// Get image by ID
  Future<Image?> getImageById(String id) async {
    return await (select(images)..where((i) => i.id.equals(id))).getSingleOrNull();
  }

  /// Get images by IDs
  Future<List<Image>> getImagesByIds(List<String> ids) async {
    return await (select(images)..where((i) => i.id.isIn(ids))).get();
  }

  /// Get primary image for garment
  Future<Image?> getPrimaryImageForGarment(String garmentId) async {
    return await (select(images)
          ..where((i) => i.garmentId.equals(garmentId) & i.isPrimary.equals(true)))
        .getSingleOrNull();
  }

  /// Get unprocessed images
  Future<List<Image>> getUnprocessedImages() async {
    return await (select(images)
          ..where((i) => i.isProcessed.equals(false))
          ..orderBy([(i) => OrderingTerm(expression: i.createdAt)]))
        .get();
  }

  /// Get images with failed processing
  Future<List<Image>> getFailedProcessingImages() async {
    return await (select(images)
          ..where((i) => i.processingStatus.equals('failed')))
        .get();
  }

  /// Insert or update image
  Future<void> upsertImage(ImageModel imageModel) async {
    await into(images).insertOnConflictUpdate(
      Image(
        id: imageModel.id,
        userId: imageModel.userId,
        garmentId: imageModel.garmentId,
        wardrobeId: imageModel.wardrobeId,
        originalUrl: imageModel.originalUrl,
        thumbnailUrl: imageModel.thumbnailUrl,
        processedUrl: imageModel.processedUrl,
        backgroundRemovedUrl: imageModel.backgroundRemovedUrl,
        localPath: null, // Set separately when downloaded
        filename: imageModel.filename,
        mimeType: imageModel.mimeType,
        fileSize: imageModel.fileSize,
        width: imageModel.width,
        height: imageModel.height,
        isPrimary: imageModel.isPrimary,
        isProcessed: imageModel.isProcessed,
        isBackgroundRemoved: imageModel.isBackgroundRemoved,
        processingStatus: imageModel.processingStatus,
        processingError: imageModel.processingError,
        colorPalette: imageModel.colorPalette,
        dominantColor: imageModel.dominantColor,
        aiTags: imageModel.aiTags,
        metadata: imageModel.metadata,
        createdAt: imageModel.createdAt,
        updatedAt: imageModel.updatedAt,
        lastSyncedAt: DateTime.now(),
      ),
    );
  }

  /// Update image processing status
  Future<void> updateProcessingStatus(
    String imageId,
    String status, {
    String? processedUrl,
    String? error,
  }) async {
    await (update(images)..where((i) => i.id.equals(imageId))).write(
      ImagesCompanion(
        processingStatus: Value(status),
        isProcessed: Value(status == 'completed'),
        processedUrl: Value(processedUrl),
        processingError: Value(error),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Update background removal status
  Future<void> updateBackgroundRemoval(
    String imageId,
    String? backgroundRemovedUrl,
  ) async {
    await (update(images)..where((i) => i.id.equals(imageId))).write(
      ImagesCompanion(
        isBackgroundRemoved: Value(backgroundRemovedUrl != null),
        backgroundRemovedUrl: Value(backgroundRemovedUrl),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Update AI tags and colors
  Future<void> updateImageAnalysis(
    String imageId, {
    List<String>? aiTags,
    List<String>? colorPalette,
    String? dominantColor,
  }) async {
    await (update(images)..where((i) => i.id.equals(imageId))).write(
      ImagesCompanion(
        aiTags: aiTags != null ? Value(aiTags) : const Value.absent(),
        colorPalette: colorPalette != null ? Value(colorPalette) : const Value.absent(),
        dominantColor: dominantColor != null ? Value(dominantColor) : const Value.absent(),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Update local path after download
  Future<void> updateLocalPath(String imageId, String localPath) async {
    await (update(images)..where((i) => i.id.equals(imageId))).write(
      ImagesCompanion(
        localPath: Value(localPath),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Set primary image for garment
  Future<void> setPrimaryImageForGarment(String garmentId, String imageId) async {
    await transaction(() async {
      // Remove primary from all other images
      await (update(images)..where((i) => i.garmentId.equals(garmentId))).write(
        const ImagesCompanion(isPrimary: Value(false)),
      );
      
      // Set the new primary
      await (update(images)..where((i) => i.id.equals(imageId))).write(
        const ImagesCompanion(isPrimary: Value(true)),
      );
    });
  }

  /// Delete image
  Future<void> deleteImage(String imageId) async {
    await (delete(images)..where((i) => i.id.equals(imageId))).go();
  }

  /// Delete images for garment
  Future<void> deleteImagesForGarment(String garmentId) async {
    await (delete(images)..where((i) => i.garmentId.equals(garmentId))).go();
  }

  /// Get image statistics
  Future<Map<String, dynamic>> getImageStatistics() async {
    final allImages = await select(images).get();
    
    return {
      'totalCount': allImages.length,
      'processedCount': allImages.where((i) => i.isProcessed).length,
      'backgroundRemovedCount': allImages.where((i) => i.isBackgroundRemoved).length,
      'failedCount': allImages.where((i) => i.processingStatus == 'failed').length,
      'totalSizeBytes': allImages.fold<int>(0, (sum, i) => sum + i.fileSize),
      'averageSizeBytes': allImages.isEmpty ? 0 : 
          allImages.fold<int>(0, (sum, i) => sum + i.fileSize) ~/ allImages.length,
    };
  }

  /// Convert database image to ImageModel
  ImageModel imageToModel(Image image) {
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
      processingStatus: image.processingStatus,
      processingError: image.processingError,
      colorPalette: image.colorPalette,
      dominantColor: image.dominantColor,
      aiTags: image.aiTags,
      metadata: image.metadata,
      createdAt: image.createdAt,
      updatedAt: image.updatedAt,
    );
  }
}