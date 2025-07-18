import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/image/image_model.dart';

/// Model validation utilities
class ModelValidators {
  ModelValidators._();

  /// Validate UserModel
  static List<String> validateUser(UserModel user) {
    final errors = <String>[];

    // Required fields
    if (user.id.isEmpty) errors.add('User ID is required');
    if (user.email.isEmpty) errors.add('Email is required');
    if (user.username.isEmpty) errors.add('Username is required');

    // Email format
    if (!RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$').hasMatch(user.email)) {
      errors.add('Invalid email format');
    }

    // Username format
    if (user.username.length < 3) {
      errors.add('Username must be at least 3 characters');
    }
    if (user.username.length > 20) {
      errors.add('Username must be less than 20 characters');
    }
    if (!RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(user.username)) {
      errors.add('Username can only contain letters, numbers, and underscores');
    }

    // Timestamps
    if (user.createdAt.isAfter(DateTime.now())) {
      errors.add('Created date cannot be in the future');
    }
    if (user.updatedAt.isBefore(user.createdAt)) {
      errors.add('Updated date cannot be before created date');
    }

    return errors;
  }

  /// Validate WardrobeModel
  static List<String> validateWardrobe(WardrobeModel wardrobe) {
    final errors = <String>[];

    // Required fields
    if (wardrobe.id.isEmpty) errors.add('Wardrobe ID is required');
    if (wardrobe.userId.isEmpty) errors.add('User ID is required');
    if (wardrobe.name.isEmpty) errors.add('Wardrobe name is required');

    // Name length
    if (wardrobe.name.length > 100) {
      errors.add('Wardrobe name must be less than 100 characters');
    }

    // Description length
    if (wardrobe.description != null && wardrobe.description!.length > 500) {
      errors.add('Description must be less than 500 characters');
    }

    // Sharing validation
    if (!wardrobe.isShared && wardrobe.sharedWithUserIds.isNotEmpty) {
      errors.add('Cannot have shared users when wardrobe is not shared');
    }

    // Sort order
    if (wardrobe.sortOrder < 0) {
      errors.add('Sort order cannot be negative');
    }

    // Timestamps
    if (wardrobe.createdAt.isAfter(DateTime.now())) {
      errors.add('Created date cannot be in the future');
    }
    if (wardrobe.updatedAt.isBefore(wardrobe.createdAt)) {
      errors.add('Updated date cannot be before created date');
    }

    return errors;
  }

  /// Validate GarmentModel
  static List<String> validateGarment(GarmentModel garment) {
    final errors = <String>[];

    // Required fields
    if (garment.id.isEmpty) errors.add('Garment ID is required');
    if (garment.wardrobeId.isEmpty) errors.add('Wardrobe ID is required');
    if (garment.userId.isEmpty) errors.add('User ID is required');
    if (garment.name.isEmpty) errors.add('Garment name is required');
    if (garment.category.isEmpty) errors.add('Category is required');

    // Name length
    if (garment.name.length > 100) {
      errors.add('Garment name must be less than 100 characters');
    }

    // Description length
    if (garment.description != null && garment.description!.length > 500) {
      errors.add('Description must be less than 500 characters');
    }

    // Price validation
    if (garment.purchasePrice != null && garment.purchasePrice! < 0) {
      errors.add('Purchase price cannot be negative');
    }

    // Wear count
    if (garment.wearCount < 0) {
      errors.add('Wear count cannot be negative');
    }

    // Date validations
    if (garment.purchaseDate != null && garment.purchaseDate!.isAfter(DateTime.now())) {
      errors.add('Purchase date cannot be in the future');
    }
    if (garment.lastWornDate != null) {
      if (garment.lastWornDate!.isAfter(DateTime.now())) {
        errors.add('Last worn date cannot be in the future');
      }
      if (garment.wearCount == 0) {
        errors.add('Cannot have last worn date with zero wear count');
      }
    }

    // Logical validations
    if (garment.wearCount > 0 && garment.lastWornDate == null) {
      errors.add('Must have last worn date if wear count is greater than zero');
    }

    // Image validations
    if (garment.primaryImageId != null && !garment.imageIds.contains(garment.primaryImageId)) {
      errors.add('Primary image must be in the image list');
    }

    // Timestamps
    if (garment.createdAt.isAfter(DateTime.now())) {
      errors.add('Created date cannot be in the future');
    }
    if (garment.updatedAt.isBefore(garment.createdAt)) {
      errors.add('Updated date cannot be before created date');
    }

    return errors;
  }

  /// Validate ImageModel
  static List<String> validateImage(ImageModel image) {
    final errors = <String>[];

    // Required fields
    if (image.id.isEmpty) errors.add('Image ID is required');
    if (image.userId.isEmpty) errors.add('User ID is required');
    if (image.originalUrl.isEmpty) errors.add('Original URL is required');
    if (image.filename.isEmpty) errors.add('Filename is required');
    if (image.mimeType.isEmpty) errors.add('MIME type is required');

    // Either garmentId or wardrobeId should be present
    if (image.garmentId == null && image.wardrobeId == null) {
      errors.add('Image must be associated with either a garment or wardrobe');
    }

    // File validations
    if (image.fileSize <= 0) {
      errors.add('File size must be greater than zero');
    }
    if (image.fileSize > 10 * 1024 * 1024) { // 10MB limit
      errors.add('File size cannot exceed 10MB');
    }

    // Dimension validations
    if (image.width <= 0) errors.add('Width must be greater than zero');
    if (image.height <= 0) errors.add('Height must be greater than zero');
    if (image.width > 5000 || image.height > 5000) {
      errors.add('Image dimensions cannot exceed 5000x5000 pixels');
    }

    // MIME type validation
    final validMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
    if (!validMimeTypes.contains(image.mimeType)) {
      errors.add('Invalid image type. Supported: JPEG, PNG, WebP, GIF');
    }

    // URL validations
    try {
      Uri.parse(image.originalUrl);
    } catch (e) {
      errors.add('Invalid original URL format');
    }

    if (image.thumbnailUrl != null) {
      try {
        Uri.parse(image.thumbnailUrl!);
      } catch (e) {
        errors.add('Invalid thumbnail URL format');
      }
    }

    // Processing validations
    if (image.isProcessed && image.processedUrl == null) {
      errors.add('Processed URL required when image is marked as processed');
    }
    if (image.isBackgroundRemoved && image.backgroundRemovedUrl == null) {
      errors.add('Background removed URL required when background removal is marked');
    }
    if (image.processingError != null && image.processingStatus != 'failed') {
      errors.add('Processing error should only exist when status is failed');
    }

    // Color validations
    if (image.colorPalette != null) {
      for (final color in image.colorPalette!) {
        if (!RegExp(r'^#[0-9A-F]{6}$', caseSensitive: false).hasMatch(color)) {
          errors.add('Invalid color format in palette: $color');
          break;
        }
      }
    }

    if (image.dominantColor != null && 
        !RegExp(r'^#[0-9A-F]{6}$', caseSensitive: false).hasMatch(image.dominantColor!)) {
      errors.add('Invalid dominant color format');
    }

    // Timestamps
    if (image.createdAt.isAfter(DateTime.now())) {
      errors.add('Created date cannot be in the future');
    }
    if (image.updatedAt.isBefore(image.createdAt)) {
      errors.add('Updated date cannot be before created date');
    }

    return errors;
  }

  /// Check if a model is valid (no validation errors)
  static bool isValidUser(UserModel user) => validateUser(user).isEmpty;
  static bool isValidWardrobe(WardrobeModel wardrobe) => validateWardrobe(wardrobe).isEmpty;
  static bool isValidGarment(GarmentModel garment) => validateGarment(garment).isEmpty;
  static bool isValidImage(ImageModel image) => validateImage(image).isEmpty;
}