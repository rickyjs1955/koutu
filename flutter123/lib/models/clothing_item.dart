import 'dart:io';

class ClothingItem {
  final String id;
  final String imagePath;
  final DateTime addedDate;
  final String? category;
  final String? color;
  final String? brand;
  final String? notes;

  ClothingItem({
    required this.id,
    required this.imagePath,
    required this.addedDate,
    this.category,
    this.color,
    this.brand,
    this.notes,
  });

  // For web compatibility
  bool get isNetworkImage => imagePath.startsWith('http') || imagePath.startsWith('data:');
  
  // Generate unique ID
  static String generateId() {
    return DateTime.now().millisecondsSinceEpoch.toString();
  }
}