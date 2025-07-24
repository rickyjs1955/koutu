class Wardrobe {
  final String id;
  final String name;
  final DateTime createdDate;
  final String? description;
  final int itemCount;

  Wardrobe({
    required this.id,
    required this.name,
    required this.createdDate,
    this.description,
    this.itemCount = 0,
  });

  // Generate unique ID
  static String generateId() {
    return DateTime.now().millisecondsSinceEpoch.toString();
  }
}