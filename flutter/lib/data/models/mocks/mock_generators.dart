import 'dart:math';
import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/image/image_model.dart';

/// Mock data generators for testing
class MockGenerators {
  static final _random = Random();

  /// Generate a mock user
  static UserModel generateUser({
    String? id,
    String? email,
    String? username,
  }) {
    final userId = id ?? 'user_${_random.nextInt(10000)}';
    final userEmail = email ?? 'user$userId@example.com';
    final userUsername = username ?? 'user$userId';

    return UserModel(
      id: userId,
      email: userEmail,
      username: userUsername,
      firstName: _randomFirstName(),
      lastName: _randomLastName(),
      profilePictureUrl: 'https://i.pravatar.cc/300?u=$userId',
      isEmailVerified: _random.nextBool(),
      wardrobeIds: List.generate(_random.nextInt(3) + 1, (i) => 'wardrobe_$i'),
      createdAt: DateTime.now().subtract(Duration(days: _random.nextInt(365))),
      updatedAt: DateTime.now(),
      lastLoginAt: DateTime.now().subtract(Duration(hours: _random.nextInt(48))),
    );
  }

  /// Generate a mock wardrobe
  static WardrobeModel generateWardrobe({
    String? id,
    String? userId,
    String? name,
  }) {
    final wardrobeId = id ?? 'wardrobe_${_random.nextInt(10000)}';
    final wardrobeUserId = userId ?? 'user_${_random.nextInt(1000)}';
    final wardrobeName = name ?? _randomWardrobeName();

    return WardrobeModel(
      id: wardrobeId,
      userId: wardrobeUserId,
      name: wardrobeName,
      description: 'A collection of ${wardrobeName.toLowerCase()} items',
      imageUrl: 'https://picsum.photos/400/300?random=$wardrobeId',
      garmentIds: List.generate(_random.nextInt(20) + 5, (i) => 'garment_$i'),
      isShared: _random.nextBool(),
      sharedWithUserIds: _random.nextBool() 
          ? List.generate(_random.nextInt(3) + 1, (i) => 'user_$i')
          : [],
      isDefault: _random.nextBool() && _random.nextBool(),
      sortOrder: _random.nextInt(10),
      colorTheme: _randomColorTheme(),
      iconName: _randomIconName(),
      createdAt: DateTime.now().subtract(Duration(days: _random.nextInt(365))),
      updatedAt: DateTime.now(),
    );
  }

  /// Generate a mock garment
  static GarmentModel generateGarment({
    String? id,
    String? wardrobeId,
    String? userId,
  }) {
    final garmentId = id ?? 'garment_${_random.nextInt(10000)}';
    final garmentWardrobeId = wardrobeId ?? 'wardrobe_${_random.nextInt(1000)}';
    final garmentUserId = userId ?? 'user_${_random.nextInt(1000)}';

    final category = _randomCategory();
    final subcategory = _randomSubcategory(category);
    final purchasePrice = _random.nextDouble() * 200 + 10;
    final wearCount = _random.nextInt(50);

    return GarmentModel(
      id: garmentId,
      wardrobeId: garmentWardrobeId,
      userId: garmentUserId,
      name: _randomGarmentName(category),
      description: 'A stylish $subcategory',
      category: category,
      subcategory: subcategory,
      brand: _randomBrand(),
      size: _randomSize(),
      colors: _randomColors(),
      tags: _randomTags(),
      imageIds: List.generate(_random.nextInt(3) + 1, (i) => 'image_${garmentId}_$i'),
      primaryImageId: 'image_${garmentId}_0',
      purchasePrice: purchasePrice,
      purchaseDate: DateTime.now().subtract(Duration(days: _random.nextInt(730))),
      purchaseLocation: _randomStore(),
      wearCount: wearCount,
      lastWornDate: wearCount > 0 
          ? DateTime.now().subtract(Duration(days: _random.nextInt(30)))
          : null,
      isFavorite: _random.nextBool() && _random.nextBool(),
      season: _randomSeasons(),
      occasion: _randomOccasions(),
      material: _randomMaterials(),
      careInstructions: 'Machine wash cold, tumble dry low',
      notes: _random.nextBool() ? 'Gift from ${_randomFirstName()}' : null,
      createdAt: DateTime.now().subtract(Duration(days: _random.nextInt(365))),
      updatedAt: DateTime.now(),
    );
  }

  /// Generate a mock image
  static ImageModel generateImage({
    String? id,
    String? userId,
    String? garmentId,
    String? wardrobeId,
  }) {
    final imageId = id ?? 'image_${_random.nextInt(10000)}';
    final imageUserId = userId ?? 'user_${_random.nextInt(1000)}';
    final width = 800 + _random.nextInt(1200);
    final height = 800 + _random.nextInt(1200);

    return ImageModel(
      id: imageId,
      userId: imageUserId,
      garmentId: garmentId,
      wardrobeId: wardrobeId,
      originalUrl: 'https://picsum.photos/$width/$height?random=$imageId',
      thumbnailUrl: 'https://picsum.photos/200/200?random=$imageId',
      processedUrl: _random.nextBool() 
          ? 'https://picsum.photos/$width/$height?random=$imageId&processed=true'
          : null,
      backgroundRemovedUrl: _random.nextBool() && _random.nextBool()
          ? 'https://picsum.photos/$width/$height?random=$imageId&bg_removed=true'
          : null,
      filename: 'image_$imageId.jpg',
      mimeType: 'image/jpeg',
      fileSize: width * height * 3,
      width: width,
      height: height,
      isPrimary: _random.nextBool() && _random.nextBool(),
      isProcessed: _random.nextBool(),
      isBackgroundRemoved: _random.nextBool() && _random.nextBool(),
      colorPalette: _randomColorPalette(),
      dominantColor: _randomHexColor(),
      aiTags: _random.nextBool() ? _randomAiTags() : null,
      createdAt: DateTime.now().subtract(Duration(days: _random.nextInt(365))),
      updatedAt: DateTime.now(),
    );
  }

  // Helper methods for random data generation

  static String _randomFirstName() {
    final names = ['Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'Ethan', 'Sophia', 'Mason', 'Isabella', 'William'];
    return names[_random.nextInt(names.length)];
  }

  static String _randomLastName() {
    final names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez'];
    return names[_random.nextInt(names.length)];
  }

  static String _randomWardrobeName() {
    final names = ['Summer Collection', 'Work Attire', 'Casual Wear', 'Formal Outfits', 'Sports Gear', 'Weekend Wardrobe', 'Travel Essentials', 'Party Clothes'];
    return names[_random.nextInt(names.length)];
  }

  static String _randomColorTheme() {
    final themes = ['blue', 'green', 'purple', 'pink', 'orange', 'teal', 'indigo', 'amber'];
    return themes[_random.nextInt(themes.length)];
  }

  static String _randomIconName() {
    final icons = ['wardrobe', 'hanger', 'shirt', 'dress', 'suit', 'casual', 'sport', 'formal'];
    return icons[_random.nextInt(icons.length)];
  }

  static String _randomCategory() {
    final categories = ['Tops', 'Bottoms', 'Dresses', 'Outerwear', 'Shoes', 'Accessories'];
    return categories[_random.nextInt(categories.length)];
  }

  static String _randomSubcategory(String category) {
    final subcategories = {
      'Tops': ['T-Shirt', 'Shirt', 'Blouse', 'Tank Top', 'Sweater'],
      'Bottoms': ['Jeans', 'Trousers', 'Shorts', 'Skirt', 'Leggings'],
      'Dresses': ['Casual Dress', 'Formal Dress', 'Maxi Dress', 'Mini Dress'],
      'Outerwear': ['Jacket', 'Coat', 'Blazer', 'Cardigan'],
      'Shoes': ['Sneakers', 'Boots', 'Heels', 'Flats', 'Sandals'],
      'Accessories': ['Belt', 'Scarf', 'Hat', 'Bag', 'Watch'],
    };
    final options = subcategories[category] ?? ['Other'];
    return options[_random.nextInt(options.length)];
  }

  static String _randomGarmentName(String category) {
    final prefixes = ['Classic', 'Modern', 'Vintage', 'Designer', 'Casual', 'Formal', 'Stylish'];
    final prefix = prefixes[_random.nextInt(prefixes.length)];
    return '$prefix $category';
  }

  static String _randomBrand() {
    final brands = ['Nike', 'Adidas', 'Zara', 'H&M', 'Uniqlo', 'Gap', 'Levi\'s', 'Ralph Lauren', 'Tommy Hilfiger', 'Calvin Klein'];
    return brands[_random.nextInt(brands.length)];
  }

  static String _randomSize() {
    final sizes = ['XS', 'S', 'M', 'L', 'XL', 'XXL'];
    return sizes[_random.nextInt(sizes.length)];
  }

  static List<String> _randomColors() {
    final colors = ['Black', 'White', 'Blue', 'Red', 'Green', 'Yellow', 'Purple', 'Pink', 'Gray', 'Brown', 'Navy', 'Beige'];
    final count = _random.nextInt(3) + 1;
    return List.generate(count, (i) => colors[_random.nextInt(colors.length)])
        .toSet()
        .toList();
  }

  static List<String> _randomTags() {
    final tags = ['Comfortable', 'Stylish', 'Casual', 'Formal', 'Business', 'Party', 'Sports', 'Travel', 'Favorite', 'New'];
    final count = _random.nextInt(4);
    return List.generate(count, (i) => tags[_random.nextInt(tags.length)])
        .toSet()
        .toList();
  }

  static String _randomStore() {
    final stores = ['Nordstrom', 'Macy\'s', 'Target', 'Amazon', 'Walmart', 'Local Boutique', 'Online Store', 'Outlet Mall'];
    return stores[_random.nextInt(stores.length)];
  }

  static List<String> _randomSeasons() {
    final seasons = ['Spring', 'Summer', 'Fall', 'Winter'];
    final count = _random.nextInt(3) + 1;
    return List.generate(count, (i) => seasons[_random.nextInt(seasons.length)])
        .toSet()
        .toList();
  }

  static List<String> _randomOccasions() {
    final occasions = ['Work', 'Casual', 'Formal', 'Party', 'Date', 'Sports', 'Beach', 'Travel'];
    final count = _random.nextInt(3) + 1;
    return List.generate(count, (i) => occasions[_random.nextInt(occasions.length)])
        .toSet()
        .toList();
  }

  static List<String> _randomMaterials() {
    final materials = ['Cotton', 'Polyester', 'Wool', 'Silk', 'Denim', 'Leather', 'Linen', 'Rayon'];
    final count = _random.nextInt(3) + 1;
    return List.generate(count, (i) => materials[_random.nextInt(materials.length)])
        .toSet()
        .toList();
  }

  static List<String> _randomColorPalette() {
    final count = _random.nextInt(4) + 2;
    return List.generate(count, (i) => _randomHexColor());
  }

  static String _randomHexColor() {
    final color = _random.nextInt(0xFFFFFF);
    return '#${color.toRadixString(16).padLeft(6, '0').toUpperCase()}';
  }

  static List<String> _randomAiTags() {
    final tags = ['striped', 'floral', 'solid', 'patterned', 'casual', 'formal', 'modern', 'vintage', 'elegant', 'sporty'];
    final count = _random.nextInt(4) + 1;
    return List.generate(count, (i) => tags[_random.nextInt(tags.length)])
        .toSet()
        .toList();
  }
}