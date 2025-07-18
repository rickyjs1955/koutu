import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/image/image_model.dart';
import 'package:koutu/data/models/auth/auth_response_model.dart';

/// Mock data for testing
class MockData {
  static final testUser = UserModel(
    id: 'user_123',
    email: 'test@example.com',
    username: 'testuser',
    fullName: 'Test User',
    avatarUrl: 'https://example.com/avatar.jpg',
    bio: 'Test bio',
    isEmailVerified: true,
    isPremium: false,
    preferences: const {},
    createdAt: DateTime(2024, 1, 1),
    updatedAt: DateTime(2024, 1, 1),
  );

  static final testAuthResponse = AuthResponseModel(
    user: testUser,
    accessToken: 'test_access_token',
    refreshToken: 'test_refresh_token',
    expiresIn: 3600,
  );

  static final testWardrobe = WardrobeModel(
    id: 'wardrobe_123',
    userId: 'user_123',
    name: 'Summer Collection',
    description: 'My summer wardrobe',
    imageUrl: 'https://example.com/wardrobe.jpg',
    colorTheme: 'blue',
    iconName: 'wardrobe',
    isDefault: true,
    isShared: false,
    garmentIds: ['garment_1', 'garment_2'],
    createdAt: DateTime(2024, 1, 1),
    updatedAt: DateTime(2024, 1, 1),
  );

  static final testWardrobe2 = WardrobeModel(
    id: 'wardrobe_456',
    userId: 'user_123',
    name: 'Winter Collection',
    description: 'My winter wardrobe',
    imageUrl: 'https://example.com/wardrobe2.jpg',
    colorTheme: 'purple',
    iconName: 'hanger',
    isDefault: false,
    isShared: true,
    garmentIds: ['garment_3', 'garment_4'],
    createdAt: DateTime(2024, 1, 2),
    updatedAt: DateTime(2024, 1, 2),
  );

  static final testImage = ImageModel(
    id: 'image_123',
    url: 'https://example.com/garment.jpg',
    thumbnailUrl: 'https://example.com/garment_thumb.jpg',
    width: 800,
    height: 1200,
    size: 102400, // 100KB
    hash: 'abc123',
    createdAt: DateTime(2024, 1, 1),
  );

  static final testGarment = GarmentModel(
    id: 'garment_123',
    wardrobeId: 'wardrobe_123',
    name: 'Blue T-Shirt',
    category: 'tops',
    subcategory: 'T-Shirt',
    brand: 'Nike',
    colors: ['blue', 'white'],
    size: 'M',
    material: 'Cotton',
    price: 29.99,
    purchaseDate: DateTime(2024, 1, 1),
    tags: ['casual', 'summer', 'favorite'],
    notes: 'Comfortable for daily wear',
    images: [testImage],
    isFavorite: true,
    wearCount: 10,
    lastWornDate: DateTime(2024, 1, 15),
    createdAt: DateTime(2024, 1, 1),
    updatedAt: DateTime(2024, 1, 15),
  );

  static final testGarment2 = GarmentModel(
    id: 'garment_456',
    wardrobeId: 'wardrobe_123',
    name: 'Black Jeans',
    category: 'bottoms',
    subcategory: 'Jeans',
    brand: 'Levi\'s',
    colors: ['black'],
    size: '32',
    material: 'Denim',
    price: 79.99,
    purchaseDate: DateTime(2024, 1, 10),
    tags: ['casual', 'versatile'],
    notes: null,
    images: [
      ImageModel(
        id: 'image_456',
        url: 'https://example.com/jeans.jpg',
        thumbnailUrl: 'https://example.com/jeans_thumb.jpg',
        width: 800,
        height: 1200,
        createdAt: DateTime(2024, 1, 10),
      ),
    ],
    isFavorite: false,
    wearCount: 5,
    lastWornDate: DateTime(2024, 1, 20),
    createdAt: DateTime(2024, 1, 10),
    updatedAt: DateTime(2024, 1, 20),
  );

  static List<WardrobeModel> get testWardrobes => [testWardrobe, testWardrobe2];
  
  static List<GarmentModel> get testGarments => [testGarment, testGarment2];

  static List<GarmentModel> generateGarments(int count) {
    return List.generate(count, (index) {
      final categories = ['tops', 'bottoms', 'dresses', 'outerwear', 'shoes', 'accessories'];
      final category = categories[index % categories.length];
      
      return GarmentModel(
        id: 'garment_${1000 + index}',
        wardrobeId: index % 2 == 0 ? 'wardrobe_123' : 'wardrobe_456',
        name: 'Test Garment ${index + 1}',
        category: category,
        subcategory: _getSubcategory(category),
        brand: ['Nike', 'Adidas', 'Zara', 'H&M', 'Uniqlo'][index % 5],
        colors: _getColors(index),
        size: ['XS', 'S', 'M', 'L', 'XL'][index % 5],
        material: ['Cotton', 'Polyester', 'Wool', 'Silk', 'Denim'][index % 5],
        price: 19.99 + (index * 10),
        purchaseDate: DateTime(2024, 1, 1).add(Duration(days: index)),
        tags: _getTags(index),
        notes: index % 3 == 0 ? 'Test notes for garment ${index + 1}' : null,
        images: [
          ImageModel(
            id: 'image_${1000 + index}',
            url: 'https://example.com/garment_${index + 1}.jpg',
            thumbnailUrl: 'https://example.com/garment_${index + 1}_thumb.jpg',
            width: 800,
            height: 1200,
            createdAt: DateTime(2024, 1, 1),
          ),
        ],
        isFavorite: index % 4 == 0,
        wearCount: index % 20,
        lastWornDate: index % 2 == 0 
            ? DateTime(2024, 1, 1).add(Duration(days: index * 2))
            : null,
        createdAt: DateTime(2024, 1, 1).add(Duration(days: index)),
        updatedAt: DateTime(2024, 1, 1).add(Duration(days: index)),
      );
    });
  }

  static String _getSubcategory(String category) {
    switch (category) {
      case 'tops':
        return 'T-Shirt';
      case 'bottoms':
        return 'Jeans';
      case 'dresses':
        return 'Casual Dress';
      case 'outerwear':
        return 'Jacket';
      case 'shoes':
        return 'Sneakers';
      case 'accessories':
        return 'Bag';
      default:
        return 'Other';
    }
  }

  static List<String> _getColors(int index) {
    final allColors = [
      ['black'],
      ['white'],
      ['blue'],
      ['red', 'white'],
      ['green', 'black'],
      ['navy', 'grey'],
      ['pink'],
      ['yellow', 'blue'],
    ];
    return allColors[index % allColors.length];
  }

  static List<String> _getTags(int index) {
    final allTags = [
      ['casual'],
      ['formal', 'work'],
      ['summer', 'casual'],
      ['winter', 'warm'],
      ['party', 'evening'],
      ['sport', 'comfortable'],
      ['vintage', 'unique'],
      ['basic', 'versatile'],
    ];
    return allTags[index % allTags.length];
  }
}