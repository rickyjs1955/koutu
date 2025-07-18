import 'package:flutter/material.dart';

class AppConstants {
  // App Info
  static const String appName = 'Koutu';
  static const String appVersion = '1.0.0';
  
  // API
  static const Duration apiTimeout = Duration(seconds: 30);
  static const int maxRetries = 3;
  
  // Storage
  static const String authTokenKey = 'auth_token';
  static const String refreshTokenKey = 'refresh_token';
  static const String userKey = 'user';
  static const String themeKey = 'theme';
  static const String localeKey = 'locale';
  
  // Pagination
  static const int defaultPageSize = 20;
  
  // Image
  static const int imageQuality = 85;
  static const double maxImageWidth = 1080;
  static const double maxImageHeight = 1920;
  static const double thumbnailSize = 200;
  
  // Garment Categories
  static const List<String> garmentCategories = [
    'tops',
    'bottoms',
    'dresses',
    'outerwear',
    'shoes',
    'accessories',
  ];
  
  // Colors
  static const Map<String, Color> colors = {
    'black': Colors.black,
    'white': Colors.white,
    'grey': Colors.grey,
    'navy': Color(0xFF000080),
    'blue': Colors.blue,
    'lightblue': Colors.lightBlue,
    'red': Colors.red,
    'burgundy': Color(0xFF800020),
    'pink': Colors.pink,
    'orange': Colors.orange,
    'yellow': Colors.yellow,
    'green': Colors.green,
    'olive': Color(0xFF808000),
    'purple': Colors.purple,
    'brown': Colors.brown,
    'beige': Color(0xFFF5F5DC),
    'cream': Color(0xFFFFFDD0),
    'gold': Color(0xFFFFD700),
    'silver': Color(0xFFC0C0C0),
  };
  
  // Sizes
  static const List<String> clothingSizes = [
    'XXS',
    'XS',
    'S',
    'M',
    'L',
    'XL',
    'XXL',
    'XXXL',
  ];
  
  static const List<String> shoeSizes = [
    '35', '35.5', '36', '36.5', '37', '37.5', '38', '38.5',
    '39', '39.5', '40', '40.5', '41', '41.5', '42', '42.5',
    '43', '43.5', '44', '44.5', '45', '45.5', '46',
  ];
  
  // Materials
  static const List<String> materials = [
    'Cotton',
    'Polyester',
    'Wool',
    'Silk',
    'Linen',
    'Denim',
    'Leather',
    'Suede',
    'Velvet',
    'Satin',
    'Chiffon',
    'Jersey',
    'Fleece',
    'Nylon',
    'Rayon',
    'Spandex',
    'Cashmere',
    'Acrylic',
    'Modal',
    'Bamboo',
  ];
  
  // Weather conditions
  static const List<String> weatherConditions = [
    'Sunny',
    'Cloudy',
    'Rainy',
    'Snowy',
    'Windy',
    'Hot',
    'Cold',
    'Mild',
  ];
  
  // Occasions
  static const List<String> occasions = [
    'Casual',
    'Formal',
    'Business',
    'Party',
    'Wedding',
    'Date',
    'Sport',
    'Beach',
    'Travel',
    'Home',
  ];
  
  // Validation
  static const int minPasswordLength = 8;
  static const int maxPasswordLength = 128;
  static const int minUsernameLength = 3;
  static const int maxUsernameLength = 30;
  static const int maxBioLength = 500;
  
  // Date formats
  static const String dateFormat = 'dd/MM/yyyy';
  static const String timeFormat = 'HH:mm';
  static const String dateTimeFormat = 'dd/MM/yyyy HH:mm';
  
  // Regular expressions
  static final RegExp emailRegex = RegExp(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
  );
  
  static final RegExp usernameRegex = RegExp(
    r'^[a-zA-Z0-9_]+$',
  );
  
  static final RegExp urlRegex = RegExp(
    r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$',
  );
}