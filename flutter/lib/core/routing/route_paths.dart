/// Route path constants for the application
class RoutePaths {
  RoutePaths._();

  // Initial routes
  static const String splash = '/';
  static const String onboarding = '/onboarding';

  // Auth routes
  static const String login = '/login';
  static const String register = '/register';
  static const String forgotPassword = '/forgot-password';

  // Main app routes
  static const String home = '/home';
  
  // Wardrobe routes
  static const String wardrobeList = '/wardrobes';
  static const String wardrobeDetail = '/wardrobe/:id';
  static const String createWardrobe = '/wardrobe/create';
  
  // Garment routes
  static const String garmentList = '/garments';
  static const String garmentDetail = '/garment/:id';
  static const String addGarment = '/garment/add';
  
  // Camera routes
  static const String camera = '/camera';
  static const String imagePreview = '/camera/preview';
  
  // Profile routes
  static const String profile = '/profile';
  static const String editProfile = '/profile/edit';
  static const String settings = '/settings';
  
  // Outfit routes
  static const String outfitBuilder = '/outfit/builder';
  static const String outfitHistory = '/outfit/history';
}