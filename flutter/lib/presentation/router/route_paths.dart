/// Route paths for navigation
class RoutePaths {
  // Auth routes
  static const String login = '/login';
  static const String register = '/register';
  static const String forgotPassword = '/forgot-password';
  static const String resetPassword = '/reset-password';
  
  // Onboarding
  static const String onboarding = '/onboarding';
  
  // Main app routes
  static const String home = '/';
  static const String profile = '/profile';
  static const String settings = '/settings';
  
  // Wardrobe routes
  static const String wardrobes = '/wardrobes';
  static const String createWardrobe = '/wardrobes/create';
  static String wardrobeDetail(String id) => '/wardrobes/$id';
  static String editWardrobe(String id) => '/wardrobes/$id/edit';
  
  // Garment routes
  static const String garments = '/garments';
  static String addGarment(String wardrobeId) => '/wardrobes/$wardrobeId/garments/add';
  static String garmentDetail(String id) => '/garments/$id';
  static String editGarment(String id) => '/garments/$id/edit';
  
  // Outfit routes
  static const String outfits = '/outfits';
  static const String createOutfit = '/outfits/create';
  static String outfitDetail(String id) => '/outfits/$id';
  
  // Calendar
  static const String calendar = '/calendar';
  
  // Statistics
  static const String statistics = '/statistics';
  
  // Camera
  static const String camera = '/camera';
  
  // Image processing
  static const String imageProcessing = '/image-processing';
  static const String backgroundRemoval = '/image-processing/background-removal';
}