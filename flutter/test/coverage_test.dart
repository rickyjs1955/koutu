// This file is used to ensure all source files are included in coverage reports
// Import all source files here

// Core
import 'package:koutu/core/constants/api_constants.dart';
import 'package:koutu/core/constants/app_constants.dart';
import 'package:koutu/core/error/exceptions.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:koutu/core/network/api_response.dart';
import 'package:koutu/core/network/network_info.dart';
import 'package:koutu/core/utils/validators.dart';

// Data layer
import 'package:koutu/data/datasources/local/app_database.dart';
import 'package:koutu/data/datasources/remote/api_client.dart';
import 'package:koutu/data/models/auth/auth_request_model.dart';
import 'package:koutu/data/models/auth/auth_response_model.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/image/image_model.dart';
import 'package:koutu/data/models/user/user_model.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/data/repositories/auth_repository.dart';
import 'package:koutu/data/repositories/garment_repository.dart';
import 'package:koutu/data/repositories/image_repository.dart';
import 'package:koutu/data/repositories/wardrobe_repository.dart';

// Domain layer
import 'package:koutu/domain/repositories/i_auth_repository.dart';
import 'package:koutu/domain/repositories/i_garment_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/domain/repositories/i_wardrobe_repository.dart';

// Presentation layer - BLoCs
import 'package:koutu/presentation/bloc/auth/auth_bloc.dart';
import 'package:koutu/presentation/bloc/garment/garment_bloc.dart';
import 'package:koutu/presentation/bloc/wardrobe/wardrobe_bloc.dart';

// Presentation layer - Screens
import 'package:koutu/presentation/screens/auth/login_screen.dart';
import 'package:koutu/presentation/screens/auth/register_screen.dart';
import 'package:koutu/presentation/screens/auth/forgot_password_screen.dart';
import 'package:koutu/presentation/screens/garment/add_garment_screen.dart';
import 'package:koutu/presentation/screens/garment/garment_detail_screen.dart';
import 'package:koutu/presentation/screens/garment/garment_list_screen.dart';
import 'package:koutu/presentation/screens/home/home_screen.dart';
import 'package:koutu/presentation/screens/image/camera_capture_screen.dart';
import 'package:koutu/presentation/screens/wardrobe/create_wardrobe_screen.dart';
import 'package:koutu/presentation/screens/wardrobe/wardrobe_detail_screen.dart';
import 'package:koutu/presentation/screens/wardrobe/wardrobe_list_screen.dart';

// Presentation layer - Widgets
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/presentation/widgets/animations/app_animated_list_item.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/buttons/app_button.dart';
import 'package:koutu/presentation/widgets/common/app_badge.dart';
import 'package:koutu/presentation/widgets/dialogs/app_dialog.dart';
import 'package:koutu/presentation/widgets/error/app_error_widget.dart';
import 'package:koutu/presentation/widgets/forms/app_checkbox_field.dart';
import 'package:koutu/presentation/widgets/forms/app_dropdown_field.dart';
import 'package:koutu/presentation/widgets/forms/app_text_field.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/loading/app_skeleton_loader.dart';

// Services
import 'package:koutu/services/image/background_removal_service.dart';
import 'package:koutu/services/image/color_extraction_service.dart';
import 'package:koutu/services/image/image_compression_service.dart';
import 'package:koutu/services/image/image_manager.dart';
import 'package:koutu/services/image/image_processing_service.dart';
import 'package:koutu/services/image/image_upload_service.dart';
import 'package:koutu/services/storage/cache_service.dart';
import 'package:koutu/services/storage/secure_storage_service.dart';

// Theme
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_theme.dart';

// Router
import 'package:koutu/presentation/router/app_router.dart';
import 'package:koutu/presentation/router/route_paths.dart';

// Injection
import 'package:koutu/injection/injection.dart';
import 'package:koutu/injection/modules/app_module.dart';
import 'package:koutu/injection/modules/database_module.dart';
import 'package:koutu/injection/modules/network_module.dart';
import 'package:koutu/injection/modules/repository_module.dart';

// Environment
import 'package:koutu/env/env.dart';

void main() {
  // This file exists solely to ensure code coverage includes all source files
  // It is not meant to be run
}