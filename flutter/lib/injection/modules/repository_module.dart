import 'package:injectable/injectable.dart';
import 'package:koutu/data/repositories/auth_repository.dart';
import 'package:koutu/data/repositories/garment_repository.dart';
import 'package:koutu/data/repositories/image_repository.dart';
import 'package:koutu/data/repositories/wardrobe_repository.dart';
import 'package:koutu/domain/repositories/i_auth_repository.dart';
import 'package:koutu/domain/repositories/i_garment_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/domain/repositories/i_wardrobe_repository.dart';

/// Module for registering repository dependencies
@module
abstract class RepositoryModule {
  /// Auth repository
  @LazySingleton(as: IAuthRepository)
  AuthRepository get authRepository;

  /// Wardrobe repository
  @LazySingleton(as: IWardrobeRepository)
  WardrobeRepository get wardrobeRepository;

  /// Garment repository
  @LazySingleton(as: IGarmentRepository)
  GarmentRepository get garmentRepository;

  /// Image repository
  @LazySingleton(as: IImageRepository)
  ImageRepository get imageRepository;
}