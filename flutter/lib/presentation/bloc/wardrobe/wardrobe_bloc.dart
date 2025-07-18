import 'dart:io';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/domain/repositories/i_wardrobe_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';
import 'package:koutu/core/error/failures.dart';

part 'wardrobe_bloc.freezed.dart';

@injectable
class WardrobeBloc extends Bloc<WardrobeEvent, WardrobeState> {
  final IWardrobeRepository _wardrobeRepository;
  final IImageRepository _imageRepository;

  WardrobeBloc(
    this._wardrobeRepository,
    this._imageRepository,
  ) : super(const WardrobeState.initial()) {
    on<LoadWardrobes>(_onLoadWardrobes);
    on<LoadWardrobeDetail>(_onLoadWardrobeDetail);
    on<CreateWardrobe>(_onCreateWardrobe);
    on<UpdateWardrobe>(_onUpdateWardrobe);
    on<DeleteWardrobe>(_onDeleteWardrobe);
    on<SetDefaultWardrobe>(_onSetDefaultWardrobe);
    on<GenerateShareLink>(_onGenerateShareLink);
    on<InviteUserToWardrobe>(_onInviteUserToWardrobe);
    on<RemoveUserFromWardrobe>(_onRemoveUserFromWardrobe);
    on<LoadSharedUsers>(_onLoadSharedUsers);
  }

  Future<void> _onLoadWardrobes(
    LoadWardrobes event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    final result = await _wardrobeRepository.getWardrobes();

    result.fold(
      (failure) => emit(WardrobeState.error(
        _mapFailureToMessage(failure),
        state.wardrobes,
      )),
      (wardrobes) => emit(WardrobeState.loaded(wardrobes)),
    );
  }

  Future<void> _onLoadWardrobeDetail(
    LoadWardrobeDetail event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    final result = await _wardrobeRepository.getWardrobe(event.wardrobeId);

    result.fold(
      (failure) => emit(WardrobeState.error(
        _mapFailureToMessage(failure),
        state.wardrobes,
      )),
      (wardrobe) => emit(WardrobeState.success(
        state.wardrobes,
        selectedWardrobe: wardrobe,
      )),
    );
  }

  Future<void> _onCreateWardrobe(
    CreateWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    try {
      String? imageUrl;
      
      // Upload image if provided
      if (event.imageFile != null) {
        final imageResult = await _imageRepository.uploadImage(event.imageFile!);
        imageResult.fold(
          (failure) => throw failure,
          (url) => imageUrl = url,
        );
      }

      // Create wardrobe
      final wardrobe = WardrobeModel(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        userId: 'current_user_id', // TODO: Get from auth
        name: event.name,
        description: event.description,
        imageUrl: imageUrl,
        colorTheme: event.colorTheme,
        iconName: event.iconName,
        isDefault: event.isDefault,
        isShared: event.isShared,
        garmentIds: [],
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final result = await _wardrobeRepository.createWardrobe(wardrobe);

      result.fold(
        (failure) => emit(WardrobeState.error(
          _mapFailureToMessage(failure),
          state.wardrobes,
        )),
        (createdWardrobe) {
          final updatedWardrobes = [...state.wardrobes, createdWardrobe];
          emit(WardrobeState.success(updatedWardrobes));
        },
      );
    } catch (e) {
      emit(WardrobeState.error(
        'Failed to create wardrobe: ${e.toString()}',
        state.wardrobes,
      ));
    }
  }

  Future<void> _onUpdateWardrobe(
    UpdateWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    final result = await _wardrobeRepository.updateWardrobe(event.wardrobe);

    result.fold(
      (failure) => emit(WardrobeState.error(
        _mapFailureToMessage(failure),
        state.wardrobes,
      )),
      (updatedWardrobe) {
        final updatedWardrobes = state.wardrobes.map((w) {
          return w.id == updatedWardrobe.id ? updatedWardrobe : w;
        }).toList();
        emit(WardrobeState.success(updatedWardrobes));
      },
    );
  }

  Future<void> _onDeleteWardrobe(
    DeleteWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    final result = await _wardrobeRepository.deleteWardrobe(event.wardrobeId);

    result.fold(
      (failure) => emit(WardrobeState.error(
        _mapFailureToMessage(failure),
        state.wardrobes,
      )),
      (_) {
        final updatedWardrobes = state.wardrobes
            .where((w) => w.id != event.wardrobeId)
            .toList();
        emit(WardrobeState.success(updatedWardrobes));
      },
    );
  }

  Future<void> _onSetDefaultWardrobe(
    SetDefaultWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    emit(WardrobeState.loading(state.wardrobes));

    // First, unset all default wardrobes
    final updatedWardrobes = state.wardrobes.map((w) {
      if (w.id == event.wardrobeId) {
        return w.copyWith(isDefault: true);
      } else if (w.isDefault) {
        return w.copyWith(isDefault: false);
      }
      return w;
    }).toList();

    // Update in repository
    for (final wardrobe in updatedWardrobes) {
      if (wardrobe.id == event.wardrobeId || wardrobe.isDefault == false) {
        await _wardrobeRepository.updateWardrobe(wardrobe);
      }
    }

    emit(WardrobeState.success(updatedWardrobes));
  }

  Future<void> _onGenerateShareLink(
    GenerateShareLink event,
    Emitter<WardrobeState> emit,
  ) async {
    // Generate share link logic
    final shareLink = 'https://koutu.app/wardrobe/${event.wardrobeId}';
    
    emit(WardrobeState.success(
      state.wardrobes,
      shareLink: shareLink,
    ));
  }

  Future<void> _onInviteUserToWardrobe(
    InviteUserToWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    // Add user invitation logic
    final currentSharedUsers = state.sharedUsers ?? [];
    final updatedSharedUsers = [...currentSharedUsers, event.email];
    
    emit(WardrobeState.success(
      state.wardrobes,
      sharedUsers: updatedSharedUsers,
    ));
  }

  Future<void> _onRemoveUserFromWardrobe(
    RemoveUserFromWardrobe event,
    Emitter<WardrobeState> emit,
  ) async {
    // Remove user access logic
    final currentSharedUsers = state.sharedUsers ?? [];
    final updatedSharedUsers = currentSharedUsers
        .where((email) => email != event.email)
        .toList();
    
    emit(WardrobeState.success(
      state.wardrobes,
      sharedUsers: updatedSharedUsers,
    ));
  }

  Future<void> _onLoadSharedUsers(
    LoadSharedUsers event,
    Emitter<WardrobeState> emit,
  ) async {
    // Load shared users logic
    // For now, return mock data
    final sharedUsers = ['user1@example.com', 'user2@example.com'];
    
    emit(WardrobeState.success(
      state.wardrobes,
      sharedUsers: sharedUsers,
    ));
  }

  String _mapFailureToMessage(Failure failure) {
    if (failure is ServerFailure) {
      return failure.message ?? 'Server error occurred';
    } else if (failure is CacheFailure) {
      return 'Cache error occurred';
    } else if (failure is NetworkFailure) {
      return 'Network error occurred';
    }
    return 'Unexpected error occurred';
  }
}

// Events
@freezed
class WardrobeEvent with _$WardrobeEvent {
  const factory WardrobeEvent.loadWardrobes() = LoadWardrobes;
  
  const factory WardrobeEvent.loadWardrobeDetail(String wardrobeId) = LoadWardrobeDetail;
  
  const factory WardrobeEvent.createWardrobe({
    required String name,
    String? description,
    File? imageFile,
    String? colorTheme,
    String? iconName,
    required bool isDefault,
    required bool isShared,
  }) = CreateWardrobe;
  
  const factory WardrobeEvent.updateWardrobe(WardrobeModel wardrobe) = UpdateWardrobe;
  
  const factory WardrobeEvent.deleteWardrobe(String wardrobeId) = DeleteWardrobe;
  
  const factory WardrobeEvent.setDefaultWardrobe(String wardrobeId) = SetDefaultWardrobe;
  
  const factory WardrobeEvent.generateShareLink({
    required String wardrobeId,
    required bool isPublic,
  }) = GenerateShareLink;
  
  const factory WardrobeEvent.inviteUserToWardrobe({
    required String wardrobeId,
    required String email,
  }) = InviteUserToWardrobe;
  
  const factory WardrobeEvent.removeUserFromWardrobe({
    required String wardrobeId,
    required String email,
  }) = RemoveUserFromWardrobe;
  
  const factory WardrobeEvent.loadSharedUsers(String wardrobeId) = LoadSharedUsers;
}

// States
@freezed
class WardrobeState with _$WardrobeState {
  const WardrobeState._();

  const factory WardrobeState.initial() = _Initial;
  
  const factory WardrobeState.loading(List<WardrobeModel> wardrobes) = WardrobeLoading;
  
  const factory WardrobeState.loaded(List<WardrobeModel> wardrobes) = WardrobeLoaded;
  
  const factory WardrobeState.success(
    List<WardrobeModel> wardrobes, {
    WardrobeModel? selectedWardrobe,
    String? shareLink,
    List<String>? sharedUsers,
  }) = WardrobeSuccess;
  
  const factory WardrobeState.error(
    String message,
    List<WardrobeModel> wardrobes,
  ) = WardrobeError;

  // Helper getters
  List<WardrobeModel> get wardrobes => map(
    initial: (_) => [],
    loading: (state) => state.wardrobes,
    loaded: (state) => state.wardrobes,
    success: (state) => state.wardrobes,
    error: (state) => state.wardrobes,
  );

  WardrobeModel? get selectedWardrobe => maybeMap(
    success: (state) => state.selectedWardrobe,
    orElse: () => null,
  );

  String? get shareLink => maybeMap(
    success: (state) => state.shareLink,
    orElse: () => null,
  );

  List<String>? get sharedUsers => maybeMap(
    success: (state) => state.sharedUsers,
    orElse: () => null,
  );
}