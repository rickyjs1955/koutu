import 'dart:io';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:injectable/injectable.dart';
import 'package:koutu/domain/repositories/i_garment_repository.dart';
import 'package:koutu/domain/repositories/i_image_repository.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/image/image_model.dart';
import 'package:koutu/core/error/failures.dart';
import 'package:koutu/presentation/bloc/garment/garment_event.dart';
import 'package:koutu/presentation/bloc/garment/garment_state.dart';

@injectable
class GarmentBloc extends Bloc<GarmentEvent, GarmentState> {
  final IGarmentRepository _garmentRepository;
  final IImageRepository _imageRepository;

  GarmentBloc(
    this._garmentRepository,
    this._imageRepository,
  ) : super(const GarmentState.initial()) {
    on<LoadGarments>(_onLoadGarments);
    on<LoadGarmentsByWardrobe>(_onLoadGarmentsByWardrobe);
    on<LoadGarmentDetail>(_onLoadGarmentDetail);
    on<CreateGarment>(_onCreateGarment);
    on<UpdateGarment>(_onUpdateGarment);
    on<DeleteGarment>(_onDeleteGarment);
    on<FilterGarments>(_onFilterGarments);
    on<SearchGarments>(_onSearchGarments);
    on<RecordWear>(_onRecordWear);
    on<ToggleFavorite>(_onToggleFavorite);
    on<BulkDeleteGarments>(_onBulkDeleteGarments);
    on<BulkUpdateGarments>(_onBulkUpdateGarments);
    on<MoveGarmentToWardrobe>(_onMoveGarmentToWardrobe);
    on<DuplicateGarment>(_onDuplicateGarment);
    on<SortGarments>(_onSortGarments);
    on<ArchiveGarment>(_onArchiveGarment);
    on<UnarchiveGarment>(_onUnarchiveGarment);
    on<ExportGarments>(_onExportGarments);
    on<ImportGarments>(_onImportGarments);
    on<SyncGarments>(_onSyncGarments);
    on<RefreshGarments>(_onRefreshGarments);
    on<ClearCache>(_onClearCache);
    on<ClearError>(_onClearError);
    on<Retry>(_onRetry);
    on<SelectGarment>(_onSelectGarment);
    on<DeselectGarment>(_onDeselectGarment);
    on<EnableSelectionMode>(_onEnableSelectionMode);
    on<DisableSelectionMode>(_onDisableSelectionMode);
    on<ToggleGarmentSelection>(_onToggleGarmentSelection);
    on<SelectAllGarments>(_onSelectAllGarments);
    on<DeselectAllGarments>(_onDeselectAllGarments);
  }

  Future<void> _onLoadGarments(
    LoadGarments event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final result = await _garmentRepository.getGarments();

    result.fold(
      (failure) => emit(GarmentState.error(
        _mapFailureToMessage(failure),
        state.garments,
      )),
      (garments) => emit(GarmentState.loaded(garments)),
    );
  }

  Future<void> _onLoadGarmentsByWardrobe(
    LoadGarmentsByWardrobe event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final result = await _garmentRepository.getGarmentsByWardrobe(event.wardrobeId);

    result.fold(
      (failure) => emit(GarmentState.error(
        _mapFailureToMessage(failure),
        state.garments,
      )),
      (garments) => emit(GarmentState.loaded(garments)),
    );
  }

  Future<void> _onLoadGarmentDetail(
    LoadGarmentDetail event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final result = await _garmentRepository.getGarment(event.garmentId);

    result.fold(
      (failure) => emit(GarmentState.error(
        _mapFailureToMessage(failure),
        state.garments,
      )),
      (garment) => emit(GarmentState.success(
        state.garments,
        selectedGarment: garment,
      )),
    );
  }

  Future<void> _onCreateGarment(
    CreateGarment event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    try {
      // Upload images
      final uploadedImages = <ImageModel>[];
      for (final imageFile in event.imageFiles) {
        final result = await _imageRepository.uploadImage(imageFile);
        result.fold(
          (failure) => throw failure,
          (url) {
            uploadedImages.add(ImageModel(
              id: DateTime.now().millisecondsSinceEpoch.toString(),
              url: url,
              thumbnailUrl: url, // TODO: Generate actual thumbnail
              width: 800,
              height: 1200,
              createdAt: DateTime.now(),
            ));
          },
        );
      }

      // Create garment
      final garment = GarmentModel(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        wardrobeId: event.wardrobeId,
        name: event.name,
        category: event.category,
        subcategory: event.subcategory,
        brand: event.brand,
        colors: event.colors,
        size: event.size,
        material: event.material,
        price: event.price,
        purchaseDate: event.purchaseDate,
        tags: event.tags,
        notes: event.notes,
        images: uploadedImages,
        isFavorite: false,
        wearCount: 0,
        lastWornDate: null,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final result = await _garmentRepository.createGarment(garment);

      result.fold(
        (failure) => emit(GarmentState.error(
          _mapFailureToMessage(failure),
          state.garments,
        )),
        (createdGarment) {
          final updatedGarments = [...state.garments, createdGarment];
          emit(GarmentState.success(updatedGarments));
        },
      );
    } catch (e) {
      emit(GarmentState.error(
        'Failed to create garment: ${e.toString()}',
        state.garments,
      ));
    }
  }

  Future<void> _onUpdateGarment(
    UpdateGarment event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final result = await _garmentRepository.updateGarment(event.garment);

    result.fold(
      (failure) => emit(GarmentState.error(
        _mapFailureToMessage(failure),
        state.garments,
      )),
      (updatedGarment) {
        final updatedGarments = state.garments.map((g) {
          return g.id == updatedGarment.id ? updatedGarment : g;
        }).toList();
        emit(GarmentState.success(updatedGarments));
      },
    );
  }

  Future<void> _onDeleteGarment(
    DeleteGarment event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final result = await _garmentRepository.deleteGarment(event.garmentId);

    result.fold(
      (failure) => emit(GarmentState.error(
        _mapFailureToMessage(failure),
        state.garments,
      )),
      (_) {
        final updatedGarments = state.garments
            .where((g) => g.id != event.garmentId)
            .toList();
        emit(GarmentState.success(updatedGarments));
      },
    );
  }

  Future<void> _onFilterGarments(
    FilterGarments event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final filtered = state.garments.where((garment) {
      bool matches = true;

      if (event.category != null && event.category != 'all') {
        matches = matches && garment.category == event.category;
      }

      if (event.brand != null) {
        matches = matches && garment.brand == event.brand;
      }

      if (event.color != null) {
        matches = matches && garment.colors.contains(event.color);
      }

      if (event.size != null) {
        matches = matches && garment.size == event.size;
      }

      if (event.tags.isNotEmpty) {
        matches = matches && event.tags.any((tag) => garment.tags.contains(tag));
      }

      return matches;
    }).toList();

    emit(GarmentState.filtered(state.garments, filtered));
  }

  Future<void> _onSearchGarments(
    SearchGarments event,
    Emitter<GarmentState> emit,
  ) async {
    emit(GarmentState.loading(state.garments));

    final query = event.query.toLowerCase();
    final searched = state.garments.where((garment) {
      return garment.name.toLowerCase().contains(query) ||
          (garment.brand?.toLowerCase().contains(query) ?? false) ||
          garment.tags.any((tag) => tag.toLowerCase().contains(query)) ||
          garment.category.toLowerCase().contains(query) ||
          (garment.notes?.toLowerCase().contains(query) ?? false);
    }).toList();

    emit(GarmentState.filtered(state.garments, searched));
  }

  // Add placeholder implementations for new event handlers
  Future<void> _onRecordWear(RecordWear event, Emitter<GarmentState> emit) async {
    // TODO: Implement record wear functionality
    emit(GarmentState.loading(state.garments));
    
    final result = await _garmentRepository.getGarment(event.garmentId);
    result.fold(
      (failure) => emit(GarmentState.error(_mapFailureToMessage(failure), state.garments)),
      (garment) {
        final updatedGarment = garment.copyWith(
          wearCount: garment.wearCount + 1,
          lastWornDate: DateTime.now(),
        );
        final result = _garmentRepository.updateGarment(updatedGarment);
        // Handle result...
        emit(GarmentState.wearRecorded(state.garments, event.garmentId));
      },
    );
  }
  
  Future<void> _onToggleFavorite(ToggleFavorite event, Emitter<GarmentState> emit) async {
    // TODO: Implement toggle favorite functionality
    emit(GarmentState.loading(state.garments));
    
    final result = await _garmentRepository.getGarment(event.garmentId);
    result.fold(
      (failure) => emit(GarmentState.error(_mapFailureToMessage(failure), state.garments)),
      (garment) {
        final updatedGarment = garment.copyWith(isFavorite: !garment.isFavorite);
        final result = _garmentRepository.updateGarment(updatedGarment);
        // Handle result...
        emit(GarmentState.favoriteToggled(state.garments, event.garmentId, !garment.isFavorite));
      },
    );
  }
  
  Future<void> _onBulkDeleteGarments(BulkDeleteGarments event, Emitter<GarmentState> emit) async {
    // TODO: Implement bulk delete functionality
    emit(GarmentState.loading(state.garments));
    // Implementation placeholder
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onBulkUpdateGarments(BulkUpdateGarments event, Emitter<GarmentState> emit) async {
    // TODO: Implement bulk update functionality
    emit(GarmentState.loading(state.garments));
    // Implementation placeholder
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onMoveGarmentToWardrobe(MoveGarmentToWardrobe event, Emitter<GarmentState> emit) async {
    // TODO: Implement move garment functionality
    emit(GarmentState.loading(state.garments));
    // Implementation placeholder
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onDuplicateGarment(DuplicateGarment event, Emitter<GarmentState> emit) async {
    // TODO: Implement duplicate garment functionality
    emit(GarmentState.loading(state.garments));
    // Implementation placeholder
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onSortGarments(SortGarments event, Emitter<GarmentState> emit) async {
    emit(GarmentState.sorting(state.garments, event.sortBy, event.ascending));
    
    final sorted = List<GarmentModel>.from(state.garments);
    sorted.sort((a, b) {
      int comparison = 0;
      switch (event.sortBy) {
        case 'name':
          comparison = a.name.compareTo(b.name);
          break;
        case 'category':
          comparison = a.category.compareTo(b.category);
          break;
        case 'brand':
          comparison = (a.brand ?? '').compareTo(b.brand ?? '');
          break;
        case 'wearCount':
          comparison = a.wearCount.compareTo(b.wearCount);
          break;
        case 'lastWorn':
          comparison = (a.lastWornDate ?? DateTime(1970)).compareTo(b.lastWornDate ?? DateTime(1970));
          break;
        default:
          comparison = a.name.compareTo(b.name);
      }
      return event.ascending ? comparison : -comparison;
    });
    
    emit(GarmentState.sorted(sorted, event.sortBy, event.ascending));
  }
  
  Future<void> _onArchiveGarment(ArchiveGarment event, Emitter<GarmentState> emit) async {
    // TODO: Implement archive functionality
    emit(GarmentState.loading(state.garments));
    emit(GarmentState.archived(state.garments));
  }
  
  Future<void> _onUnarchiveGarment(UnarchiveGarment event, Emitter<GarmentState> emit) async {
    // TODO: Implement unarchive functionality
    emit(GarmentState.loading(state.garments));
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onExportGarments(ExportGarments event, Emitter<GarmentState> emit) async {
    // TODO: Implement export functionality
    emit(GarmentState.loading(state.garments));
    emit(GarmentState.exported(state.garments, '/path/to/export.json'));
  }
  
  Future<void> _onImportGarments(ImportGarments event, Emitter<GarmentState> emit) async {
    // TODO: Implement import functionality
    emit(GarmentState.loading(state.garments));
    emit(GarmentState.imported(state.garments, 5));
  }
  
  Future<void> _onSyncGarments(SyncGarments event, Emitter<GarmentState> emit) async {
    emit(GarmentState.syncing(state.garments));
    // TODO: Implement sync functionality
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onRefreshGarments(RefreshGarments event, Emitter<GarmentState> emit) async {
    emit(GarmentState.loading(state.garments));
    add(LoadGarments());
  }
  
  Future<void> _onClearCache(ClearCache event, Emitter<GarmentState> emit) async {
    // TODO: Implement clear cache functionality
    emit(GarmentState.success([]));
  }
  
  Future<void> _onClearError(ClearError event, Emitter<GarmentState> emit) async {
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onRetry(Retry event, Emitter<GarmentState> emit) async {
    add(LoadGarments());
  }
  
  Future<void> _onSelectGarment(SelectGarment event, Emitter<GarmentState> emit) async {
    final result = await _garmentRepository.getGarment(event.garmentId);
    result.fold(
      (failure) => emit(GarmentState.error(_mapFailureToMessage(failure), state.garments)),
      (garment) => emit(GarmentState.success(state.garments, selectedGarment: garment)),
    );
  }
  
  Future<void> _onDeselectGarment(DeselectGarment event, Emitter<GarmentState> emit) async {
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onEnableSelectionMode(EnableSelectionMode event, Emitter<GarmentState> emit) async {
    emit(GarmentState.selectionMode(state.garments, []));
  }
  
  Future<void> _onDisableSelectionMode(DisableSelectionMode event, Emitter<GarmentState> emit) async {
    emit(GarmentState.success(state.garments));
  }
  
  Future<void> _onToggleGarmentSelection(ToggleGarmentSelection event, Emitter<GarmentState> emit) async {
    final currentState = state;
    if (currentState is GarmentSelectionMode) {
      final selectedIds = List<String>.from(currentState.selectedIds);
      if (selectedIds.contains(event.garmentId)) {
        selectedIds.remove(event.garmentId);
      } else {
        selectedIds.add(event.garmentId);
      }
      emit(GarmentState.selectionMode(currentState.garments, selectedIds));
    }
  }
  
  Future<void> _onSelectAllGarments(SelectAllGarments event, Emitter<GarmentState> emit) async {
    final allIds = state.garments.map((g) => g.id).toList();
    emit(GarmentState.selectionMode(state.garments, allIds));
  }
  
  Future<void> _onDeselectAllGarments(DeselectAllGarments event, Emitter<GarmentState> emit) async {
    emit(GarmentState.selectionMode(state.garments, []));
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