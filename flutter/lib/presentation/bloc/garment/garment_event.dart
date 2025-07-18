import 'dart:io';
import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

part 'garment_event.freezed.dart';

@freezed
class GarmentEvent with _$GarmentEvent {
  const factory GarmentEvent.loadGarments() = LoadGarments;
  
  const factory GarmentEvent.loadGarmentsByWardrobe(String wardrobeId) = LoadGarmentsByWardrobe;
  
  const factory GarmentEvent.loadGarmentDetail(String garmentId) = LoadGarmentDetail;
  
  const factory GarmentEvent.createGarment({
    required String wardrobeId,
    required String name,
    required String category,
    String? subcategory,
    String? brand,
    required List<String> colors,
    String? size,
    String? material,
    double? price,
    DateTime? purchaseDate,
    required List<String> tags,
    String? notes,
    required List<File> imageFiles,
  }) = CreateGarment;
  
  const factory GarmentEvent.updateGarment(GarmentModel garment) = UpdateGarment;
  
  const factory GarmentEvent.deleteGarment(String garmentId) = DeleteGarment;
  
  const factory GarmentEvent.filterGarments({
    String? category,
    String? brand,
    String? color,
    String? size,
    @Default([]) List<String> tags,
  }) = FilterGarments;
  
  const factory GarmentEvent.searchGarments(String query) = SearchGarments;
  
  const factory GarmentEvent.recordWear(String garmentId) = RecordWear;
  
  const factory GarmentEvent.toggleFavorite(String garmentId) = ToggleFavorite;
  
  const factory GarmentEvent.bulkDeleteGarments(List<String> garmentIds) = BulkDeleteGarments;
  
  const factory GarmentEvent.bulkUpdateGarments({
    required List<String> garmentIds,
    required Map<String, dynamic> updates,
  }) = BulkUpdateGarments;
  
  const factory GarmentEvent.moveGarmentToWardrobe({
    required String garmentId,
    required String wardrobeId,
  }) = MoveGarmentToWardrobe;
  
  const factory GarmentEvent.duplicateGarment(String garmentId) = DuplicateGarment;
  
  const factory GarmentEvent.sortGarments({
    required String sortBy,
    required bool ascending,
  }) = SortGarments;
  
  const factory GarmentEvent.loadGarmentsByCategory({
    required String wardrobeId,
    required String category,
  }) = LoadGarmentsByCategory;
  
  const factory GarmentEvent.loadGarmentsByTag({
    required String wardrobeId,
    required String tag,
  }) = LoadGarmentsByTag;
  
  const factory GarmentEvent.loadGarmentsByColor({
    required String wardrobeId,
    required String color,
  }) = LoadGarmentsByColor;
  
  const factory GarmentEvent.loadGarmentsByBrand({
    required String wardrobeId,
    required String brand,
  }) = LoadGarmentsByBrand;
  
  const factory GarmentEvent.loadGarmentStats(String garmentId) = LoadGarmentStats;
  
  const factory GarmentEvent.loadWearHistory(String garmentId) = LoadWearHistory;
  
  const factory GarmentEvent.loadSimilarGarments(String garmentId) = LoadSimilarGarments;
  
  const factory GarmentEvent.archiveGarment(String garmentId) = ArchiveGarment;
  
  const factory GarmentEvent.unarchiveGarment(String garmentId) = UnarchiveGarment;
  
  const factory GarmentEvent.exportGarments(List<String> garmentIds) = ExportGarments;
  
  const factory GarmentEvent.importGarments({
    required String wardrobeId,
    required File file,
  }) = ImportGarments;
  
  const factory GarmentEvent.syncGarments() = SyncGarments;
  
  const factory GarmentEvent.refreshGarments() = RefreshGarments;
  
  const factory GarmentEvent.clearCache() = ClearCache;
  
  const factory GarmentEvent.clearError() = ClearError;
  
  const factory GarmentEvent.retry() = Retry;
  
  const factory GarmentEvent.selectGarment(String garmentId) = SelectGarment;
  
  const factory GarmentEvent.deselectGarment() = DeselectGarment;
  
  const factory GarmentEvent.enableSelectionMode() = EnableSelectionMode;
  
  const factory GarmentEvent.disableSelectionMode() = DisableSelectionMode;
  
  const factory GarmentEvent.toggleGarmentSelection(String garmentId) = ToggleGarmentSelection;
  
  const factory GarmentEvent.selectAllGarments() = SelectAllGarments;
  
  const factory GarmentEvent.deselectAllGarments() = DeselectAllGarments;
}