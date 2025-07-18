import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

part 'garment_state.freezed.dart';

@freezed
class GarmentState with _$GarmentState {
  const GarmentState._();

  const factory GarmentState.initial() = _Initial;
  
  const factory GarmentState.loading(List<GarmentModel> garments) = GarmentLoading;
  
  const factory GarmentState.loaded(List<GarmentModel> garments) = GarmentLoaded;
  
  const factory GarmentState.filtered(
    List<GarmentModel> allGarments,
    List<GarmentModel> filteredGarments,
  ) = GarmentFiltered;
  
  const factory GarmentState.success(
    List<GarmentModel> garments, {
    GarmentModel? selectedGarment,
    Map<String, dynamic>? statistics,
    List<Map<String, dynamic>>? wearHistory,
    List<GarmentModel>? similarGarments,
    String? exportPath,
    int? importedCount,
  }) = GarmentSuccess;
  
  const factory GarmentState.error(
    String message,
    List<GarmentModel> garments,
  ) = GarmentError;
  
  const factory GarmentState.searching(
    List<GarmentModel> garments,
    String query,
  ) = GarmentSearching;
  
  const factory GarmentState.sorting(
    List<GarmentModel> garments,
    String sortBy,
    bool ascending,
  ) = GarmentSorting;
  
  const factory GarmentState.sorted(
    List<GarmentModel> garments,
    String sortBy,
    bool ascending,
  ) = GarmentSorted;
  
  const factory GarmentState.selectionMode(
    List<GarmentModel> garments,
    List<String> selectedIds,
  ) = GarmentSelectionMode;
  
  const factory GarmentState.syncing(
    List<GarmentModel> garments,
  ) = GarmentSyncing;
  
  const factory GarmentState.offline(
    List<GarmentModel> garments,
  ) = GarmentOffline;
  
  const factory GarmentState.archived(
    List<GarmentModel> garments,
  ) = GarmentArchived;
  
  const factory GarmentState.exported(
    List<GarmentModel> garments,
    String filePath,
  ) = GarmentExported;
  
  const factory GarmentState.imported(
    List<GarmentModel> garments,
    int importedCount,
  ) = GarmentImported;
  
  const factory GarmentState.wearRecorded(
    List<GarmentModel> garments,
    String garmentId,
  ) = GarmentWearRecorded;
  
  const factory GarmentState.favoriteToggled(
    List<GarmentModel> garments,
    String garmentId,
    bool isFavorite,
  ) = GarmentFavoriteToggled;

  // Helper getters
  List<GarmentModel> get garments => map(
    initial: (_) => [],
    loading: (state) => state.garments,
    loaded: (state) => state.garments,
    filtered: (state) => state.filteredGarments,
    success: (state) => state.garments,
    error: (state) => state.garments,
    searching: (state) => state.garments,
    sorting: (state) => state.garments,
    sorted: (state) => state.garments,
    selectionMode: (state) => state.garments,
    syncing: (state) => state.garments,
    offline: (state) => state.garments,
    archived: (state) => state.garments,
    exported: (state) => state.garments,
    imported: (state) => state.garments,
    wearRecorded: (state) => state.garments,
    favoriteToggled: (state) => state.garments,
  );

  GarmentModel? get selectedGarment => maybeMap(
    success: (state) => state.selectedGarment,
    orElse: () => null,
  );
  
  Map<String, dynamic>? get statistics => maybeMap(
    success: (state) => state.statistics,
    orElse: () => null,
  );
  
  List<Map<String, dynamic>>? get wearHistory => maybeMap(
    success: (state) => state.wearHistory,
    orElse: () => null,
  );
  
  List<GarmentModel>? get similarGarments => maybeMap(
    success: (state) => state.similarGarments,
    orElse: () => null,
  );
  
  String? get exportPath => maybeMap(
    success: (state) => state.exportPath,
    exported: (state) => state.filePath,
    orElse: () => null,
  );
  
  int? get importedCount => maybeMap(
    success: (state) => state.importedCount,
    imported: (state) => state.importedCount,
    orElse: () => null,
  );
  
  List<String> get selectedIds => maybeMap(
    selectionMode: (state) => state.selectedIds,
    orElse: () => [],
  );
  
  bool get isSelectionMode => maybeMap(
    selectionMode: (_) => true,
    orElse: () => false,
  );
  
  bool get isLoading => maybeMap(
    loading: (_) => true,
    syncing: (_) => true,
    sorting: (_) => true,
    orElse: () => false,
  );
  
  bool get isError => maybeMap(
    error: (_) => true,
    orElse: () => false,
  );
  
  bool get isOffline => maybeMap(
    offline: (_) => true,
    orElse: () => false,
  );
  
  String? get errorMessage => maybeMap(
    error: (state) => state.message,
    orElse: () => null,
  );
  
  bool get hasGarments => garments.isNotEmpty;
  
  List<GarmentModel> get favoriteGarments => garments.where((g) => g.isFavorite).toList();
  
  List<GarmentModel> get recentlyWornGarments => garments
      .where((g) => g.lastWornDate != null)
      .toList()
      ..sort((a, b) => b.lastWornDate!.compareTo(a.lastWornDate!));
  
  List<GarmentModel> get mostWornGarments => garments
      .where((g) => g.wearCount > 0)
      .toList()
      ..sort((a, b) => b.wearCount.compareTo(a.wearCount));
  
  List<GarmentModel> get leastWornGarments => garments
      .where((g) => g.wearCount == 0)
      .toList();
  
  Map<String, int> get categoryCount {
    final Map<String, int> counts = {};
    for (final garment in garments) {
      counts[garment.category] = (counts[garment.category] ?? 0) + 1;
    }
    return counts;
  }
  
  Map<String, int> get colorCount {
    final Map<String, int> counts = {};
    for (final garment in garments) {
      for (final color in garment.colors) {
        counts[color] = (counts[color] ?? 0) + 1;
      }
    }
    return counts;
  }
  
  Map<String, int> get brandCount {
    final Map<String, int> counts = {};
    for (final garment in garments) {
      if (garment.brand != null) {
        counts[garment.brand!] = (counts[garment.brand!] ?? 0) + 1;
      }
    }
    return counts;
  }
  
  double get totalValue => garments.fold(0.0, (sum, garment) => sum + (garment.price ?? 0.0));
  
  double get averageWearCount => garments.isEmpty
      ? 0.0
      : garments.fold(0, (sum, garment) => sum + garment.wearCount) / garments.length;
  
  int get totalWears => garments.fold(0, (sum, garment) => sum + garment.wearCount);
  
  List<String> get allTags {
    final Set<String> tags = {};
    for (final garment in garments) {
      tags.addAll(garment.tags);
    }
    return tags.toList()..sort();
  }
  
  List<String> get allBrands {
    final Set<String> brands = {};
    for (final garment in garments) {
      if (garment.brand != null) {
        brands.add(garment.brand!);
      }
    }
    return brands.toList()..sort();
  }
  
  List<String> get allColors {
    final Set<String> colors = {};
    for (final garment in garments) {
      colors.addAll(garment.colors);
    }
    return colors.toList()..sort();
  }
  
  List<String> get allSizes {
    final Set<String> sizes = {};
    for (final garment in garments) {
      if (garment.size != null) {
        sizes.add(garment.size!);
      }
    }
    return sizes.toList()..sort();
  }
}