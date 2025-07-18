import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';

part 'wardrobe_state.freezed.dart';

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
    Map<String, dynamic>? statistics,
    String? exportPath,
  }) = WardrobeSuccess;
  
  const factory WardrobeState.error(
    String message,
    List<WardrobeModel> wardrobes,
  ) = WardrobeError;
  
  const factory WardrobeState.searching(
    List<WardrobeModel> wardrobes,
    String query,
  ) = WardrobeSearching;
  
  const factory WardrobeState.filtered(
    List<WardrobeModel> wardrobes,
    Map<String, dynamic> filters,
  ) = WardrobeFiltered;
  
  const factory WardrobeState.sorted(
    List<WardrobeModel> wardrobes,
    String sortBy,
    bool ascending,
  ) = WardrobeSorted;
  
  const factory WardrobeState.syncing(
    List<WardrobeModel> wardrobes,
  ) = WardrobeSyncing;
  
  const factory WardrobeState.offline(
    List<WardrobeModel> wardrobes,
  ) = WardrobeOffline;
  
  const factory WardrobeState.invitationSent(
    List<WardrobeModel> wardrobes,
    String email,
  ) = WardrobeInvitationSent;
  
  const factory WardrobeState.archived(
    List<WardrobeModel> wardrobes,
  ) = WardrobeArchived;
  
  const factory WardrobeState.exported(
    List<WardrobeModel> wardrobes,
    String filePath,
  ) = WardrobeExported;
  
  const factory WardrobeState.imported(
    List<WardrobeModel> wardrobes,
    int importedCount,
  ) = WardrobeImported;

  // Helper getters
  List<WardrobeModel> get wardrobes => map(
    initial: (_) => [],
    loading: (state) => state.wardrobes,
    loaded: (state) => state.wardrobes,
    success: (state) => state.wardrobes,
    error: (state) => state.wardrobes,
    searching: (state) => state.wardrobes,
    filtered: (state) => state.wardrobes,
    sorted: (state) => state.wardrobes,
    syncing: (state) => state.wardrobes,
    offline: (state) => state.wardrobes,
    invitationSent: (state) => state.wardrobes,
    archived: (state) => state.wardrobes,
    exported: (state) => state.wardrobes,
    imported: (state) => state.wardrobes,
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
  
  Map<String, dynamic>? get statistics => maybeMap(
    success: (state) => state.statistics,
    orElse: () => null,
  );
  
  String? get exportPath => maybeMap(
    success: (state) => state.exportPath,
    exported: (state) => state.filePath,
    orElse: () => null,
  );
  
  bool get isLoading => maybeMap(
    loading: (_) => true,
    syncing: (_) => true,
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
  
  bool get hasWardrobes => wardrobes.isNotEmpty;
  
  WardrobeModel? get defaultWardrobe => wardrobes.firstWhere(
    (w) => w.isDefault,
    orElse: () => wardrobes.isNotEmpty ? wardrobes.first : null,
  );
  
  int get totalGarments => wardrobes.fold<int>(
    0,
    (sum, wardrobe) => sum + wardrobe.garmentIds.length,
  );
  
  List<WardrobeModel> get sharedWardrobes => wardrobes.where((w) => w.isShared).toList();
  
  List<WardrobeModel> get personalWardrobes => wardrobes.where((w) => !w.isShared).toList();
}