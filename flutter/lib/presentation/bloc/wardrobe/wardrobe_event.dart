import 'dart:io';
import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/wardrobe/wardrobe_model.dart';

part 'wardrobe_event.freezed.dart';

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
    String? role,
  }) = InviteUserToWardrobe;
  
  const factory WardrobeEvent.removeUserFromWardrobe({
    required String wardrobeId,
    required String email,
  }) = RemoveUserFromWardrobe;
  
  const factory WardrobeEvent.loadSharedUsers(String wardrobeId) = LoadSharedUsers;
  
  const factory WardrobeEvent.acceptInvitation(String invitationId) = AcceptInvitation;
  
  const factory WardrobeEvent.rejectInvitation(String invitationId) = RejectInvitation;
  
  const factory WardrobeEvent.searchWardrobes(String query) = SearchWardrobes;
  
  const factory WardrobeEvent.filterWardrobes({
    String? colorTheme,
    bool? isShared,
    bool? isDefault,
  }) = FilterWardrobes;
  
  const factory WardrobeEvent.sortWardrobes({
    required String sortBy,
    required bool ascending,
  }) = SortWardrobes;
  
  const factory WardrobeEvent.bulkDeleteWardrobes(List<String> wardrobeIds) = BulkDeleteWardrobes;
  
  const factory WardrobeEvent.duplicateWardrobe(String wardrobeId) = DuplicateWardrobe;
  
  const factory WardrobeEvent.archiveWardrobe(String wardrobeId) = ArchiveWardrobe;
  
  const factory WardrobeEvent.unarchiveWardrobe(String wardrobeId) = UnarchiveWardrobe;
  
  const factory WardrobeEvent.exportWardrobe(String wardrobeId) = ExportWardrobe;
  
  const factory WardrobeEvent.importWardrobe(File file) = ImportWardrobe;
  
  const factory WardrobeEvent.syncWardrobes() = SyncWardrobes;
  
  const factory WardrobeEvent.clearCache() = ClearCache;
  
  const factory WardrobeEvent.refreshWardrobes() = RefreshWardrobes;
  
  const factory WardrobeEvent.loadWardrobeStatistics(String wardrobeId) = LoadWardrobeStatistics;
  
  const factory WardrobeEvent.clearError() = ClearError;
  
  const factory WardrobeEvent.retry() = Retry;
}