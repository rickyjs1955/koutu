import 'package:drift/drift.dart';
import 'package:koutu/data/local/database/app_database.dart';
import 'package:koutu/data/local/database/tables/users_table.dart';
import 'package:koutu/data/models/user/user_model.dart';

part 'user_dao.g.dart';

@DriftAccessor(tables: [Users])
class UserDao extends DatabaseAccessor<AppDatabase> with _$UserDaoMixin {
  UserDao(AppDatabase db) : super(db);

  /// Get current user
  Future<User?> getCurrentUser() async {
    return await (select(users)..limit(1)).getSingleOrNull();
  }

  /// Get user by ID
  Future<User?> getUserById(String id) async {
    return await (select(users)..where((u) => u.id.equals(id))).getSingleOrNull();
  }

  /// Insert or update user
  Future<void> upsertUser(UserModel userModel) async {
    await into(users).insertOnConflictUpdate(
      User(
        id: userModel.id,
        email: userModel.email,
        username: userModel.username,
        firstName: userModel.firstName,
        lastName: userModel.lastName,
        profilePictureUrl: userModel.profilePictureUrl,
        isEmailVerified: userModel.isEmailVerified,
        wardrobeIds: userModel.wardrobeIds,
        createdAt: userModel.createdAt,
        updatedAt: userModel.updatedAt,
        lastLoginAt: userModel.lastLoginAt,
        lastSyncedAt: DateTime.now(),
      ),
    );
  }

  /// Update last login time
  Future<void> updateLastLogin(String userId) async {
    await (update(users)..where((u) => u.id.equals(userId))).write(
      UsersCompanion(
        lastLoginAt: Value(DateTime.now()),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Update profile picture
  Future<void> updateProfilePicture(String userId, String? profilePictureUrl) async {
    await (update(users)..where((u) => u.id.equals(userId))).write(
      UsersCompanion(
        profilePictureUrl: Value(profilePictureUrl),
        updatedAt: Value(DateTime.now()),
      ),
    );
  }

  /// Add wardrobe to user
  Future<void> addWardrobeToUser(String userId, String wardrobeId) async {
    final user = await getUserById(userId);
    if (user != null) {
      final wardrobeIds = List<String>.from(user.wardrobeIds);
      if (!wardrobeIds.contains(wardrobeId)) {
        wardrobeIds.add(wardrobeId);
        await (update(users)..where((u) => u.id.equals(userId))).write(
          UsersCompanion(
            wardrobeIds: Value(wardrobeIds),
            updatedAt: Value(DateTime.now()),
          ),
        );
      }
    }
  }

  /// Remove wardrobe from user
  Future<void> removeWardrobeFromUser(String userId, String wardrobeId) async {
    final user = await getUserById(userId);
    if (user != null) {
      final wardrobeIds = List<String>.from(user.wardrobeIds);
      wardrobeIds.remove(wardrobeId);
      await (update(users)..where((u) => u.id.equals(userId))).write(
        UsersCompanion(
          wardrobeIds: Value(wardrobeIds),
          updatedAt: Value(DateTime.now()),
        ),
      );
    }
  }

  /// Delete user
  Future<void> deleteUser(String userId) async {
    await (delete(users)..where((u) => u.id.equals(userId))).go();
  }

  /// Clear all user data
  Future<void> clearAllUsers() async {
    await delete(users).go();
  }

  /// Convert database user to UserModel
  UserModel userToModel(User user) {
    return UserModel(
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      profilePictureUrl: user.profilePictureUrl,
      isEmailVerified: user.isEmailVerified,
      wardrobeIds: user.wardrobeIds,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      lastLoginAt: user.lastLoginAt,
    );
  }
}