import 'package:dartz/dartz.dart';
import 'package:injectable/injectable.dart';
import 'package:rxdart/rxdart.dart';

import '../../domain/entities/wardrobe.dart';
import '../../domain/failures/failures.dart';
import '../../domain/repositories/i_wardrobe_repository.dart';

@LazySingleton(as: IWardrobeRepository)
class WardrobeRepository implements IWardrobeRepository {
  // In-memory storage for stub data
  final List<Wardrobe> _wardrobes = [];
  final Map<String, List<WardrobeShare>> _wardrobeShares = {};
  final _wardrobesSubject = BehaviorSubject<List<Wardrobe>>();
  final Map<String, BehaviorSubject<Wardrobe>> _wardrobeSubjects = {};

  WardrobeRepository() {
    // Initialize with some stub data
    _initializeStubData();
  }

  void _initializeStubData() {
    _wardrobes.addAll([
      Wardrobe(
        id: 'wardrobe-1',
        userId: 'user-1',
        name: 'Main Wardrobe',
        description: 'My primary wardrobe collection',
        createdAt: DateTime.now().subtract(const Duration(days: 30)),
        updatedAt: DateTime.now().subtract(const Duration(days: 1)),
        garmentCount: 42,
      ),
      Wardrobe(
        id: 'wardrobe-2',
        userId: 'user-1',
        name: 'Summer Collection',
        description: 'Light clothes for warm weather',
        createdAt: DateTime.now().subtract(const Duration(days: 15)),
        updatedAt: DateTime.now(),
        garmentCount: 18,
      ),
    ]);
    _wardrobesSubject.add(_wardrobes);
  }

  @override
  Future<Either<Failure, Wardrobe>> createWardrobe({
    required String name,
    String? description,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 500));

    final wardrobe = Wardrobe(
      id: 'wardrobe-${DateTime.now().millisecondsSinceEpoch}',
      userId: 'user-1', // TODO: Get from auth service
      name: name,
      description: description,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
      garmentCount: 0,
    );

    _wardrobes.add(wardrobe);
    _wardrobesSubject.add(_wardrobes);

    return Right(wardrobe);
  }

  @override
  Future<Either<Failure, List<Wardrobe>>> getAllWardrobes() async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));
    return Right(List.from(_wardrobes));
  }

  @override
  Future<Either<Failure, Wardrobe>> getWardrobeById(String wardrobeId) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    try {
      final wardrobe = _wardrobes.firstWhere((w) => w.id == wardrobeId);
      return Right(wardrobe);
    } catch (_) {
      return Left(Failure.notFound(
        message: 'Wardrobe not found',
        resourceType: 'Wardrobe',
        resourceId: wardrobeId,
      ));
    }
  }

  @override
  Future<Either<Failure, Wardrobe>> updateWardrobe({
    required String wardrobeId,
    String? name,
    String? description,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 400));

    final index = _wardrobes.indexWhere((w) => w.id == wardrobeId);
    if (index == -1) {
      return Left(Failure.notFound(
        message: 'Wardrobe not found',
        resourceType: 'Wardrobe',
        resourceId: wardrobeId,
      ));
    }

    final wardrobe = _wardrobes[index];
    final updated = wardrobe.copyWith(
      name: name ?? wardrobe.name,
      description: description ?? wardrobe.description,
      updatedAt: DateTime.now(),
    );

    _wardrobes[index] = updated;
    _wardrobesSubject.add(_wardrobes);
    _wardrobeSubjects[wardrobeId]?.add(updated);

    return Right(updated);
  }

  @override
  Future<Either<Failure, Unit>> deleteWardrobe(String wardrobeId) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 600));

    _wardrobes.removeWhere((w) => w.id == wardrobeId);
    _wardrobeShares.remove(wardrobeId);
    _wardrobesSubject.add(_wardrobes);
    _wardrobeSubjects[wardrobeId]?.close();
    _wardrobeSubjects.remove(wardrobeId);

    return const Right(unit);
  }

  @override
  Future<Either<Failure, Unit>> shareWardrobe({
    required String wardrobeId,
    required String userId,
    required SharePermission permission,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 400));

    final shares = _wardrobeShares[wardrobeId] ?? [];
    shares.add(WardrobeShare(
      userId: userId,
      userName: 'User $userId', // TODO: Get actual user name
      permission: permission,
      sharedAt: DateTime.now(),
    ));
    _wardrobeShares[wardrobeId] = shares;

    // Update wardrobe's isShared status
    final index = _wardrobes.indexWhere((w) => w.id == wardrobeId);
    if (index != -1) {
      final wardrobe = _wardrobes[index];
      _wardrobes[index] = wardrobe.copyWith(
        isShared: true,
        sharedWith: shares.map((s) => s.userId).toList(),
      );
      _wardrobesSubject.add(_wardrobes);
    }

    return const Right(unit);
  }

  @override
  Future<Either<Failure, Unit>> unshareWardrobe({
    required String wardrobeId,
    required String userId,
  }) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));

    final shares = _wardrobeShares[wardrobeId] ?? [];
    shares.removeWhere((s) => s.userId == userId);
    _wardrobeShares[wardrobeId] = shares;

    // Update wardrobe's shared status
    final index = _wardrobes.indexWhere((w) => w.id == wardrobeId);
    if (index != -1) {
      final wardrobe = _wardrobes[index];
      _wardrobes[index] = wardrobe.copyWith(
        isShared: shares.isNotEmpty,
        sharedWith: shares.map((s) => s.userId).toList(),
      );
      _wardrobesSubject.add(_wardrobes);
    }

    return const Right(unit);
  }

  @override
  Future<Either<Failure, List<WardrobeShare>>> getWardrobeShares(
    String wardrobeId,
  ) async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 200));

    final shares = _wardrobeShares[wardrobeId] ?? [];
    return Right(List.from(shares));
  }

  @override
  Future<Either<Failure, List<Wardrobe>>> getSharedWardrobes() async {
    // TODO: Implement actual API call
    await Future.delayed(const Duration(milliseconds: 300));

    // Return wardrobes that are shared with the current user
    // For stub, return empty list
    return const Right([]);
  }

  @override
  Stream<Either<Failure, List<Wardrobe>>> watchWardrobes() {
    // TODO: Implement actual real-time subscription
    return _wardrobesSubject.stream.map((wardrobes) => Right(wardrobes));
  }

  @override
  Stream<Either<Failure, Wardrobe>> watchWardrobe(String wardrobeId) {
    // TODO: Implement actual real-time subscription
    if (!_wardrobeSubjects.containsKey(wardrobeId)) {
      final wardrobe = _wardrobes.firstWhere(
        (w) => w.id == wardrobeId,
        orElse: () => throw Exception('Wardrobe not found'),
      );
      _wardrobeSubjects[wardrobeId] = BehaviorSubject.seeded(wardrobe);
    }

    return _wardrobeSubjects[wardrobeId]!.stream.map((wardrobe) => Right(wardrobe));
  }

  void dispose() {
    _wardrobesSubject.close();
    for (final subject in _wardrobeSubjects.values) {
      subject.close();
    }
  }
}