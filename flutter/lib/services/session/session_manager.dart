import 'package:flutter/foundation.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:koutu/data/datasources/local/database/app_database.dart';
import 'package:koutu/services/auth/auth_service.dart';
import 'package:koutu/services/sync/websocket_service.dart';
import 'package:dartz/dartz.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:dio/dio.dart';
import 'package:koutu/core/config/environment.dart';
import 'dart:io';
import 'dart:async';

/// Manages user sessions across multiple devices
class SessionManager {
  final AppDatabase _database;
  final AuthService _authService;
  final WebSocketService _webSocketService;
  final Dio _dio;
  final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();
  
  // Current session
  SessionInfo? _currentSession;
  String? _deviceId;
  Timer? _heartbeatTimer;
  
  // Stream controllers
  final _sessionStateController = StreamController<SessionState>.broadcast();
  final _activeSessionsController = StreamController<List<SessionInfo>>.broadcast();
  
  // Streams
  Stream<SessionState> get sessionState => _sessionStateController.stream;
  Stream<List<SessionInfo>> get activeSessions => _activeSessionsController.stream;
  
  // Session settings
  static const Duration _heartbeatInterval = Duration(minutes: 5);
  static const Duration _sessionTimeout = Duration(minutes: 30);
  static const int _maxDevicesPerUser = 5;
  
  SessionManager({
    required AppDatabase database,
    required AuthService authService,
    required WebSocketService webSocketService,
    required Dio dio,
  })  : _database = database,
        _authService = authService,
        _webSocketService = webSocketService,
        _dio = dio;
  
  /// Initialize session manager
  Future<void> initialize() async {
    await _loadDeviceId();
    
    // Listen to auth state changes
    _authService.authState.listen((isAuthenticated) {
      if (isAuthenticated) {
        _createOrResumeSession();
      } else {
        _endSession();
      }
    });
    
    // Listen to WebSocket events
    _webSocketService.subscribeTo<SyncEvent>('session')
        .listen(_handleSessionEvent);
  }
  
  /// Create or resume session
  Future<Either<Failure, SessionInfo>> createSession() async {
    try {
      // Get device info
      final deviceInfo = await _getDeviceInfo();
      
      // Check if session already exists
      final existingSession = await _checkExistingSession(deviceInfo.deviceId);
      
      if (existingSession != null) {
        // Resume existing session
        return await _resumeSession(existingSession);
      }
      
      // Create new session
      return await _createNewSession(deviceInfo);
    } catch (e) {
      return Left(ServerFailure('Failed to create session: $e'));
    }
  }
  
  /// End current session
  Future<Either<Failure, void>> endSession() async {
    if (_currentSession == null) {
      return const Right(null);
    }
    
    try {
      await _endSession();
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to end session: $e'));
    }
  }
  
  /// Get active sessions for current user
  Future<Either<Failure, List<SessionInfo>>> getActiveSessions() async {
    try {
      final userId = _authService.currentUser?.id;
      if (userId == null) {
        return Left(AuthFailure('User not authenticated'));
      }
      
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.get(
        '${Environment.apiUrl}/sessions/active',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final sessions = (response.data['sessions'] as List)
            .map((json) => SessionInfo.fromJson(json))
            .toList();
        
        _activeSessionsController.add(sessions);
        
        return Right(sessions);
      } else {
        throw Exception('Failed to get sessions: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to get active sessions: $e'));
    }
  }
  
  /// Revoke session on another device
  Future<Either<Failure, void>> revokeSession(String sessionId) async {
    try {
      if (sessionId == _currentSession?.id) {
        return Left(ServerFailure('Cannot revoke current session'));
      }
      
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/sessions/$sessionId/revoke',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Refresh active sessions
        await getActiveSessions();
        
        return const Right(null);
      } else {
        throw Exception('Failed to revoke session: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to revoke session: $e'));
    }
  }
  
  /// Revoke all other sessions
  Future<Either<Failure, void>> revokeAllOtherSessions() async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/sessions/revoke-others',
        data: {
          'currentSessionId': _currentSession?.id,
        },
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Refresh active sessions
        await getActiveSessions();
        
        return const Right(null);
      } else {
        throw Exception('Failed to revoke sessions: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to revoke other sessions: $e'));
    }
  }
  
  /// Update FCM token for push notifications
  Future<Either<Failure, void>> updateFCMToken(String fcmToken) async {
    if (_currentSession == null) {
      return Left(ServerFailure('No active session'));
    }
    
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.put(
        '${Environment.apiUrl}/sessions/${_currentSession!.id}/fcm-token',
        data: {'fcmToken': fcmToken},
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        // Update local session
        _currentSession = _currentSession!.copyWith(fcmToken: fcmToken);
        
        // Update database
        await (_database.update(_database.sessions)
          ..where((tbl) => tbl.id.equals(_currentSession!.id)))
          .write(SessionsCompanion(
            fcmToken: Value(fcmToken),
          ));
        
        return const Right(null);
      } else {
        throw Exception('Failed to update FCM token: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to update FCM token: $e'));
    }
  }
  
  /// Get current session info
  SessionInfo? getCurrentSession() => _currentSession;
  
  /// Check if device limit reached
  Future<Either<Failure, bool>> isDeviceLimitReached() async {
    final result = await getActiveSessions();
    
    return result.fold(
      (failure) => Left(failure),
      (sessions) => Right(sessions.length >= _maxDevicesPerUser),
    );
  }
  
  // Private methods
  
  Future<void> _createOrResumeSession() async {
    final result = await createSession();
    
    result.fold(
      (failure) {
        debugPrint('Failed to create session: ${failure.message}');
        _updateSessionState(SessionState.error);
      },
      (session) {
        _currentSession = session;
        _updateSessionState(SessionState.active);
        _startHeartbeat();
      },
    );
  }
  
  Future<Either<Failure, SessionInfo>> _createNewSession(
    DeviceInfo deviceInfo,
  ) async {
    try {
      // Check device limit
      final limitResult = await isDeviceLimitReached();
      
      final isLimitReached = limitResult.fold(
        (failure) => false,
        (reached) => reached,
      );
      
      if (isLimitReached) {
        return Left(ServerFailure(
          'Device limit reached. Please remove an existing device.',
        ));
      }
      
      final authToken = await _authService.getAuthToken();
      final userId = _authService.currentUser?.id;
      
      if (userId == null) {
        return Left(AuthFailure('User not authenticated'));
      }
      
      final sessionData = {
        'userId': userId,
        'deviceId': deviceInfo.deviceId,
        'deviceName': deviceInfo.deviceName,
        'deviceType': deviceInfo.deviceType,
        'deviceOS': deviceInfo.deviceOS,
        'appVersion': deviceInfo.appVersion,
      };
      
      final response = await _dio.post(
        '${Environment.apiUrl}/sessions/create',
        data: sessionData,
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final session = SessionInfo.fromJson(response.data);
        
        // Save to local database
        await _database.into(_database.sessions).insert(
          SessionsCompanion(
            id: Value(session.id),
            userId: Value(session.userId),
            deviceId: Value(session.deviceId),
            deviceName: Value(session.deviceName),
            deviceType: Value(session.deviceType),
            fcmToken: Value(session.fcmToken),
            isActive: const Value(true),
            lastActiveAt: Value(DateTime.now()),
            createdAt: Value(session.createdAt),
          ),
        );
        
        return Right(session);
      } else {
        throw Exception('Failed to create session: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to create session: $e'));
    }
  }
  
  Future<Either<Failure, SessionInfo>> _resumeSession(
    SessionInfo existingSession,
  ) async {
    try {
      final authToken = await _authService.getAuthToken();
      
      final response = await _dio.post(
        '${Environment.apiUrl}/sessions/${existingSession.id}/resume',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      if (response.statusCode == 200) {
        final session = SessionInfo.fromJson(response.data);
        
        // Update local database
        await (_database.update(_database.sessions)
          ..where((tbl) => tbl.id.equals(session.id)))
          .write(SessionsCompanion(
            isActive: const Value(true),
            lastActiveAt: Value(DateTime.now()),
          ));
        
        return Right(session);
      } else {
        throw Exception('Failed to resume session: ${response.statusCode}');
      }
    } catch (e) {
      return Left(ServerFailure('Failed to resume session: $e'));
    }
  }
  
  Future<SessionInfo?> _checkExistingSession(String deviceId) async {
    try {
      final session = await (_database.select(_database.sessions)
        ..where((tbl) => tbl.deviceId.equals(deviceId))
        ..where((tbl) => tbl.isActive.equals(true)))
        .getSingleOrNull();
      
      if (session != null) {
        return SessionInfo(
          id: session.id,
          userId: session.userId,
          deviceId: session.deviceId,
          deviceName: session.deviceName,
          deviceType: session.deviceType,
          fcmToken: session.fcmToken,
          isActive: session.isActive,
          lastActiveAt: session.lastActiveAt,
          createdAt: session.createdAt,
        );
      }
      
      return null;
    } catch (e) {
      debugPrint('Error checking existing session: $e');
      return null;
    }
  }
  
  Future<DeviceInfo> _getDeviceInfo() async {
    String deviceName = 'Unknown Device';
    String deviceType = 'unknown';
    String deviceOS = 'unknown';
    
    if (Platform.isAndroid) {
      final androidInfo = await _deviceInfo.androidInfo;
      deviceName = '${androidInfo.manufacturer} ${androidInfo.model}';
      deviceType = 'android';
      deviceOS = 'Android ${androidInfo.version.release}';
    } else if (Platform.isIOS) {
      final iosInfo = await _deviceInfo.iosInfo;
      deviceName = iosInfo.name;
      deviceType = 'ios';
      deviceOS = '${iosInfo.systemName} ${iosInfo.systemVersion}';
    }
    
    return DeviceInfo(
      deviceId: _deviceId!,
      deviceName: deviceName,
      deviceType: deviceType,
      deviceOS: deviceOS,
      appVersion: Environment.appVersion,
    );
  }
  
  Future<void> _loadDeviceId() async {
    final prefs = await SharedPreferences.getInstance();
    _deviceId = prefs.getString('device_id');
    
    if (_deviceId == null) {
      // Generate new device ID
      _deviceId = DateTime.now().millisecondsSinceEpoch.toString();
      await prefs.setString('device_id', _deviceId!);
    }
  }
  
  void _startHeartbeat() {
    _heartbeatTimer?.cancel();
    
    _heartbeatTimer = Timer.periodic(_heartbeatInterval, (_) {
      _sendHeartbeat();
    });
    
    // Send initial heartbeat
    _sendHeartbeat();
  }
  
  Future<void> _sendHeartbeat() async {
    if (_currentSession == null) return;
    
    try {
      final authToken = await _authService.getAuthToken();
      
      await _dio.post(
        '${Environment.apiUrl}/sessions/${_currentSession!.id}/heartbeat',
        options: Options(
          headers: {'Authorization': 'Bearer $authToken'},
        ),
      );
      
      // Update local last active time
      await (_database.update(_database.sessions)
        ..where((tbl) => tbl.id.equals(_currentSession!.id)))
        .write(SessionsCompanion(
          lastActiveAt: Value(DateTime.now()),
        ));
    } catch (e) {
      debugPrint('Heartbeat failed: $e');
    }
  }
  
  Future<void> _endSession() async {
    _heartbeatTimer?.cancel();
    
    if (_currentSession != null) {
      try {
        final authToken = await _authService.getAuthToken();
        
        await _dio.post(
          '${Environment.apiUrl}/sessions/${_currentSession!.id}/end',
          options: Options(
            headers: {'Authorization': 'Bearer $authToken'},
          ),
        );
        
        // Update local database
        await (_database.update(_database.sessions)
          ..where((tbl) => tbl.id.equals(_currentSession!.id)))
          .write(SessionsCompanion(
            isActive: const Value(false),
          ));
      } catch (e) {
        debugPrint('Failed to end session: $e');
      }
    }
    
    _currentSession = null;
    _updateSessionState(SessionState.ended);
  }
  
  void _handleSessionEvent(SyncEvent event) {
    switch (event.operation) {
      case SyncOperation.update:
        if (event.data['sessionId'] == _currentSession?.id) {
          // Session updated (possibly revoked)
          if (event.data['isActive'] == false) {
            _endSession();
          }
        }
        break;
      default:
        break;
    }
    
    // Refresh active sessions
    getActiveSessions();
  }
  
  void _updateSessionState(SessionState state) {
    _sessionStateController.add(state);
  }
  
  void dispose() {
    _heartbeatTimer?.cancel();
    _sessionStateController.close();
    _activeSessionsController.close();
  }
}

/// Session information
class SessionInfo {
  final String id;
  final String userId;
  final String deviceId;
  final String deviceName;
  final String deviceType;
  final String? fcmToken;
  final bool isActive;
  final DateTime lastActiveAt;
  final DateTime createdAt;
  
  const SessionInfo({
    required this.id,
    required this.userId,
    required this.deviceId,
    required this.deviceName,
    required this.deviceType,
    this.fcmToken,
    required this.isActive,
    required this.lastActiveAt,
    required this.createdAt,
  });
  
  factory SessionInfo.fromJson(Map<String, dynamic> json) {
    return SessionInfo(
      id: json['id'],
      userId: json['userId'],
      deviceId: json['deviceId'],
      deviceName: json['deviceName'],
      deviceType: json['deviceType'],
      fcmToken: json['fcmToken'],
      isActive: json['isActive'] ?? true,
      lastActiveAt: DateTime.parse(json['lastActiveAt']),
      createdAt: DateTime.parse(json['createdAt']),
    );
  }
  
  SessionInfo copyWith({
    String? fcmToken,
    bool? isActive,
    DateTime? lastActiveAt,
  }) {
    return SessionInfo(
      id: id,
      userId: userId,
      deviceId: deviceId,
      deviceName: deviceName,
      deviceType: deviceType,
      fcmToken: fcmToken ?? this.fcmToken,
      isActive: isActive ?? this.isActive,
      lastActiveAt: lastActiveAt ?? this.lastActiveAt,
      createdAt: createdAt,
    );
  }
}

/// Device information
class DeviceInfo {
  final String deviceId;
  final String deviceName;
  final String deviceType;
  final String deviceOS;
  final String appVersion;
  
  const DeviceInfo({
    required this.deviceId,
    required this.deviceName,
    required this.deviceType,
    required this.deviceOS,
    required this.appVersion,
  });
}

/// Session state
enum SessionState {
  active,
  inactive,
  ended,
  error,
}