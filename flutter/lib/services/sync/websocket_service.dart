import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:web_socket_channel/status.dart' as status;
import 'package:koutu/core/config/environment.dart';
import 'package:koutu/core/errors/failures.dart';
import 'package:dartz/dartz.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

/// WebSocket service for real-time data synchronization
class WebSocketService {
  static final WebSocketService _instance = WebSocketService._internal();
  factory WebSocketService() => _instance;
  WebSocketService._internal();
  
  WebSocketChannel? _channel;
  StreamSubscription<ConnectivityResult>? _connectivitySubscription;
  
  // Stream controllers
  final _messageController = StreamController<WebSocketMessage>.broadcast();
  final _connectionStateController = StreamController<ConnectionState>.broadcast();
  final _syncEventController = StreamController<SyncEvent>.broadcast();
  
  // Streams
  Stream<WebSocketMessage> get messages => _messageController.stream;
  Stream<ConnectionState> get connectionState => _connectionStateController.stream;
  Stream<SyncEvent> get syncEvents => _syncEventController.stream;
  
  // Connection state
  ConnectionState _currentState = ConnectionState.disconnected;
  ConnectionState get currentConnectionState => _currentState;
  
  // Reconnection settings
  int _reconnectAttempts = 0;
  static const int _maxReconnectAttempts = 5;
  static const Duration _reconnectDelay = Duration(seconds: 5);
  Timer? _reconnectTimer;
  
  // Ping/Pong for connection health
  Timer? _pingTimer;
  static const Duration _pingInterval = Duration(seconds: 30);
  DateTime? _lastPongReceived;
  
  // Message queue for offline support
  final List<QueuedMessage> _messageQueue = [];
  
  /// Initialize WebSocket connection
  Future<Either<Failure, void>> connect({
    required String userId,
    required String authToken,
  }) async {
    try {
      if (_channel != null) {
        await disconnect();
      }
      
      _updateConnectionState(ConnectionState.connecting);
      
      // Monitor connectivity
      _connectivitySubscription = Connectivity().onConnectivityChanged.listen(
        _handleConnectivityChange,
      );
      
      // Create WebSocket connection
      final wsUrl = '${Environment.wsUrl}/sync?userId=$userId';
      _channel = WebSocketChannel.connect(
        Uri.parse(wsUrl),
        protocols: ['v1.koutu.sync'],
      );
      
      // Send authentication
      _sendMessage(WebSocketMessage(
        type: MessageType.auth,
        data: {'token': authToken},
      ));
      
      // Listen to messages
      _channel!.stream.listen(
        _handleMessage,
        onError: _handleError,
        onDone: _handleDone,
      );
      
      // Start ping timer
      _startPingTimer();
      
      _updateConnectionState(ConnectionState.connected);
      _reconnectAttempts = 0;
      
      // Process queued messages
      await _processMessageQueue();
      
      return const Right(null);
    } catch (e) {
      _updateConnectionState(ConnectionState.error);
      return Left(ServerFailure('Failed to connect: $e'));
    }
  }
  
  /// Disconnect WebSocket
  Future<void> disconnect() async {
    _reconnectTimer?.cancel();
    _pingTimer?.cancel();
    _connectivitySubscription?.cancel();
    
    if (_channel != null) {
      await _channel!.sink.close(status.normalClosure);
      _channel = null;
    }
    
    _updateConnectionState(ConnectionState.disconnected);
  }
  
  /// Send a message through WebSocket
  Future<Either<Failure, void>> sendMessage(WebSocketMessage message) async {
    if (_currentState != ConnectionState.connected) {
      // Queue message for later
      _messageQueue.add(QueuedMessage(
        message: message,
        timestamp: DateTime.now(),
      ));
      return const Right(null);
    }
    
    try {
      _sendMessage(message);
      return const Right(null);
    } catch (e) {
      return Left(ServerFailure('Failed to send message: $e'));
    }
  }
  
  /// Subscribe to specific sync events
  Stream<T> subscribeTo<T extends SyncEvent>(String eventType) {
    return _syncEventController.stream
        .where((event) => event.type == eventType)
        .cast<T>();
  }
  
  /// Request full sync for a specific entity
  Future<Either<Failure, void>> requestSync({
    required SyncEntity entity,
    DateTime? lastSyncTime,
  }) async {
    final message = WebSocketMessage(
      type: MessageType.syncRequest,
      data: {
        'entity': entity.name,
        'lastSync': lastSyncTime?.toIso8601String(),
      },
    );
    
    return sendMessage(message);
  }
  
  // Private methods
  
  void _handleMessage(dynamic data) {
    try {
      final jsonData = json.decode(data as String);
      final message = WebSocketMessage.fromJson(jsonData);
      
      _messageController.add(message);
      
      // Handle specific message types
      switch (message.type) {
        case MessageType.pong:
          _lastPongReceived = DateTime.now();
          break;
          
        case MessageType.sync:
          _handleSyncMessage(message);
          break;
          
        case MessageType.error:
          debugPrint('WebSocket error: ${message.data}');
          break;
          
        default:
          break;
      }
    } catch (e) {
      debugPrint('Error handling WebSocket message: $e');
    }
  }
  
  void _handleSyncMessage(WebSocketMessage message) {
    try {
      final eventType = message.data['eventType'] as String;
      final entityType = message.data['entityType'] as String;
      final operation = message.data['operation'] as String;
      final data = message.data['data'];
      
      final syncEvent = SyncEvent(
        id: message.id,
        type: eventType,
        entityType: entityType,
        operation: SyncOperation.values.firstWhere(
          (op) => op.name == operation,
        ),
        data: data,
        timestamp: DateTime.parse(message.data['timestamp']),
      );
      
      _syncEventController.add(syncEvent);
    } catch (e) {
      debugPrint('Error processing sync message: $e');
    }
  }
  
  void _handleError(error) {
    debugPrint('WebSocket error: $error');
    _updateConnectionState(ConnectionState.error);
    _scheduleReconnect();
  }
  
  void _handleDone() {
    debugPrint('WebSocket connection closed');
    _updateConnectionState(ConnectionState.disconnected);
    _scheduleReconnect();
  }
  
  void _handleConnectivityChange(ConnectivityResult result) {
    if (result != ConnectivityResult.none && 
        _currentState == ConnectionState.disconnected) {
      _scheduleReconnect();
    }
  }
  
  void _scheduleReconnect() {
    if (_reconnectAttempts >= _maxReconnectAttempts) {
      debugPrint('Max reconnection attempts reached');
      return;
    }
    
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(_reconnectDelay, () {
      _reconnectAttempts++;
      debugPrint('Attempting reconnection $_reconnectAttempts/$_maxReconnectAttempts');
      // Reconnect logic would go here
    });
  }
  
  void _startPingTimer() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(_pingInterval, (_) {
      if (_currentState == ConnectionState.connected) {
        _sendMessage(WebSocketMessage(type: MessageType.ping));
        
        // Check for pong timeout
        Timer(const Duration(seconds: 10), () {
          if (_lastPongReceived == null ||
              DateTime.now().difference(_lastPongReceived!) >
                  const Duration(seconds: 40)) {
            debugPrint('Ping timeout - connection may be lost');
            _handleError('Ping timeout');
          }
        });
      }
    });
  }
  
  void _sendMessage(WebSocketMessage message) {
    if (_channel != null) {
      _channel!.sink.add(json.encode(message.toJson()));
    }
  }
  
  void _updateConnectionState(ConnectionState state) {
    _currentState = state;
    _connectionStateController.add(state);
  }
  
  Future<void> _processMessageQueue() async {
    final messagesToSend = List<QueuedMessage>.from(_messageQueue);
    _messageQueue.clear();
    
    for (final queuedMessage in messagesToSend) {
      // Skip old messages
      if (DateTime.now().difference(queuedMessage.timestamp) >
          const Duration(hours: 24)) {
        continue;
      }
      
      await sendMessage(queuedMessage.message);
    }
  }
  
  void dispose() {
    disconnect();
    _messageController.close();
    _connectionStateController.close();
    _syncEventController.close();
  }
}

/// WebSocket message model
class WebSocketMessage {
  final String id;
  final MessageType type;
  final Map<String, dynamic> data;
  final DateTime timestamp;
  
  WebSocketMessage({
    String? id,
    required this.type,
    this.data = const {},
    DateTime? timestamp,
  }) : id = id ?? DateTime.now().millisecondsSinceEpoch.toString(),
       timestamp = timestamp ?? DateTime.now();
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type.name,
    'data': data,
    'timestamp': timestamp.toIso8601String(),
  };
  
  factory WebSocketMessage.fromJson(Map<String, dynamic> json) {
    return WebSocketMessage(
      id: json['id'],
      type: MessageType.values.firstWhere(
        (type) => type.name == json['type'],
      ),
      data: json['data'] ?? {},
      timestamp: DateTime.parse(json['timestamp']),
    );
  }
}

/// Sync event model
class SyncEvent {
  final String id;
  final String type;
  final String entityType;
  final SyncOperation operation;
  final dynamic data;
  final DateTime timestamp;
  
  const SyncEvent({
    required this.id,
    required this.type,
    required this.entityType,
    required this.operation,
    required this.data,
    required this.timestamp,
  });
}

/// Queued message for offline support
class QueuedMessage {
  final WebSocketMessage message;
  final DateTime timestamp;
  
  const QueuedMessage({
    required this.message,
    required this.timestamp,
  });
}

/// Connection states
enum ConnectionState {
  disconnected,
  connecting,
  connected,
  error,
}

/// Message types
enum MessageType {
  auth,
  ping,
  pong,
  sync,
  syncRequest,
  error,
  custom,
}

/// Sync operations
enum SyncOperation {
  create,
  update,
  delete,
  batch,
}

/// Sync entities
enum SyncEntity {
  user,
  wardrobe,
  garment,
  outfit,
  image,
  preference,
}