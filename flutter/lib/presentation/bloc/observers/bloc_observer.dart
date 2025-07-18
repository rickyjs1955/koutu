import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:koutu/core/utils/logger.dart';

/// Global BLoC observer for monitoring state changes, events, and errors
class AppBlocObserver extends BlocObserver {
  final Logger _logger = Logger();
  final bool _isDebugMode;
  final bool _logTransitions;
  final bool _logEvents;
  final bool _logErrors;
  final bool _logCreation;
  final bool _logClosing;
  
  AppBlocObserver({
    bool isDebugMode = false,
    bool logTransitions = true,
    bool logEvents = true,
    bool logErrors = true,
    bool logCreation = true,
    bool logClosing = true,
  }) : 
    _isDebugMode = isDebugMode,
    _logTransitions = logTransitions,
    _logEvents = logEvents,
    _logErrors = logErrors,
    _logCreation = logCreation,
    _logClosing = logClosing;
  
  @override
  void onCreate(BlocBase bloc) {
    super.onCreate(bloc);
    
    if (_logCreation) {
      _logger.info('🏗️  BLoC Created: ${bloc.runtimeType}');
      
      if (_isDebugMode) {
        _logger.debug('   Initial State: ${bloc.state}');
      }
    }
  }
  
  @override
  void onEvent(BlocBase bloc, Object? event) {
    super.onEvent(bloc, event);
    
    if (_logEvents) {
      _logger.info('📢 Event: ${bloc.runtimeType} → $event');
      
      if (_isDebugMode) {
        _logger.debug('   Current State: ${bloc.state}');
        _logger.debug('   Event Details: ${_formatEventDetails(event)}');
      }
    }
  }
  
  @override
  void onTransition(BlocBase bloc, Transition transition) {
    super.onTransition(bloc, transition);
    
    if (_logTransitions) {
      _logger.info('🔄 Transition: ${bloc.runtimeType}');
      _logger.info('   From: ${transition.currentState}');
      _logger.info('   To: ${transition.nextState}');
      
      if (_isDebugMode) {
        _logger.debug('   Event: ${transition.event}');
        _logger.debug('   Duration: ${_getTransitionDuration(transition)}');
      }
    }
  }
  
  @override
  void onError(BlocBase bloc, Object error, StackTrace stackTrace) {
    super.onError(bloc, error, stackTrace);
    
    if (_logErrors) {
      _logger.error('❌ BLoC Error: ${bloc.runtimeType}');
      _logger.error('   Error: $error');
      _logger.error('   Current State: ${bloc.state}');
      
      if (_isDebugMode) {
        _logger.error('   Stack Trace: $stackTrace');
      }
    }
  }
  
  @override
  void onClose(BlocBase bloc) {
    super.onClose(bloc);
    
    if (_logClosing) {
      _logger.info('🔒 BLoC Closed: ${bloc.runtimeType}');
      
      if (_isDebugMode) {
        _logger.debug('   Final State: ${bloc.state}');
      }
    }
  }
  
  String _formatEventDetails(Object? event) {
    if (event == null) return 'null';
    
    final eventString = event.toString();
    
    // For large events, truncate and show key information
    if (eventString.length > 200) {
      return '${eventString.substring(0, 200)}...';
    }
    
    return eventString;
  }
  
  String _getTransitionDuration(Transition transition) {
    // This is a simplified implementation
    // In a real app, you might track transition timing
    return 'N/A';
  }
}

/// Development-specific BLoC observer with enhanced debugging features
class DevBlocObserver extends BlocObserver {
  final Logger _logger = Logger();
  final Map<String, int> _eventCounts = {};
  final Map<String, int> _transitionCounts = {};
  final Map<String, int> _errorCounts = {};
  final Map<String, DateTime> _creationTimes = {};
  final Map<String, List<String>> _stateHistory = {};
  
  @override
  void onCreate(BlocBase bloc) {
    super.onCreate(bloc);
    
    final blocType = bloc.runtimeType.toString();
    _creationTimes[blocType] = DateTime.now();
    _stateHistory[blocType] = [bloc.state.toString()];
    
    _logger.info('🏗️  [DEV] BLoC Created: $blocType');
    _logger.debug('   📊 Active BLoCs: ${_creationTimes.length}');
  }
  
  @override
  void onEvent(BlocBase bloc, Object? event) {
    super.onEvent(bloc, event);
    
    final blocType = bloc.runtimeType.toString();
    final eventType = event.runtimeType.toString();
    
    _eventCounts[eventType] = (_eventCounts[eventType] ?? 0) + 1;
    
    _logger.info('📢 [DEV] Event: $blocType → $eventType');
    _logger.debug('   📈 Event Count: ${_eventCounts[eventType]}');
    _logger.debug('   📊 Total Events: ${_eventCounts.values.fold(0, (sum, count) => sum + count)}');
  }
  
  @override
  void onTransition(BlocBase bloc, Transition transition) {
    super.onTransition(bloc, transition);
    
    final blocType = bloc.runtimeType.toString();
    final fromState = transition.currentState.runtimeType.toString();
    final toState = transition.nextState.runtimeType.toString();
    
    _transitionCounts[blocType] = (_transitionCounts[blocType] ?? 0) + 1;
    _stateHistory[blocType]?.add(toState);
    
    _logger.info('🔄 [DEV] Transition: $blocType');
    _logger.info('   From: $fromState');
    _logger.info('   To: $toState');
    _logger.debug('   📈 Transition Count: ${_transitionCounts[blocType]}');
    _logger.debug('   📚 State History: ${_getRecentStateHistory(blocType)}');
  }
  
  @override
  void onError(BlocBase bloc, Object error, StackTrace stackTrace) {
    super.onError(bloc, error, stackTrace);
    
    final blocType = bloc.runtimeType.toString();
    _errorCounts[blocType] = (_errorCounts[blocType] ?? 0) + 1;
    
    _logger.error('❌ [DEV] BLoC Error: $blocType');
    _logger.error('   Error: $error');
    _logger.error('   📈 Error Count: ${_errorCounts[blocType]}');
    _logger.error('   📚 Recent States: ${_getRecentStateHistory(blocType)}');
    _logger.error('   Stack Trace: $stackTrace');
  }
  
  @override
  void onClose(BlocBase bloc) {
    super.onClose(bloc);
    
    final blocType = bloc.runtimeType.toString();
    final creationTime = _creationTimes[blocType];
    final lifetime = creationTime != null 
        ? DateTime.now().difference(creationTime).inSeconds
        : 0;
    
    _logger.info('🔒 [DEV] BLoC Closed: $blocType');
    _logger.debug('   ⏱️  Lifetime: ${lifetime}s');
    _logger.debug('   📊 Final Stats:');
    _logger.debug('      - Transitions: ${_transitionCounts[blocType] ?? 0}');
    _logger.debug('      - Errors: ${_errorCounts[blocType] ?? 0}');
    _logger.debug('      - States: ${_stateHistory[blocType]?.length ?? 0}');
    
    // Clean up tracking data
    _creationTimes.remove(blocType);
    _stateHistory.remove(blocType);
    _transitionCounts.remove(blocType);
    _errorCounts.remove(blocType);
  }
  
  String _getRecentStateHistory(String blocType) {
    final history = _stateHistory[blocType];
    if (history == null || history.isEmpty) return 'None';
    
    // Show last 5 states
    final recent = history.length > 5 
        ? history.sublist(history.length - 5)
        : history;
    
    return recent.join(' → ');
  }
  
  // Development utilities
  void printStats() {
    _logger.info('📊 [DEV] BLoC Statistics:');
    _logger.info('   Active BLoCs: ${_creationTimes.length}');
    _logger.info('   Total Events: ${_eventCounts.values.fold(0, (sum, count) => sum + count)}');
    _logger.info('   Total Transitions: ${_transitionCounts.values.fold(0, (sum, count) => sum + count)}');
    _logger.info('   Total Errors: ${_errorCounts.values.fold(0, (sum, count) => sum + count)}');
    
    _logger.info('   📈 Most Active BLoCs:');
    final sortedTransitions = _transitionCounts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    
    for (final entry in sortedTransitions.take(5)) {
      _logger.info('      ${entry.key}: ${entry.value} transitions');
    }
    
    if (_errorCounts.isNotEmpty) {
      _logger.info('   ❌ BLoCs with Errors:');
      for (final entry in _errorCounts.entries) {
        _logger.info('      ${entry.key}: ${entry.value} errors');
      }
    }
  }
  
  void clearStats() {
    _eventCounts.clear();
    _transitionCounts.clear();
    _errorCounts.clear();
    _stateHistory.clear();
    _logger.info('📊 [DEV] BLoC statistics cleared');
  }
}

/// Testing-specific BLoC observer for test validation
class TestBlocObserver extends BlocObserver {
  final List<String> _events = [];
  final List<String> _transitions = [];
  final List<String> _errors = [];
  final List<String> _creations = [];
  final List<String> _closures = [];
  
  // Getters for test validation
  List<String> get events => List.unmodifiable(_events);
  List<String> get transitions => List.unmodifiable(_transitions);
  List<String> get errors => List.unmodifiable(_errors);
  List<String> get creations => List.unmodifiable(_creations);
  List<String> get closures => List.unmodifiable(_closures);
  
  @override
  void onCreate(BlocBase bloc) {
    super.onCreate(bloc);
    _creations.add(bloc.runtimeType.toString());
  }
  
  @override
  void onEvent(BlocBase bloc, Object? event) {
    super.onEvent(bloc, event);
    _events.add('${bloc.runtimeType} → ${event.runtimeType}');
  }
  
  @override
  void onTransition(BlocBase bloc, Transition transition) {
    super.onTransition(bloc, transition);
    _transitions.add('${bloc.runtimeType}: ${transition.currentState.runtimeType} → ${transition.nextState.runtimeType}');
  }
  
  @override
  void onError(BlocBase bloc, Object error, StackTrace stackTrace) {
    super.onError(bloc, error, stackTrace);
    _errors.add('${bloc.runtimeType}: $error');
  }
  
  @override
  void onClose(BlocBase bloc) {
    super.onClose(bloc);
    _closures.add(bloc.runtimeType.toString());
  }
  
  void clear() {
    _events.clear();
    _transitions.clear();
    _errors.clear();
    _creations.clear();
    _closures.clear();
  }
  
  bool hasEvent(String eventPattern) {
    return _events.any((event) => event.contains(eventPattern));
  }
  
  bool hasTransition(String transitionPattern) {
    return _transitions.any((transition) => transition.contains(transitionPattern));
  }
  
  bool hasError(String errorPattern) {
    return _errors.any((error) => error.contains(errorPattern));
  }
  
  int getEventCount(String eventPattern) {
    return _events.where((event) => event.contains(eventPattern)).length;
  }
  
  int getTransitionCount(String transitionPattern) {
    return _transitions.where((transition) => transition.contains(transitionPattern)).length;
  }
  
  int getErrorCount(String errorPattern) {
    return _errors.where((error) => error.contains(errorPattern)).length;
  }
}