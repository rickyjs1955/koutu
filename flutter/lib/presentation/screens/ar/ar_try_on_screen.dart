import 'package:flutter/material.dart';
import 'package:camera/camera.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/ar/ar_session_model.dart';
import 'package:koutu/services/ar/ar_service.dart';
import 'package:go_router/go_router.dart';

/// AR Virtual Try-On Screen
class ARTryOnScreen extends StatefulWidget {
  final GarmentModel garment;
  
  const ARTryOnScreen({
    super.key,
    required this.garment,
  });

  @override
  State<ARTryOnScreen> createState() => _ARTryOnScreenState();
}

class _ARTryOnScreenState extends State<ARTryOnScreen> {
  CameraController? _cameraController;
  ARSessionModel? _arSession;
  ARBodyTracking? _bodyTracking;
  List<ARGarmentPlacement> _garmentPlacements = [];
  bool _isInitializing = true;
  bool _isProcessing = false;
  bool _showControls = true;
  bool _showOutfitSuggestions = false;
  double _currentScale = 1.0;
  double _currentRotation = 0.0;
  List<List<GarmentModel>>? _outfitSuggestions;
  
  @override
  void initState() {
    super.initState();
    _initializeAR();
  }
  
  @override
  void dispose() {
    _endARSession();
    _cameraController?.dispose();
    super.dispose();
  }
  
  Future<void> _initializeAR() async {
    try {
      // Check AR capabilities
      final capabilitiesResult = await ARService.checkARCapabilities();
      
      capabilitiesResult.fold(
        (failure) {
          _showError('AR not supported: ${failure.message}');
        },
        (deviceInfo) async {
          if (!deviceInfo.supportsARCore && !deviceInfo.supportsARKit) {
            _showError('Your device does not support AR');
            return;
          }
          
          // Initialize camera
          final cameras = await availableCameras();
          final camera = cameras.firstWhere(
            (cam) => cam.lensDirection == CameraLensDirection.back,
            orElse: () => cameras.first,
          );
          
          _cameraController = CameraController(
            camera,
            ResolutionPreset.high,
            enableAudio: false,
          );
          
          await _cameraController!.initialize();
          
          // Initialize AR session
          final sessionResult = await ARService.initializeARSession('current_user_id');
          
          sessionResult.fold(
            (failure) {
              _showError('Failed to start AR: ${failure.message}');
            },
            (session) async {
              setState(() {
                _arSession = session;
              });
              
              // Start body tracking
              final trackingResult = await ARService.startBodyTracking(session.sessionId);
              
              trackingResult.fold(
                (failure) {
                  _showError('Failed to start tracking: ${failure.message}');
                },
                (tracking) {
                  setState(() {
                    _bodyTracking = tracking;
                    _isInitializing = false;
                  });
                  
                  // Place initial garment
                  _placeGarment(widget.garment);
                  
                  // Load outfit suggestions
                  _loadOutfitSuggestions();
                },
              );
            },
          );
        },
      );
    } catch (e) {
      _showError('Error initializing AR: $e');
    }
  }
  
  Future<void> _placeGarment(GarmentModel garment) async {
    if (_arSession == null || _bodyTracking == null) return;
    
    setState(() => _isProcessing = true);
    
    final result = await ARService.placeGarment(
      _arSession!.sessionId,
      garment,
      _bodyTracking!,
    );
    
    result.fold(
      (failure) {
        _showError('Failed to place garment: ${failure.message}');
      },
      (placement) {
        setState(() {
          // Remove existing placement of same category
          _garmentPlacements.removeWhere(
            (p) => p.garment.category == garment.category,
          );
          _garmentPlacements.add(placement);
        });
      },
    );
    
    setState(() => _isProcessing = false);
  }
  
  Future<void> _adjustGarmentPlacement(
    ARGarmentPlacement placement,
    Map<String, dynamic> adjustments,
  ) async {
    final result = await ARService.adjustGarmentPlacement(placement, adjustments);
    
    result.fold(
      (failure) {
        _showError('Failed to adjust garment: ${failure.message}');
      },
      (updatedPlacement) {
        setState(() {
          final index = _garmentPlacements.indexWhere(
            (p) => p.placementId == placement.placementId,
          );
          if (index != -1) {
            _garmentPlacements[index] = updatedPlacement;
          }
        });
      },
    );
  }
  
  Future<void> _captureARPhoto() async {
    if (_arSession == null || _garmentPlacements.isEmpty) return;
    
    setState(() => _isProcessing = true);
    
    final result = await ARService.captureARScene(
      _arSession!.sessionId,
      _garmentPlacements,
    );
    
    result.fold(
      (failure) {
        _showError('Failed to capture photo: ${failure.message}');
      },
      (capture) {
        // Navigate to capture result screen
        context.push('/ar/capture/${capture.captureId}', extra: capture);
      },
    );
    
    setState(() => _isProcessing = false);
  }
  
  Future<void> _loadOutfitSuggestions() async {
    final result = await ARService.getAROutfitSuggestions(
      'current_user_id',
      widget.garment,
    );
    
    result.fold(
      (failure) {
        debugPrint('Failed to load suggestions: ${failure.message}');
      },
      (suggestions) {
        setState(() {
          _outfitSuggestions = suggestions;
        });
      },
    );
  }
  
  Future<void> _applyOutfitSuggestion(List<GarmentModel> outfit) async {
    setState(() => _showOutfitSuggestions = false);
    
    for (final garment in outfit) {
      await _placeGarment(garment);
      await Future.delayed(const Duration(milliseconds: 300));
    }
  }
  
  Future<void> _endARSession() async {
    if (_arSession != null) {
      await ARService.endARSession(_arSession!.sessionId);
    }
  }
  
  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: AppColors.error,
      ),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [
          // Camera preview
          if (_cameraController != null && _cameraController!.value.isInitialized)
            Positioned.fill(
              child: CameraPreview(_cameraController!),
            ),
          
          // AR overlay (in real implementation, this would be the AR view)
          if (!_isInitializing && _bodyTracking != null)
            _buildAROverlay(),
          
          // Loading indicator
          if (_isInitializing)
            const Center(
              child: AppLoadingIndicator(
                message: 'Initializing AR...',
              ),
            ),
          
          // Top controls
          if (_showControls && !_isInitializing)
            _buildTopControls(),
          
          // Bottom controls
          if (_showControls && !_isInitializing)
            _buildBottomControls(),
          
          // Outfit suggestions panel
          if (_showOutfitSuggestions && _outfitSuggestions != null)
            _buildOutfitSuggestionsPanel(),
          
          // Processing indicator
          if (_isProcessing)
            Container(
              color: Colors.black54,
              child: const Center(
                child: AppLoadingIndicator(),
              ),
            ),
        ],
      ),
    );
  }
  
  Widget _buildAROverlay() {
    // In a real implementation, this would render the AR garments
    // For now, we'll show placement indicators
    return Stack(
      children: _garmentPlacements.map((placement) {
        return Positioned(
          left: MediaQuery.of(context).size.width / 2 - 100,
          top: _getGarmentPositionY(placement.garment.category),
          child: AppFadeAnimation(
            child: Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                border: Border.all(
                  color: AppColors.primary.withOpacity(0.5),
                  width: 2,
                ),
                borderRadius: BorderRadius.circular(AppDimensions.radiusM),
              ),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      Icons.checkroom,
                      color: AppColors.primary,
                      size: 48,
                    ),
                    const SizedBox(height: AppDimensions.paddingS),
                    Text(
                      placement.garment.name,
                      style: AppTextStyles.labelMedium.copyWith(
                        color: Colors.white,
                        backgroundColor: Colors.black54,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      }).toList(),
    );
  }
  
  Widget _buildTopControls() {
    return Positioned(
      top: MediaQuery.of(context).padding.top,
      left: 0,
      right: 0,
      child: AppFadeAnimation(
        child: Container(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                Colors.black.withOpacity(0.6),
                Colors.transparent,
              ],
            ),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // Back button
              IconButton(
                icon: const Icon(Icons.close, color: Colors.white),
                onPressed: () => context.pop(),
              ),
              
              // AR status
              if (_bodyTracking != null)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppDimensions.paddingM,
                    vertical: AppDimensions.paddingS,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.black54,
                    borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        Icons.person,
                        color: _bodyTracking!.isTracking 
                            ? AppColors.success 
                            : AppColors.warning,
                        size: 16,
                      ),
                      const SizedBox(width: AppDimensions.paddingS),
                      Text(
                        _bodyTracking!.isTracking ? 'Tracking' : 'Searching',
                        style: AppTextStyles.caption.copyWith(
                          color: Colors.white,
                        ),
                      ),
                    ],
                  ),
                ),
              
              // Settings
              IconButton(
                icon: const Icon(Icons.settings, color: Colors.white),
                onPressed: () {
                  // Show AR settings
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildBottomControls() {
    return Positioned(
      bottom: 0,
      left: 0,
      right: 0,
      child: AppFadeAnimation(
        child: Container(
          padding: EdgeInsets.only(
            left: AppDimensions.paddingL,
            right: AppDimensions.paddingL,
            bottom: MediaQuery.of(context).padding.bottom + AppDimensions.paddingL,
            top: AppDimensions.paddingL,
          ),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.bottomCenter,
              end: Alignment.topCenter,
              colors: [
                Colors.black.withOpacity(0.8),
                Colors.transparent,
              ],
            ),
          ),
          child: Column(
            children: [
              // Adjustment controls
              if (_garmentPlacements.isNotEmpty)
                Container(
                  margin: const EdgeInsets.only(bottom: AppDimensions.paddingL),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      // Scale control
                      Column(
                        children: [
                          Text(
                            'Size',
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white70,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              IconButton(
                                icon: const Icon(Icons.remove_circle_outline),
                                color: Colors.white,
                                onPressed: () {
                                  setState(() => _currentScale -= 0.1);
                                  _adjustGarmentPlacement(
                                    _garmentPlacements.last,
                                    {'scale': _currentScale},
                                  );
                                },
                              ),
                              Text(
                                '${(_currentScale * 100).toInt()}%',
                                style: AppTextStyles.labelMedium.copyWith(
                                  color: Colors.white,
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.add_circle_outline),
                                color: Colors.white,
                                onPressed: () {
                                  setState(() => _currentScale += 0.1);
                                  _adjustGarmentPlacement(
                                    _garmentPlacements.last,
                                    {'scale': _currentScale},
                                  );
                                },
                              ),
                            ],
                          ),
                        ],
                      ),
                      
                      // Rotation control
                      Column(
                        children: [
                          Text(
                            'Rotate',
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white70,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              IconButton(
                                icon: const Icon(Icons.rotate_left),
                                color: Colors.white,
                                onPressed: () {
                                  setState(() => _currentRotation -= 15);
                                  _adjustGarmentPlacement(
                                    _garmentPlacements.last,
                                    {'rotation_y': _currentRotation * 3.14159 / 180},
                                  );
                                },
                              ),
                              Text(
                                '${_currentRotation.toInt()}°',
                                style: AppTextStyles.labelMedium.copyWith(
                                  color: Colors.white,
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.rotate_right),
                                color: Colors.white,
                                onPressed: () {
                                  setState(() => _currentRotation += 15);
                                  _adjustGarmentPlacement(
                                    _garmentPlacements.last,
                                    {'rotation_y': _currentRotation * 3.14159 / 180},
                                  );
                                },
                              ),
                            ],
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              
              // Action buttons
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  // Outfit suggestions
                  _buildActionButton(
                    icon: Icons.style,
                    label: 'Outfits',
                    onPressed: () {
                      setState(() => _showOutfitSuggestions = !_showOutfitSuggestions);
                    },
                  ),
                  
                  // Capture button
                  GestureDetector(
                    onTap: _captureARPhoto,
                    child: Container(
                      width: 70,
                      height: 70,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: AppColors.primary,
                        border: Border.all(
                          color: Colors.white,
                          width: 3,
                        ),
                      ),
                      child: const Icon(
                        Icons.camera_alt,
                        color: Colors.white,
                        size: 32,
                      ),
                    ),
                  ),
                  
                  // Clear button
                  _buildActionButton(
                    icon: Icons.clear,
                    label: 'Clear',
                    onPressed: () {
                      setState(() {
                        _garmentPlacements.clear();
                        _currentScale = 1.0;
                        _currentRotation = 0.0;
                      });
                    },
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
  }) {
    return Column(
      children: [
        IconButton(
          icon: Icon(icon),
          color: Colors.white,
          iconSize: 28,
          onPressed: onPressed,
        ),
        Text(
          label,
          style: AppTextStyles.caption.copyWith(
            color: Colors.white70,
          ),
        ),
      ],
    );
  }
  
  Widget _buildOutfitSuggestionsPanel() {
    return Positioned(
      bottom: 0,
      left: 0,
      right: 0,
      child: AppFadeAnimation(
        child: Container(
          height: 250,
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: const BorderRadius.vertical(
              top: Radius.circular(AppDimensions.radiusL),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.2),
                blurRadius: 10,
                offset: const Offset(0, -2),
              ),
            ],
          ),
          child: Column(
            children: [
              // Handle
              Container(
                margin: const EdgeInsets.only(top: AppDimensions.paddingM),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: AppColors.backgroundSecondary,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              
              // Title
              Padding(
                padding: const EdgeInsets.all(AppDimensions.paddingM),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'Outfit Suggestions',
                      style: AppTextStyles.h3,
                    ),
                    IconButton(
                      icon: const Icon(Icons.close),
                      onPressed: () {
                        setState(() => _showOutfitSuggestions = false);
                      },
                    ),
                  ],
                ),
              ),
              
              // Suggestions list
              Expanded(
                child: ListView.builder(
                  scrollDirection: Axis.horizontal,
                  padding: const EdgeInsets.symmetric(
                    horizontal: AppDimensions.paddingM,
                  ),
                  itemCount: _outfitSuggestions!.length,
                  itemBuilder: (context, index) {
                    final outfit = _outfitSuggestions![index];
                    return GestureDetector(
                      onTap: () => _applyOutfitSuggestion(outfit),
                      child: Container(
                        width: 150,
                        margin: const EdgeInsets.only(right: AppDimensions.paddingM),
                        decoration: BoxDecoration(
                          color: AppColors.backgroundSecondary,
                          borderRadius: BorderRadius.circular(AppDimensions.radiusM),
                        ),
                        child: Column(
                          children: [
                            // Outfit preview
                            Expanded(
                              child: Stack(
                                children: outfit.map((garment) {
                                  final index = outfit.indexOf(garment);
                                  return Positioned(
                                    top: index * 30.0,
                                    left: 10,
                                    right: 10,
                                    child: Container(
                                      height: 60,
                                      decoration: BoxDecoration(
                                        color: AppColors.surface,
                                        borderRadius: BorderRadius.circular(
                                          AppDimensions.radiusS,
                                        ),
                                        border: Border.all(
                                          color: AppColors.backgroundSecondary,
                                        ),
                                      ),
                                      child: Center(
                                        child: Text(
                                          garment.name,
                                          style: AppTextStyles.caption,
                                          textAlign: TextAlign.center,
                                          maxLines: 2,
                                          overflow: TextOverflow.ellipsis,
                                        ),
                                      ),
                                    ),
                                  );
                                }).toList(),
                              ),
                            ),
                            // Apply button
                            Container(
                              padding: const EdgeInsets.all(AppDimensions.paddingS),
                              child: Text(
                                'Try This Look',
                                style: AppTextStyles.labelMedium.copyWith(
                                  color: AppColors.primary,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  double _getGarmentPositionY(String category) {
    switch (category.toLowerCase()) {
      case 'tops':
      case 'shirts':
      case 't-shirts':
        return 150;
      case 'bottoms':
      case 'pants':
      case 'jeans':
        return 300;
      case 'shoes':
      case 'footwear':
        return 450;
      case 'accessories':
        return 100;
      default:
        return 250;
    }
  }
}