import 'package:flutter/material.dart';
import 'package:koutu/presentation/theme/app_colors.dart';
import 'package:koutu/presentation/theme/app_text_styles.dart';
import 'package:koutu/presentation/theme/app_dimensions.dart';
import 'package:koutu/presentation/widgets/app_bar/app_custom_app_bar.dart';
import 'package:koutu/presentation/widgets/loading/app_loading_indicator.dart';
import 'package:koutu/presentation/widgets/animations/app_fade_animation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';
import 'package:koutu/data/models/visualization/garment_3d_model.dart';
import 'package:koutu/services/visualization/garment_3d_service.dart';
import 'package:go_router/go_router.dart';
import 'package:model_viewer_plus/model_viewer_plus.dart';

/// 3D Garment Viewer Screen
class Garment3DViewerScreen extends StatefulWidget {
  final GarmentModel garment;
  
  const Garment3DViewerScreen({
    super.key,
    required this.garment,
  });

  @override
  State<Garment3DViewerScreen> createState() => _Garment3DViewerScreenState();
}

class _Garment3DViewerScreenState extends State<Garment3DViewerScreen> 
    with SingleTickerProviderStateMixin {
  Garment3DModel? _model3D;
  Model3DProcessingStatus? _processingStatus;
  Viewer3DConfiguration? _viewerConfig;
  bool _isLoading = true;
  bool _showControls = true;
  bool _autoRotate = true;
  String _selectedColor = 'original';
  List<Garment3DModel>? _colorVariations;
  late AnimationController _animationController;
  
  // Viewer settings
  double _rotationSpeed = 0.5;
  double _lightIntensity = 0.8;
  String _backgroundColor = '#F5F5F5';
  
  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    );
    _loadOrGenerate3DModel();
  }
  
  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }
  
  Future<void> _loadOrGenerate3DModel() async {
    try {
      // Check if 3D model already exists
      // In real app, this would check cache or database
      
      // Generate new 3D model
      final imageUrls = widget.garment.images.map((img) => img.url).toList();
      final result = await Garment3DService.generate3DModel(
        widget.garment.id,
        imageUrls,
      );
      
      result.fold(
        (failure) {
          _showError('Failed to generate 3D model: ${failure.message}');
        },
        (model) {
          setState(() {
            _model3D = model;
            _viewerConfig = Garment3DService.getDefaultViewerConfiguration();
          });
          
          // Load color variations
          _loadColorVariations();
          
          // Load recommendations
          _loadRecommendations();
        },
      );
    } catch (e) {
      _showError('Error loading 3D model: $e');
    } finally {
      setState(() => _isLoading = false);
      _animationController.forward();
    }
  }
  
  Future<void> _loadColorVariations() async {
    if (_model3D == null) return;
    
    final colors = ['red', 'blue', 'green', 'black', 'white'];
    final result = await Garment3DService.generateModelVariations(
      _model3D!,
      colors,
    );
    
    result.fold(
      (failure) {
        debugPrint('Failed to load color variations: ${failure.message}');
      },
      (variations) {
        setState(() {
          _colorVariations = variations;
        });
      },
    );
  }
  
  Future<void> _loadRecommendations() async {
    final result = await Garment3DService.get3DModelRecommendations(
      widget.garment.category,
    );
    
    result.fold(
      (failure) {
        debugPrint('Failed to load recommendations: ${failure.message}');
      },
      (recommendations) {
        // Show recommendations tip
        if (mounted) {
          _showRecommendationTip(recommendations.first);
        }
      },
    );
  }
  
  void _updateViewerConfiguration(Map<String, dynamic> updates) {
    if (_viewerConfig == null) return;
    
    setState(() {
      _viewerConfig = Garment3DService.updateViewerConfiguration(
        _viewerConfig!,
        updates,
      );
    });
  }
  
  void _trackInteraction(InteractionType type, Map<String, double> position) {
    if (_model3D == null) return;
    
    final event = Interaction3DEvent(
      eventId: 'event_${DateTime.now().millisecondsSinceEpoch}',
      type: type,
      timestamp: DateTime.now(),
      position: position,
      rotation: {'x': 0.0, 'y': 0.0, 'z': 0.0},
      zoom: 1.0,
      additionalData: {
        'garment_id': widget.garment.id,
        'session_id': 'session_123',
      },
    );
    
    Garment3DService.trackInteractionEvent(_model3D!.modelId, event);
  }
  
  Future<void> _exportModel(Model3DFormat format) async {
    if (_model3D == null) return;
    
    setState(() => _isLoading = true);
    
    final result = await Garment3DService.export3DModel(
      _model3D!.modelId,
      format,
    );
    
    result.fold(
      (failure) {
        _showError('Failed to export model: ${failure.message}');
      },
      (exportUrl) {
        _showSuccess('Model exported successfully!');
        // In real app, this would download or share the file
      },
    );
    
    setState(() => _isLoading = false);
  }
  
  void _showError(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: AppColors.error,
      ),
    );
  }
  
  void _showSuccess(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: AppColors.success,
      ),
    );
  }
  
  void _showRecommendationTip(Map<String, dynamic> recommendation) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              recommendation['title'],
              style: AppTextStyles.labelMedium.copyWith(color: Colors.white),
            ),
            Text(
              recommendation['description'],
              style: AppTextStyles.caption.copyWith(color: Colors.white70),
            ),
          ],
        ),
        duration: const Duration(seconds: 5),
        action: SnackBarAction(
          label: 'Apply',
          onPressed: () {
            // Apply recommended settings
            _updateViewerConfiguration(recommendation['settings']);
          },
        ),
      ),
    );
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color(int.parse(_backgroundColor.replaceAll('#', '0xFF'))),
      appBar: AppCustomAppBar(
        title: '3D View',
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              setState(() => _showControls = !_showControls);
            },
          ),
          PopupMenuButton<Model3DFormat>(
            icon: const Icon(Icons.download),
            onSelected: _exportModel,
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: Model3DFormat.glb,
                child: Text('Export as GLB'),
              ),
              const PopupMenuItem(
                value: Model3DFormat.usdz,
                child: Text('Export as USDZ'),
              ),
              const PopupMenuItem(
                value: Model3DFormat.obj,
                child: Text('Export as OBJ'),
              ),
            ],
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: AppLoadingIndicator(message: 'Loading 3D model...'))
          : _model3D == null
              ? _buildErrorState()
              : Stack(
                  children: [
                    // 3D Viewer
                    _build3DViewer(),
                    
                    // Controls panel
                    if (_showControls)
                      _buildControlsPanel(),
                    
                    // Color variations
                    if (_colorVariations != null)
                      _buildColorSelector(),
                    
                    // Info overlay
                    _buildInfoOverlay(),
                  ],
                ),
    );
  }
  
  Widget _build3DViewer() {
    return AnimatedBuilder(
      animation: _animationController,
      builder: (context, child) {
        return Transform.scale(
          scale: 0.8 + (_animationController.value * 0.2),
          child: Opacity(
            opacity: _animationController.value,
            child: ModelViewer(
              src: _model3D!.modelUrl,
              alt: widget.garment.name,
              autoRotate: _autoRotate,
              autoRotateDelay: 0,
              rotationPerSecond: '${_rotationSpeed * 360}deg',
              cameraControls: true,
              backgroundColor: Color(int.parse(_backgroundColor.replaceAll('#', '0xFF'))),
              poster: widget.garment.images.first.url,
              loading: Loading.eager,
              ar: true,
              arModes: const ['scene-viewer', 'webxr', 'quick-look'],
              arScale: ArScale.auto,
              iosSrc: _model3D!.modelUrl.replaceAll('.glb', '.usdz'),
              shadowIntensity: _viewerConfig?.lighting.shadowIntensity ?? 0.5,
              shadowSoftness: 0.5,
              exposure: 1.0,
              // Interaction callbacks
              onModelViewerCreated: (controller) {
                _trackInteraction(InteractionType.tap, {'x': 0, 'y': 0});
              },
            ),
          ),
        );
      },
    );
  }
  
  Widget _buildControlsPanel() {
    return Positioned(
      right: 0,
      top: 0,
      bottom: 0,
      child: AppFadeAnimation(
        child: Container(
          width: 280,
          decoration: BoxDecoration(
            color: AppColors.surface,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.1),
                blurRadius: 10,
                offset: const Offset(-2, 0),
              ),
            ],
          ),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(AppDimensions.paddingL),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Viewer Settings',
                  style: AppTextStyles.h3,
                ),
                const SizedBox(height: AppDimensions.paddingL),
                
                // Auto rotate
                SwitchListTile(
                  title: const Text('Auto Rotate'),
                  value: _autoRotate,
                  onChanged: (value) {
                    setState(() => _autoRotate = value);
                    _updateViewerConfiguration({'autoRotate': value});
                  },
                  contentPadding: EdgeInsets.zero,
                ),
                
                // Rotation speed
                if (_autoRotate) ...[
                  Text(
                    'Rotation Speed',
                    style: AppTextStyles.labelMedium,
                  ),
                  Slider(
                    value: _rotationSpeed,
                    min: 0.1,
                    max: 2.0,
                    divisions: 19,
                    label: '${(_rotationSpeed * 100).toInt()}%',
                    onChanged: (value) {
                      setState(() => _rotationSpeed = value);
                      _updateViewerConfiguration({'rotationSpeed': value});
                    },
                  ),
                ],
                
                const SizedBox(height: AppDimensions.paddingM),
                
                // Lighting intensity
                Text(
                  'Light Intensity',
                  style: AppTextStyles.labelMedium,
                ),
                Slider(
                  value: _lightIntensity,
                  min: 0.0,
                  max: 1.0,
                  divisions: 10,
                  label: '${(_lightIntensity * 100).toInt()}%',
                  onChanged: (value) {
                    setState(() => _lightIntensity = value);
                    _updateViewerConfiguration({'ambientIntensity': value});
                  },
                ),
                
                const SizedBox(height: AppDimensions.paddingM),
                
                // Background color
                Text(
                  'Background Color',
                  style: AppTextStyles.labelMedium,
                ),
                const SizedBox(height: AppDimensions.paddingS),
                Wrap(
                  spacing: AppDimensions.paddingS,
                  children: [
                    '#FFFFFF',
                    '#F5F5F5',
                    '#E0E0E0',
                    '#000000',
                    '#1A1A1A',
                  ].map((color) => GestureDetector(
                    onTap: () {
                      setState(() => _backgroundColor = color);
                      _updateViewerConfiguration({'backgroundColor': color});
                    },
                    child: Container(
                      width: 40,
                      height: 40,
                      decoration: BoxDecoration(
                        color: Color(int.parse(color.replaceAll('#', '0xFF'))),
                        border: Border.all(
                          color: _backgroundColor == color 
                              ? AppColors.primary 
                              : AppColors.backgroundSecondary,
                          width: 2,
                        ),
                        borderRadius: BorderRadius.circular(AppDimensions.radiusS),
                      ),
                    ),
                  )).toList(),
                ),
                
                const SizedBox(height: AppDimensions.paddingL),
                
                // Model info
                if (_model3D != null) ...[
                  _buildInfoSection('Model Info', [
                    _buildInfoRow('Format', _model3D!.format.name.toUpperCase()),
                    _buildInfoRow('Vertices', '${_model3D!.metadata.vertexCount}'),
                    _buildInfoRow('Polygons', '${_model3D!.metadata.polygonCount}'),
                    _buildInfoRow('Size', '${(_model3D!.metadata.fileSizeBytes / 1024 / 1024).toStringAsFixed(1)} MB'),
                  ]),
                ],
                
                const SizedBox(height: AppDimensions.paddingL),
                
                // Actions
                ElevatedButton.icon(
                  onPressed: () {
                    context.push('/ar/try-on/${widget.garment.id}', extra: widget.garment);
                  },
                  icon: const Icon(Icons.view_in_ar),
                  label: const Text('View in AR'),
                  style: ElevatedButton.styleFrom(
                    minimumSize: const Size(double.infinity, 48),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
  
  Widget _buildColorSelector() {
    return Positioned(
      bottom: MediaQuery.of(context).padding.bottom + AppDimensions.paddingL,
      left: AppDimensions.paddingL,
      child: AppFadeAnimation(
        child: Container(
          height: 60,
          decoration: BoxDecoration(
            color: AppColors.surface,
            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.1),
                blurRadius: 10,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Original color
              _buildColorOption('original', widget.garment.color, true),
              
              // Color variations
              ..._colorVariations!.take(5).map((variation) {
                final colorName = variation.modelId.split('_').last;
                return _buildColorOption(
                  colorName,
                  colorName,
                  false,
                );
              }).toList(),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildColorOption(String id, String colorName, bool isOriginal) {
    final isSelected = _selectedColor == id;
    
    return GestureDetector(
      onTap: () {
        setState(() => _selectedColor = id);
        
        if (!isOriginal) {
          // Switch to color variation model
          final variation = _colorVariations!.firstWhere(
            (v) => v.modelId.endsWith(id),
          );
          setState(() => _model3D = variation);
        } else {
          // Switch back to original
          _loadOrGenerate3DModel();
        }
      },
      child: Container(
        width: 50,
        height: 50,
        margin: const EdgeInsets.all(5),
        decoration: BoxDecoration(
          color: _getColorFromName(colorName),
          borderRadius: BorderRadius.circular(AppDimensions.radiusS),
          border: Border.all(
            color: isSelected ? AppColors.primary : AppColors.backgroundSecondary,
            width: isSelected ? 3 : 1,
          ),
        ),
        child: isOriginal
            ? const Icon(
                Icons.undo,
                color: Colors.white,
                size: 20,
              )
            : null,
      ),
    );
  }
  
  Widget _buildInfoOverlay() {
    return Positioned(
      top: AppDimensions.paddingL,
      left: AppDimensions.paddingL,
      child: AppFadeAnimation(
        child: Container(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          decoration: BoxDecoration(
            color: AppColors.surface.withOpacity(0.9),
            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                widget.garment.name,
                style: AppTextStyles.h3,
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Text(
                '${widget.garment.brand} • ${widget.garment.category}',
                style: AppTextStyles.bodyMedium.copyWith(
                  color: AppColors.textSecondary,
                ),
              ),
              const SizedBox(height: AppDimensions.paddingS),
              Row(
                children: [
                  Icon(
                    Icons.touch_app,
                    size: 16,
                    color: AppColors.textTertiary,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    'Drag to rotate • Pinch to zoom',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textTertiary,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildInfoSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: AppTextStyles.labelLarge,
        ),
        const SizedBox(height: AppDimensions.paddingS),
        Container(
          padding: const EdgeInsets.all(AppDimensions.paddingM),
          decoration: BoxDecoration(
            color: AppColors.backgroundSecondary,
            borderRadius: BorderRadius.circular(AppDimensions.radiusM),
          ),
          child: Column(
            children: children,
          ),
        ),
      ],
    );
  }
  
  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
          Text(
            value,
            style: AppTextStyles.caption,
          ),
        ],
      ),
    );
  }
  
  Widget _buildErrorState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 64,
            color: AppColors.error,
          ),
          const SizedBox(height: AppDimensions.paddingL),
          Text(
            'Failed to load 3D model',
            style: AppTextStyles.h3,
          ),
          const SizedBox(height: AppDimensions.paddingM),
          ElevatedButton(
            onPressed: _loadOrGenerate3DModel,
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }
  
  Color _getColorFromName(String colorName) {
    final colors = {
      'red': Colors.red,
      'blue': Colors.blue,
      'green': Colors.green,
      'black': Colors.black,
      'white': Colors.white,
      'grey': Colors.grey,
    };
    
    return colors[colorName.toLowerCase()] ?? 
           Color(int.parse('0xFF${widget.garment.color.replaceAll('#', '')}'));
  }
}