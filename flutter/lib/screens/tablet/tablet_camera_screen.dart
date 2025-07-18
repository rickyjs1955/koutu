import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/widgets/tablet/tablet_app_bar.dart';

/// iPad-specific camera screen with enhanced features
class TabletCameraScreen extends ConsumerStatefulWidget {
  const TabletCameraScreen({Key? key}) : super(key: key);

  @override
  ConsumerState<TabletCameraScreen> createState() => _TabletCameraScreenState();
}

class _TabletCameraScreenState extends ConsumerState<TabletCameraScreen> {
  String _selectedMode = 'photo'; // photo, video, scan
  bool _isFlashEnabled = false;
  bool _isGridEnabled = true;
  String _selectedFilter = 'none';
  
  final List<String> _filters = [
    'none',
    'vintage',
    'black_white',
    'sepia',
    'vivid',
    'cool',
    'warm',
  ];

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colorScheme = theme.colorScheme;
    final screenSize = MediaQuery.of(context).size;

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: TabletAppBar(
        title: 'Camera',
        backgroundColor: Colors.black,
        actions: [
          IconButton(
            icon: Icon(
              _isFlashEnabled ? Icons.flash_on : Icons.flash_off,
              color: _isFlashEnabled ? Colors.yellow : Colors.white,
            ),
            onPressed: () {
              setState(() {
                _isFlashEnabled = !_isFlashEnabled;
              });
            },
          ),
          IconButton(
            icon: Icon(
              _isGridEnabled ? Icons.grid_on : Icons.grid_off,
              color: _isGridEnabled ? colorScheme.primary : Colors.white,
            ),
            onPressed: () {
              setState(() {
                _isGridEnabled = !_isGridEnabled;
              });
            },
          ),
          IconButton(
            icon: const Icon(Icons.settings, color: Colors.white),
            onPressed: () {
              _showCameraSettings(context);
            },
          ),
        ],
      ),
      body: Row(
        children: [
          // Camera preview
          Expanded(
            flex: 3,
            child: Container(
              color: Colors.black,
              child: Stack(
                children: [
                  // Camera preview placeholder
                  Center(
                    child: Container(
                      width: screenSize.width * 0.6,
                      height: screenSize.height * 0.7,
                      decoration: BoxDecoration(
                        color: Colors.grey[900],
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: const Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.camera_alt,
                              size: 64,
                              color: Colors.white54,
                            ),
                            SizedBox(height: 16),
                            Text(
                              'Camera Preview',
                              style: TextStyle(
                                color: Colors.white54,
                                fontSize: 18,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  
                  // Grid overlay
                  if (_isGridEnabled)
                    Positioned.fill(
                      child: CustomPaint(
                        painter: GridPainter(),
                      ),
                    ),
                  
                  // Camera controls
                  Positioned(
                    bottom: 32,
                    left: 0,
                    right: 0,
                    child: _buildCameraControls(),
                  ),
                ],
              ),
            ),
          ),
          
          // Side panel
          Container(
            width: 320,
            color: colorScheme.surface,
            child: Column(
              children: [
                // Mode selector
                _buildModeSelector(),
                
                // Filter selector
                _buildFilterSelector(),
                
                // Recent photos
                Expanded(
                  child: _buildRecentPhotos(),
                ),
                
                // Quick actions
                _buildQuickActions(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCameraControls() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: [
        // Gallery button
        Container(
          width: 60,
          height: 60,
          decoration: BoxDecoration(
            color: Colors.white.withOpacity(0.2),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.white, width: 2),
          ),
          child: IconButton(
            icon: const Icon(Icons.photo_library, color: Colors.white),
            onPressed: () {
              // TODO: Open gallery
            },
          ),
        ),
        
        // Shutter button
        Container(
          width: 80,
          height: 80,
          decoration: BoxDecoration(
            color: Colors.white,
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.3),
                blurRadius: 8,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: IconButton(
            icon: Icon(
              _selectedMode == 'video' ? Icons.videocam : Icons.camera_alt,
              color: Colors.black,
              size: 32,
            ),
            onPressed: () {
              _capturePhoto();
            },
          ),
        ),
        
        // Switch camera button
        Container(
          width: 60,
          height: 60,
          decoration: BoxDecoration(
            color: Colors.white.withOpacity(0.2),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.white, width: 2),
          ),
          child: IconButton(
            icon: const Icon(Icons.flip_camera_ios, color: Colors.white),
            onPressed: () {
              // TODO: Switch camera
            },
          ),
        ),
      ],
    );
  }

  Widget _buildModeSelector() {
    return Container(
      height: 80,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Mode',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              _buildModeChip('photo', 'Photo', Icons.camera_alt),
              const SizedBox(width: 8),
              _buildModeChip('video', 'Video', Icons.videocam),
              const SizedBox(width: 8),
              _buildModeChip('scan', 'Scan', Icons.qr_code_scanner),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildModeChip(String mode, String label, IconData icon) {
    final isSelected = _selectedMode == mode;
    final colorScheme = Theme.of(context).colorScheme;
    
    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedMode = mode;
        });
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected ? colorScheme.primary : colorScheme.surfaceVariant,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 16,
              color: isSelected ? colorScheme.onPrimary : colorScheme.onSurfaceVariant,
            ),
            const SizedBox(width: 4),
            Text(
              label,
              style: TextStyle(
                fontSize: 12,
                color: isSelected ? colorScheme.onPrimary : colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterSelector() {
    return Container(
      height: 120,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Filters',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              itemCount: _filters.length,
              itemBuilder: (context, index) {
                final filter = _filters[index];
                final isSelected = _selectedFilter == filter;
                
                return GestureDetector(
                  onTap: () {
                    setState(() {
                      _selectedFilter = filter;
                    });
                  },
                  child: Container(
                    width: 60,
                    margin: const EdgeInsets.only(right: 8),
                    child: Column(
                      children: [
                        Container(
                          width: 50,
                          height: 50,
                          decoration: BoxDecoration(
                            color: Colors.grey[300],
                            borderRadius: BorderRadius.circular(8),
                            border: isSelected
                                ? Border.all(
                                    color: Theme.of(context).colorScheme.primary,
                                    width: 2,
                                  )
                                : null,
                          ),
                          child: const Center(
                            child: Icon(Icons.image, size: 24),
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          _formatFilterName(filter),
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            fontSize: 10,
                            color: isSelected
                                ? Theme.of(context).colorScheme.primary
                                : null,
                          ),
                          textAlign: TextAlign.center,
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
    );
  }

  Widget _buildRecentPhotos() {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Recent Photos',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: GridView.builder(
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 3,
                mainAxisSpacing: 8,
                crossAxisSpacing: 8,
                childAspectRatio: 1.0,
              ),
              itemCount: 12,
              itemBuilder: (context, index) {
                return Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceVariant,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Center(
                    child: Icon(Icons.image, size: 24),
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActions() {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Quick Actions',
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () {
                    // TODO: Add to garment
                  },
                  icon: const Icon(Icons.add_to_photos),
                  label: const Text('Add to Garment'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                    foregroundColor: Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () {
                    // TODO: Create outfit
                  },
                  icon: const Icon(Icons.auto_fix_high),
                  label: const Text('Create Outfit'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _formatFilterName(String filter) {
    switch (filter) {
      case 'none':
        return 'None';
      case 'vintage':
        return 'Vintage';
      case 'black_white':
        return 'B&W';
      case 'sepia':
        return 'Sepia';
      case 'vivid':
        return 'Vivid';
      case 'cool':
        return 'Cool';
      case 'warm':
        return 'Warm';
      default:
        return filter;
    }
  }

  void _capturePhoto() {
    // TODO: Implement photo capture
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Photo captured!'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  void _showCameraSettings(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Camera Settings'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ListTile(
                leading: const Icon(Icons.high_quality),
                title: const Text('Resolution'),
                subtitle: const Text('4K (3840x2160)'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  // TODO: Resolution settings
                },
              ),
              ListTile(
                leading: const Icon(Icons.aspect_ratio),
                title: const Text('Aspect Ratio'),
                subtitle: const Text('16:9'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  // TODO: Aspect ratio settings
                },
              ),
              ListTile(
                leading: const Icon(Icons.timer),
                title: const Text('Timer'),
                subtitle: const Text('Off'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  // TODO: Timer settings
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        );
      },
    );
  }
}

class GridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withOpacity(0.3)
      ..strokeWidth = 1;

    // Draw vertical lines
    canvas.drawLine(
      Offset(size.width / 3, 0),
      Offset(size.width / 3, size.height),
      paint,
    );
    canvas.drawLine(
      Offset(size.width * 2 / 3, 0),
      Offset(size.width * 2 / 3, size.height),
      paint,
    );

    // Draw horizontal lines
    canvas.drawLine(
      Offset(0, size.height / 3),
      Offset(size.width, size.height / 3),
      paint,
    );
    canvas.drawLine(
      Offset(0, size.height * 2 / 3),
      Offset(size.width, size.height * 2 / 3),
      paint,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}