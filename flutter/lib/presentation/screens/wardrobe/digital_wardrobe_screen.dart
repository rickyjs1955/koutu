import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:go_router/go_router.dart';
import 'package:koutu/core/constants/app_colors.dart';
import 'package:koutu/core/constants/app_dimensions.dart';
import 'package:koutu/core/constants/app_text_styles.dart';
import 'package:koutu/presentation/widgets/common/app_button.dart';
import 'package:cached_network_image/cached_network_image.dart';

class DigitalWardrobeScreen extends StatefulWidget {
  const DigitalWardrobeScreen({Key? key}) : super(key: key);

  @override
  State<DigitalWardrobeScreen> createState() => _DigitalWardrobeScreenState();
}

class _DigitalWardrobeScreenState extends State<DigitalWardrobeScreen> 
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  String _selectedCategory = 'All';
  String _sortBy = 'Recent';
  bool _isGridView = true;

  final List<String> _categories = ['All', 'Tops', 'Bottoms', 'Dresses', 'Outerwear', 'Shoes', 'Accessories'];
  final List<String> _sortOptions = ['Recent', 'Name', 'Brand', 'Color', 'Most Worn'];

  // Mock data for demonstration
  final List<Map<String, dynamic>> _garments = [
    {
      'id': '1',
      'name': 'Summer Floral Dress',
      'brand': 'Zara',
      'category': 'Dresses',
      'color': 'Multi',
      'size': 'M',
      'tags': ['summer', 'casual', 'floral'],
      'imageUrl': 'https://example.com/dress1.jpg',
      'wearCount': 12,
      'lastWorn': DateTime.now().subtract(const Duration(days: 3)),
      'polygonData': [], // Polygon coordinates would be stored here
    },
    {
      'id': '2',
      'name': 'Classic White Shirt',
      'brand': 'Uniqlo',
      'category': 'Tops',
      'color': 'White',
      'size': 'L',
      'tags': ['formal', 'business', 'classic'],
      'imageUrl': 'https://example.com/shirt1.jpg',
      'wearCount': 25,
      'lastWorn': DateTime.now().subtract(const Duration(days: 1)),
      'polygonData': [],
    },
    // Add more mock items as needed
  ];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: _categories.length, vsync: this);
    _tabController.addListener(() {
      setState(() {
        _selectedCategory = _categories[_tabController.index];
      });
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  List<Map<String, dynamic>> get _filteredGarments {
    var filtered = _garments;
    
    if (_selectedCategory != 'All') {
      filtered = filtered.where((g) => g['category'] == _selectedCategory).toList();
    }
    
    // Sort logic
    switch (_sortBy) {
      case 'Name':
        filtered.sort((a, b) => a['name'].compareTo(b['name']));
        break;
      case 'Brand':
        filtered.sort((a, b) => a['brand'].compareTo(b['brand']));
        break;
      case 'Color':
        filtered.sort((a, b) => a['color'].compareTo(b['color']));
        break;
      case 'Most Worn':
        filtered.sort((a, b) => b['wearCount'].compareTo(a['wearCount']));
        break;
      case 'Recent':
      default:
        filtered.sort((a, b) => b['lastWorn'].compareTo(a['lastWorn']));
    }
    
    return filtered;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.backgroundLight,
      body: CustomScrollView(
        slivers: [
          _buildSliverAppBar(),
          SliverToBoxAdapter(
            child: _buildTabBar(),
          ),
          SliverToBoxAdapter(
            child: _buildActionBar(),
          ),
          _buildGarmentGrid(),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => context.push('/garment/capture'),
        backgroundColor: AppColors.primary,
        icon: const Icon(Icons.add_a_photo),
        label: const Text('Add Garment'),
      ),
    );
  }

  Widget _buildSliverAppBar() {
    return SliverAppBar(
      expandedHeight: 200,
      floating: false,
      pinned: true,
      backgroundColor: AppColors.primary,
      flexibleSpace: FlexibleSpaceBar(
        title: Text(
          'My Digital Wardrobe',
          style: AppTextStyles.h3.copyWith(color: Colors.white),
        ),
        background: Stack(
          fit: StackFit.expand,
          children: [
            Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    AppColors.primary,
                    AppColors.primary.withOpacity(0.8),
                  ],
                ),
              ),
            ),
            Positioned(
              right: -50,
              bottom: -50,
              child: Icon(
                Icons.checkroom,
                size: 200,
                color: Colors.white.withOpacity(0.1),
              ),
            ),
            Positioned(
              left: 20,
              bottom: 60,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${_garments.length} Items',
                    style: AppTextStyles.h1.copyWith(color: Colors.white),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'AI-Powered Fashion Management',
                    style: AppTextStyles.body2.copyWith(color: Colors.white70),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTabBar() {
    return Container(
      color: AppColors.backgroundLight,
      child: TabBar(
        controller: _tabController,
        isScrollable: true,
        labelColor: AppColors.primary,
        unselectedLabelColor: AppColors.textSecondary,
        indicatorColor: AppColors.primary,
        tabs: _categories.map((category) => Tab(
          text: category,
        )).toList(),
      ),
    );
  }

  Widget _buildActionBar() {
    return Container(
      padding: const EdgeInsets.all(AppDimensions.paddingMedium),
      child: Row(
        children: [
          // Search
          Expanded(
            child: Container(
              height: 40,
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
                border: Border.all(color: AppColors.divider),
              ),
              child: TextField(
                decoration: InputDecoration(
                  hintText: 'Search garments...',
                  hintStyle: AppTextStyles.caption.copyWith(color: AppColors.textSecondary),
                  prefixIcon: Icon(Icons.search, color: AppColors.textSecondary, size: 20),
                  border: InputBorder.none,
                  contentPadding: const EdgeInsets.symmetric(vertical: 10),
                ),
              ),
            ),
          ),
          const SizedBox(width: AppDimensions.spacingSmall),
          
          // Sort dropdown
          Container(
            padding: const EdgeInsets.symmetric(horizontal: AppDimensions.paddingSmall),
            decoration: BoxDecoration(
              color: AppColors.surface,
              borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
              border: Border.all(color: AppColors.divider),
            ),
            child: DropdownButtonHideUnderline(
              child: DropdownButton<String>(
                value: _sortBy,
                icon: const Icon(Icons.sort, size: 20),
                style: AppTextStyles.caption,
                items: _sortOptions.map((option) => DropdownMenuItem(
                  value: option,
                  child: Text(option),
                )).toList(),
                onChanged: (value) => setState(() => _sortBy = value!),
              ),
            ),
          ),
          const SizedBox(width: AppDimensions.spacingSmall),
          
          // View toggle
          IconButton(
            onPressed: () => setState(() => _isGridView = !_isGridView),
            icon: Icon(_isGridView ? Icons.list : Icons.grid_view),
            color: AppColors.textSecondary,
          ),
        ],
      ),
    );
  }

  Widget _buildGarmentGrid() {
    if (_filteredGarments.isEmpty) {
      return SliverFillRemaining(
        child: _buildEmptyState(),
      );
    }

    return _isGridView 
      ? SliverPadding(
          padding: const EdgeInsets.all(AppDimensions.paddingMedium),
          sliver: SliverGrid(
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 2,
              childAspectRatio: 0.7,
              crossAxisSpacing: AppDimensions.spacingMedium,
              mainAxisSpacing: AppDimensions.spacingMedium,
            ),
            delegate: SliverChildBuilderDelegate(
              (context, index) => _buildGarmentCard(_filteredGarments[index]),
              childCount: _filteredGarments.length,
            ),
          ),
        )
      : SliverList(
          delegate: SliverChildBuilderDelegate(
            (context, index) => _buildGarmentListItem(_filteredGarments[index]),
            childCount: _filteredGarments.length,
          ),
        );
  }

  Widget _buildGarmentCard(Map<String, dynamic> garment) {
    return InkWell(
      onTap: () => _showGarmentDetails(garment),
      borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
      child: Container(
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.05),
              blurRadius: 10,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Image with AI badge
            Expanded(
              child: Stack(
                children: [
                  Container(
                    decoration: BoxDecoration(
                      color: AppColors.divider,
                      borderRadius: const BorderRadius.vertical(
                        top: Radius.circular(AppDimensions.radiusMedium),
                      ),
                    ),
                    child: const Center(
                      child: Icon(
                        Icons.checkroom,
                        size: 60,
                        color: AppColors.textSecondary,
                      ),
                    ),
                  ),
                  Positioned(
                    top: 8,
                    right: 8,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: AppColors.primary,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(
                            Icons.auto_awesome,
                            size: 12,
                            color: Colors.white,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            'AI',
                            style: AppTextStyles.caption.copyWith(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
            
            // Details
            Padding(
              padding: const EdgeInsets.all(AppDimensions.paddingSmall),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    garment['name'],
                    style: AppTextStyles.subtitle2,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    garment['brand'],
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      _buildInfoChip(
                        Icons.color_lens,
                        garment['color'],
                      ),
                      const SizedBox(width: 8),
                      _buildInfoChip(
                        Icons.straighten,
                        garment['size'],
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'Worn ${garment['wearCount']}x',
                        style: AppTextStyles.caption.copyWith(
                          color: AppColors.primary,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Icon(
                        Icons.favorite_border,
                        size: 16,
                        color: AppColors.textSecondary,
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildGarmentListItem(Map<String, dynamic> garment) {
    return InkWell(
      onTap: () => _showGarmentDetails(garment),
      child: Container(
        margin: const EdgeInsets.symmetric(
          horizontal: AppDimensions.paddingMedium,
          vertical: AppDimensions.paddingSmall,
        ),
        padding: const EdgeInsets.all(AppDimensions.paddingMedium),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.05),
              blurRadius: 10,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Row(
          children: [
            // Image
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: AppColors.divider,
                borderRadius: BorderRadius.circular(AppDimensions.radiusSmall),
              ),
              child: const Center(
                child: Icon(
                  Icons.checkroom,
                  size: 40,
                  color: AppColors.textSecondary,
                ),
              ),
            ),
            const SizedBox(width: AppDimensions.spacingMedium),
            
            // Details
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    garment['name'],
                    style: AppTextStyles.subtitle1,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${garment['brand']} • ${garment['category']}',
                    style: AppTextStyles.caption.copyWith(
                      color: AppColors.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      _buildInfoChip(Icons.color_lens, garment['color']),
                      const SizedBox(width: 8),
                      _buildInfoChip(Icons.straighten, garment['size']),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: AppColors.primary.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          'Worn ${garment['wearCount']}x',
                          style: AppTextStyles.caption.copyWith(
                            color: AppColors.primary,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            
            // Actions
            Column(
              children: [
                IconButton(
                  onPressed: () {},
                  icon: const Icon(
                    Icons.favorite_border,
                    color: AppColors.textSecondary,
                  ),
                ),
                IconButton(
                  onPressed: () => _showGarmentDetails(garment),
                  icon: const Icon(
                    Icons.more_vert,
                    color: AppColors.textSecondary,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: AppColors.backgroundLight,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: AppColors.textSecondary),
          const SizedBox(width: 4),
          Text(
            label,
            style: AppTextStyles.caption.copyWith(
              color: AppColors.textSecondary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.checkroom_outlined,
            size: 100,
            color: AppColors.textSecondary.withOpacity(0.5),
          ),
          const SizedBox(height: AppDimensions.spacingLarge),
          Text(
            _selectedCategory == 'All' 
              ? 'Your wardrobe is empty'
              : 'No ${_selectedCategory.toLowerCase()} found',
            style: AppTextStyles.h3.copyWith(color: AppColors.textSecondary),
          ),
          const SizedBox(height: AppDimensions.spacingSmall),
          Text(
            'Start adding garments to build your digital wardrobe',
            style: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
          ),
          const SizedBox(height: AppDimensions.spacingLarge),
          AppButton(
            text: 'Add First Garment',
            onPressed: () => context.push('/garment/capture'),
            icon: Icons.add_a_photo,
          ),
        ],
      ),
    );
  }

  void _showGarmentDetails(Map<String, dynamic> garment) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => _GarmentDetailSheet(garment: garment),
    );
  }
}

class _GarmentDetailSheet extends StatelessWidget {
  final Map<String, dynamic> garment;

  const _GarmentDetailSheet({required this.garment});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: MediaQuery.of(context).size.height * 0.8,
      decoration: const BoxDecoration(
        color: AppColors.backgroundLight,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Column(
        children: [
          // Handle
          Container(
            margin: const EdgeInsets.only(top: 12),
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: AppColors.divider,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          
          // Content
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(AppDimensions.paddingLarge),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Image
                  Container(
                    height: 300,
                    decoration: BoxDecoration(
                      color: AppColors.divider,
                      borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
                    ),
                    child: Stack(
                      children: [
                        const Center(
                          child: Icon(
                            Icons.checkroom,
                            size: 100,
                            color: AppColors.textSecondary,
                          ),
                        ),
                        Positioned(
                          top: 16,
                          right: 16,
                          child: Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: AppColors.primary,
                              borderRadius: BorderRadius.circular(20),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(
                                  Icons.auto_awesome,
                                  size: 16,
                                  color: Colors.white,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  'AI Analyzed',
                                  style: AppTextStyles.caption.copyWith(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  
                  const SizedBox(height: AppDimensions.spacingLarge),
                  
                  // Name and brand
                  Text(garment['name'], style: AppTextStyles.h2),
                  const SizedBox(height: 4),
                  Text(
                    garment['brand'],
                    style: AppTextStyles.body1.copyWith(color: AppColors.textSecondary),
                  ),
                  
                  const SizedBox(height: AppDimensions.spacingLarge),
                  
                  // Details grid
                  _buildDetailRow('Category', garment['category']),
                  _buildDetailRow('Color', garment['color']),
                  _buildDetailRow('Size', garment['size']),
                  _buildDetailRow('Times Worn', '${garment['wearCount']}'),
                  
                  const SizedBox(height: AppDimensions.spacingLarge),
                  
                  // Tags
                  Text('Tags', style: AppTextStyles.subtitle1),
                  const SizedBox(height: AppDimensions.spacingSmall),
                  Wrap(
                    spacing: AppDimensions.spacingSmall,
                    children: (garment['tags'] as List<String>).map((tag) => Chip(
                      label: Text(tag),
                      backgroundColor: AppColors.primary.withOpacity(0.1),
                    )).toList(),
                  ),
                  
                  const SizedBox(height: AppDimensions.spacingLarge),
                  
                  // AI Insights
                  Container(
                    padding: const EdgeInsets.all(AppDimensions.paddingMedium),
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          AppColors.primary.withOpacity(0.1),
                          AppColors.primary.withOpacity(0.05),
                        ],
                      ),
                      borderRadius: BorderRadius.circular(AppDimensions.radiusMedium),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.auto_awesome, color: AppColors.primary),
                            const SizedBox(width: 8),
                            Text('AI Insights', style: AppTextStyles.subtitle1),
                          ],
                        ),
                        const SizedBox(height: AppDimensions.spacingSmall),
                        Text(
                          'This garment pairs well with dark jeans and white sneakers for a casual look.',
                          style: AppTextStyles.body2,
                        ),
                      ],
                    ),
                  ),
                  
                  const SizedBox(height: AppDimensions.spacingLarge),
                  
                  // Actions
                  Row(
                    children: [
                      Expanded(
                        child: AppButton(
                          text: 'Edit',
                          onPressed: () {},
                          icon: Icons.edit,
                          variant: AppButtonVariant.outlined,
                        ),
                      ),
                      const SizedBox(width: AppDimensions.spacingMedium),
                      Expanded(
                        child: AppButton(
                          text: 'Create Outfit',
                          onPressed: () {},
                          icon: Icons.style,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: AppTextStyles.body2.copyWith(color: AppColors.textSecondary),
          ),
          Text(
            value,
            style: AppTextStyles.body1.copyWith(fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }
}