import React, { useState, useEffect } from 'react';
import { Camera, Upload, Scissors, Shirt, Home, User, LogOut, Plus, Grid, List, Search, Filter, Download, Edit3, Trash2, Eye, ChevronRight, Sparkles, Zap, Heart, Share2, Settings, CheckCircle, AlertCircle, X } from 'lucide-react';

// Enhanced interfaces
interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
}

interface UploadedImage {
  id: string;
  name: string;
  url: string; // Data URL for local storage
  file: File;
  uploadedAt: string;
  size: number;
  type: string;
  status: 'uploading' | 'success' | 'error';
}

interface Garment {
  id: string;
  name: string;
  type: string;
  color: string;
  imageUrl: string;
  thumbnailUrl: string;
  createdAt: string;
  metadata: {
    brand?: string;
    season?: string;
    tags?: string[];
  };
}

interface Wardrobe {
  id: string;
  name: string;
  description?: string;
  garments: Garment[];
  coverImage?: string;
  createdAt: string;
}

// Local Storage Keys
const STORAGE_KEYS = {
  IMAGES: 'koutu_uploaded_images',
  GARMENTS: 'koutu_garments',
  WARDROBES: 'koutu_wardrobes'
};

// Mock OAuth providers
const oauthProviders = [
  { name: 'Google', icon: '🔍', color: 'bg-red-500' },
  { name: 'GitHub', icon: '🐙', color: 'bg-gray-800' },
  { name: 'Microsoft', icon: '🪟', color: 'bg-blue-600' },
  { name: 'Instagram', icon: '📸', color: 'bg-gradient-to-r from-purple-500 to-pink-500' }
];

// Sample data
const sampleGarments: Garment[] = [
  {
    id: '1',
    name: 'Blue Denim Jacket',
    type: 'jacket',
    color: 'blue',
    imageUrl: 'https://images.unsplash.com/photo-1544966503-7cc5ac882d5c?w=400',
    thumbnailUrl: 'https://images.unsplash.com/photo-1544966503-7cc5ac882d5c?w=200',
    createdAt: '2024-01-15',
    metadata: { brand: 'Levi\'s', season: 'spring', tags: ['casual', 'denim'] }
  }
];

const sampleWardrobes: Wardrobe[] = [
  {
    id: '1',
    name: 'Work Essentials',
    description: 'Professional attire for the office',
    garments: sampleGarments.slice(0, 1),
    coverImage: 'https://images.unsplash.com/photo-1596755094514-f87e34085b2c?w=400',
    createdAt: '2024-01-10'
  }
];

// Utility functions for local storage
const saveToLocalStorage = (key: string, data: any) => {
  try {
    localStorage.setItem(key, JSON.stringify(data));
  } catch (error) {
    console.error('Error saving to localStorage:', error);
  }
};

const loadFromLocalStorage = (key: string, defaultValue: any = []) => {
  try {
    const saved = localStorage.getItem(key);
    return saved ? JSON.parse(saved) : defaultValue;
  } catch (error) {
    console.error('Error loading from localStorage:', error);
    return defaultValue;
  }
};

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [currentPage, setCurrentPage] = useState<'home' | 'upload' | 'images' | 'garments' | 'wardrobes' | 'profile'>('home');
  const [garments, setGarments] = useState<Garment[]>(sampleGarments);
  const [wardrobes, setWardrobes] = useState<Wardrobe[]>(sampleWardrobes);
  const [uploadedImages, setUploadedImages] = useState<UploadedImage[]>([]);
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<string>('all');
  const [notification, setNotification] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  // Load images from localStorage on component mount
  useEffect(() => {
    const savedImages = loadFromLocalStorage(STORAGE_KEYS.IMAGES, []);
    setUploadedImages(savedImages);
  }, []);

  // Save images to localStorage whenever uploadedImages changes
  useEffect(() => {
    if (uploadedImages.length > 0) {
      saveToLocalStorage(STORAGE_KEYS.IMAGES, uploadedImages);
    }
  }, [uploadedImages]);

  // Simulate OAuth login
  const handleOAuthLogin = (provider: string) => {
    setTimeout(() => {
      setUser({
        id: '1',
        name: 'Alex Chen',
        email: 'alex@example.com',
        avatar: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100'
      });
    }, 1000);
  };

  const handleLogout = () => {
    setUser(null);
    setCurrentPage('home');
  };

  // Show notification
  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 5000);
  };

  // Handle image upload
  const handleImageUpload = async (files: File[]) => {
    const newImages: UploadedImage[] = [];

    for (const file of files) {
      // Validate file
      if (!file.type.startsWith('image/')) {
        showNotification('error', `${file.name} is not a valid image file`);
        continue;
      }

      if (file.size > 10 * 1024 * 1024) { // 10MB limit
        showNotification('error', `${file.name} is too large (max 10MB)`);
        continue;
      }

      const imageId = `img_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      // Create initial image object with uploading status
      const imageObj: UploadedImage = {
        id: imageId,
        name: file.name,
        url: '', // Will be set after reading file
        file: file,
        uploadedAt: new Date().toISOString(),
        size: file.size,
        type: file.type,
        status: 'uploading'
      };

      newImages.push(imageObj);
    }

    // Add images with uploading status
    setUploadedImages(prev => [...prev, ...newImages]);

    // Process each image
    for (let i = 0; i < newImages.length; i++) {
      const imageObj = newImages[i];
      
      try {
        // Simulate upload delay
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Read file as data URL
        const dataUrl = await readFileAsDataURL(imageObj.file);
        
        // Update image with success status
        setUploadedImages(prev => prev.map(img => 
          img.id === imageObj.id 
            ? { ...img, url: dataUrl, status: 'success' }
            : img
        ));

        showNotification('success', `${imageObj.name} uploaded successfully!`);
      } catch (error) {
        // Update image with error status
        setUploadedImages(prev => prev.map(img => 
          img.id === imageObj.id 
            ? { ...img, status: 'error' }
            : img
        ));

        showNotification('error', `Failed to upload ${imageObj.name}`);
      }
    }
  };

  // Helper function to read file as data URL
  const readFileAsDataURL = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  };

  // Delete image
  const handleDeleteImage = (imageId: string) => {
    setUploadedImages(prev => prev.filter(img => img.id !== imageId));
    showNotification('success', 'Image deleted successfully');
  };

  // Filter garments based on search and filter
  const filteredGarments = garments.filter(garment => {
    const matchesSearch = garment.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         garment.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         garment.color.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFilter = selectedFilter === 'all' || garment.type === selectedFilter;
    return matchesSearch && matchesFilter;
  });

  const garmentTypes = ['all', ...Array.from(new Set(garments.map(g => g.type)))];

  if (!user) {
    return <LoginScreen onLogin={handleOAuthLogin} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-purple-50">
      {/* Notification */}
      {notification && (
        <Notification
          type={notification.type}
          message={notification.message}
          onClose={() => setNotification(null)}
        />
      )}

      {/* Navigation */}
      <nav className="bg-white/80 backdrop-blur-md border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-8">
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center">
                  <Scissors className="w-4 h-4 text-white" />
                </div>
                <span className="text-xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                  Koutu
                </span>
              </div>
              
              <div className="hidden md:flex space-x-6">
                <NavButton
                  icon={Home}
                  label="Home"
                  active={currentPage === 'home'}
                  onClick={() => setCurrentPage('home')}
                />
                <NavButton
                  icon={Upload}
                  label="Upload"
                  active={currentPage === 'upload'}
                  onClick={() => setCurrentPage('upload')}
                />
                <NavButton
                  icon={Camera}
                  label="Images"
                  active={currentPage === 'images'}
                  onClick={() => setCurrentPage('images')}
                  badge={uploadedImages.length > 0 ? uploadedImages.length : undefined}
                />
                <NavButton
                  icon={Shirt}
                  label="Garments"
                  active={currentPage === 'garments'}
                  onClick={() => setCurrentPage('garments')}
                />
                <NavButton
                  icon={Grid}
                  label="Wardrobes"
                  active={currentPage === 'wardrobes'}
                  onClick={() => setCurrentPage('wardrobes')}
                />
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <button className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors">
                <Settings className="w-5 h-5" />
              </button>
              <div className="flex items-center space-x-3">
                <img
                  src={user.avatar}
                  alt={user.name}
                  className="w-8 h-8 rounded-full"
                />
                <div className="hidden sm:block">
                  <p className="text-sm font-medium text-gray-900">{user.name}</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentPage === 'home' && <HomePage garments={garments} wardrobes={wardrobes} uploadedImages={uploadedImages} />}
        {currentPage === 'upload' && <UploadPage onImageUpload={handleImageUpload} />}
        {currentPage === 'images' && <ImagesPage images={uploadedImages} onDeleteImage={handleDeleteImage} />}
        {currentPage === 'garments' && (
          <GarmentsPage
            garments={filteredGarments}
            viewMode={viewMode}
            onViewModeChange={setViewMode}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            selectedFilter={selectedFilter}
            onFilterChange={setSelectedFilter}
            garmentTypes={garmentTypes}
          />
        )}
        {currentPage === 'wardrobes' && <WardrobesPage wardrobes={wardrobes} />}
      </main>
    </div>
  );
};

// Notification Component
const Notification: React.FC<{
  type: 'success' | 'error';
  message: string;
  onClose: () => void;
}> = ({ type, message, onClose }) => (
  <div className="fixed top-4 right-4 z-50 animate-in slide-in-from-top-2">
    <div className={`flex items-center space-x-3 p-4 rounded-xl shadow-lg max-w-sm ${
      type === 'success' 
        ? 'bg-green-50 border border-green-200' 
        : 'bg-red-50 border border-red-200'
    }`}>
      {type === 'success' ? (
        <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
      ) : (
        <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
      )}
      <p className={`text-sm font-medium ${
        type === 'success' ? 'text-green-800' : 'text-red-800'
      }`}>
        {message}
      </p>
      <button
        onClick={onClose}
        className={`p-1 rounded-lg transition-colors ${
          type === 'success' 
            ? 'text-green-600 hover:bg-green-100' 
            : 'text-red-600 hover:bg-red-100'
        }`}
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  </div>
);

// Login Screen Component
const LoginScreen: React.FC<{ onLogin: (provider: string) => void }> = ({ onLogin }) => {
  const [isLoading, setIsLoading] = useState<string | null>(null);

  const handleLogin = (provider: string) => {
    setIsLoading(provider);
    onLogin(provider);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white/10 backdrop-blur-lg rounded-2xl p-8 border border-white/20">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-r from-indigo-400 to-purple-500 rounded-2xl flex items-center justify-center mx-auto mb-4">
            <Scissors className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Welcome to Koutu</h1>
          <p className="text-indigo-200">AI-powered garment background removal</p>
        </div>

        <div className="space-y-4">
          <p className="text-center text-white/80 text-sm mb-6">
            Sign in with your preferred account
          </p>
          
          {oauthProviders.map((provider) => (
            <button
              key={provider.name}
              onClick={() => handleLogin(provider.name)}
              disabled={isLoading === provider.name}
              className={`w-full flex items-center justify-center space-x-3 p-4 ${provider.color} text-white rounded-xl hover:opacity-90 transition-all duration-200 transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {isLoading === provider.name ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <span className="text-xl">{provider.icon}</span>
              )}
              <span className="font-medium">
                {isLoading === provider.name ? 'Connecting...' : `Continue with ${provider.name}`}
              </span>
            </button>
          ))}
        </div>

        <div className="mt-8 text-center">
          <p className="text-xs text-white/60">
            By signing in, you agree to our Terms of Service and Privacy Policy
          </p>
        </div>
      </div>
    </div>
  );
};

// Navigation Button Component
const NavButton: React.FC<{
  icon: React.ElementType;
  label: string;
  active: boolean;
  onClick: () => void;
  badge?: number;
}> = ({ icon: Icon, label, active, onClick, badge }) => (
  <button
    onClick={onClick}
    className={`relative flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
      active
        ? 'text-indigo-600 bg-indigo-50'
        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
    }`}
  >
    <Icon className="w-4 h-4" />
    <span>{label}</span>
    {badge && badge > 0 && (
      <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
        {badge > 99 ? '99+' : badge}
      </span>
    )}
  </button>
);

// Wardrobe Template Interface
interface WardrobeTemplate {
  id: string;
  name: string;
  description: string;
  style: string;
  coverImage: string;
  backgroundColor: string;
  icon: React.ElementType;
  tags: string[];
  sampleItems: number;
}

// Predefined wardrobe templates (like game avatars)
const wardrobeTemplates: WardrobeTemplate[] = [
  {
    id: 'professional',
    name: 'Professional',
    description: 'Perfect for office and business meetings',
    style: 'Corporate & Formal',
    coverImage: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400',
    backgroundColor: 'from-slate-600 to-slate-800',
    icon: Shirt,
    tags: ['Formal', 'Business', 'Classic'],
    sampleItems: 12
  },
  {
    id: 'casual',
    name: 'Casual Comfort',
    description: 'Everyday relaxed and comfortable wear',
    style: 'Laid-back & Cozy',
    coverImage: 'https://images.unsplash.com/photo-1544966503-7cc5ac882d5c?w=400',
    backgroundColor: 'from-blue-500 to-indigo-600',
    icon: Shirt,
    tags: ['Casual', 'Comfort', 'Weekend'],
    sampleItems: 18
  },
  {
    id: 'trendy',
    name: 'Fashion Forward',
    description: 'Latest trends and statement pieces',
    style: 'Modern & Stylish',
    coverImage: 'https://images.unsplash.com/photo-1485462537746-965f33f7f6a7?w=400',
    backgroundColor: 'from-pink-500 to-rose-600',
    icon: Sparkles,
    tags: ['Trendy', 'Fashion', 'Statement'],
    sampleItems: 24
  },
  {
    id: 'minimalist',
    name: 'Minimalist',
    description: 'Clean, simple, and timeless pieces',
    style: 'Less is More',
    coverImage: 'https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=400',
    backgroundColor: 'from-gray-400 to-gray-600',
    icon: Grid,
    tags: ['Minimal', 'Clean', 'Timeless'],
    sampleItems: 8
  },
  {
    id: 'seasonal',
    name: 'Seasonal Mix',
    description: 'Organized by seasons and weather',
    style: 'Weather-Ready',
    coverImage: 'https://images.unsplash.com/photo-1445205170230-053b83016050?w=400',
    backgroundColor: 'from-emerald-500 to-teal-600',
    icon: Zap,
    tags: ['Seasonal', 'Versatile', 'Weather'],
    sampleItems: 20
  },
  {
    id: 'vintage',
    name: 'Vintage Vibes',
    description: 'Retro and classic vintage styles',
    style: 'Timeless Classics',
    coverImage: 'https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400',
    backgroundColor: 'from-amber-500 to-orange-600',
    icon: Heart,
    tags: ['Vintage', 'Retro', 'Classic'],
    sampleItems: 15
  }
];

// Home Page Component (Wardrobe Selection)
const HomePage: React.FC<{ 
  garments: Garment[]; 
  wardrobes: Wardrobe[];
  uploadedImages: UploadedImage[];
}> = ({ garments, wardrobes, uploadedImages }) => {
  const [currentTemplate, setCurrentTemplate] = useState(0);
  const [showExisting, setShowExisting] = useState(wardrobes.length > 0);

  // Navigation functions
  const nextTemplate = () => {
    setCurrentTemplate((prev) => (prev + 1) % wardrobeTemplates.length);
  };

  const prevTemplate = () => {
    setCurrentTemplate((prev) => (prev - 1 + wardrobeTemplates.length) % wardrobeTemplates.length);
  };

  const selectTemplate = (template: WardrobeTemplate) => {
    console.log('Selected template:', template);
    // Here you would create a new wardrobe based on the template
    // For now, just show success message
    alert(`Creating "${template.name}" wardrobe...`);
  };

  // Show existing wardrobes if user has any
  if (showExisting && wardrobes.length > 0) {
    return (
      <div className="space-y-8">
        {/* Header with Add Wardrobe button */}
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Your Wardrobes</h1>
          <p className="text-gray-600 mb-6">Manage your collections and add new ones</p>
          <button 
            onClick={() => setShowExisting(false)}
            className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white px-8 py-4 rounded-2xl font-medium hover:shadow-lg transition-all duration-200 transform hover:scale-105 flex items-center space-x-2 mx-auto"
          >
            <Plus className="w-5 h-5" />
            <span>Add New Wardrobe</span>
          </button>
        </div>

        {/* Existing Wardrobes Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {wardrobes.map((wardrobe) => (
            <ExistingWardrobeCard key={wardrobe.id} wardrobe={wardrobe} />
          ))}
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatCard
            icon={Camera}
            title="Uploaded Images"
            value={uploadedImages.length.toString()}
            change="+New!"
            color="bg-blue-500"
          />
          <StatCard
            icon={Shirt}
            title="Total Garments"
            value={garments.length.toString()}
            change="+12%"
            color="bg-green-500"
          />
          <StatCard
            icon={Grid}
            title="Wardrobes"
            value={wardrobes.length.toString()}
            change="+3%"
            color="bg-purple-500"
          />
        </div>
      </div>
    );
  }

  // Show template selection (game-like avatar selection)
  const currentTemp = wardrobeTemplates[currentTemplate];

  return (
    <div className="min-h-[80vh] flex flex-col justify-center space-y-8">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-2">Choose Your Wardrobe Style</h1>
        <p className="text-gray-600 text-lg">Select a template to start organizing your fashion collection</p>
      </div>

      {/* Main Template Display */}
      <div className="relative max-w-4xl mx-auto">
        {/* Navigation Arrows */}
        <button
          onClick={prevTemplate}
          className="absolute left-4 top-1/2 transform -translate-y-1/2 z-10 p-3 bg-white/90 backdrop-blur-sm rounded-full shadow-lg hover:bg-white transition-all duration-200 hover:scale-110"
        >
          <ChevronRight className="w-6 h-6 text-gray-700 transform rotate-180" />
        </button>
        
        <button
          onClick={nextTemplate}
          className="absolute right-4 top-1/2 transform -translate-y-1/2 z-10 p-3 bg-white/90 backdrop-blur-sm rounded-full shadow-lg hover:bg-white transition-all duration-200 hover:scale-110"
        >
          <ChevronRight className="w-6 h-6 text-gray-700" />
        </button>

        {/* Template Card */}
        <div className="mx-16">
          <WardrobeTemplateCard 
            template={currentTemp} 
            onSelect={() => selectTemplate(currentTemp)}
          />
        </div>
      </div>

      {/* Template Dots Indicator */}
      <div className="flex justify-center space-x-2">
        {wardrobeTemplates.map((_, index) => (
          <button
            key={index}
            onClick={() => setCurrentTemplate(index)}
            className={`w-3 h-3 rounded-full transition-all duration-200 ${
              index === currentTemplate 
                ? 'bg-indigo-600 scale-125' 
                : 'bg-gray-300 hover:bg-gray-400'
            }`}
          />
        ))}
      </div>

      {/* Template Grid Preview */}
      <div className="max-w-6xl mx-auto">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {wardrobeTemplates.map((template, index) => (
            <button
              key={template.id}
              onClick={() => setCurrentTemplate(index)}
              className={`relative overflow-hidden rounded-xl transition-all duration-200 transform hover:scale-105 ${
                index === currentTemplate 
                  ? 'ring-4 ring-indigo-500 ring-offset-2' 
                  : 'hover:shadow-lg'
              }`}
            >
              <img
                src={template.coverImage}
                alt={template.name}
                className="w-full h-24 object-cover"
              />
              <div className={`absolute inset-0 bg-gradient-to-t ${template.backgroundColor} opacity-80`} />
              <div className="absolute inset-0 flex items-center justify-center">
                <template.icon className="w-6 h-6 text-white" />
              </div>
              <div className="absolute bottom-1 left-1 right-1">
                <p className="text-white text-xs font-medium truncate">{template.name}</p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Skip Option */}
      {wardrobes.length === 0 && (
        <div className="text-center">
          <button 
            onClick={() => setShowExisting(true)}
            className="text-gray-500 hover:text-gray-700 transition-colors text-sm"
          >
            Skip for now - I'll create my own wardrobe
          </button>
        </div>
      )}
    </div>
  );
};

// Wardrobe Template Card Component
const WardrobeTemplateCard: React.FC<{
  template: WardrobeTemplate;
  onSelect: () => void;
}> = ({ template, onSelect }) => (
  <div className="bg-white rounded-3xl shadow-2xl overflow-hidden transform transition-all duration-300 hover:scale-[1.02]">
    {/* Cover Image */}
    <div className="relative h-80">
      <img
        src={template.coverImage}
        alt={template.name}
        className="w-full h-full object-cover"
      />
      <div className={`absolute inset-0 bg-gradient-to-t ${template.backgroundColor} opacity-60`} />
      
      {/* Floating Icon */}
      <div className="absolute top-6 right-6 w-16 h-16 bg-white/20 backdrop-blur-sm rounded-2xl flex items-center justify-center">
        <template.icon className="w-8 h-8 text-white" />
      </div>

      {/* Sample Items Badge */}
      <div className="absolute top-6 left-6 bg-white/20 backdrop-blur-sm rounded-full px-4 py-2">
        <p className="text-white text-sm font-medium">{template.sampleItems} sample items</p>
      </div>
    </div>

    {/* Content */}
    <div className="p-8">
      <div className="mb-6">
        <h2 className="text-3xl font-bold text-gray-900 mb-2">{template.name}</h2>
        <p className="text-gray-600 text-lg mb-1">{template.description}</p>
        <p className="text-indigo-600 font-medium">{template.style}</p>
      </div>

      {/* Tags */}
      <div className="flex flex-wrap gap-2 mb-8">
        {template.tags.map((tag) => (
          <span
            key={tag}
            className="px-3 py-1 bg-indigo-50 text-indigo-700 rounded-full text-sm font-medium"
          >
            {tag}
          </span>
        ))}
      </div>

      {/* Action Button */}
      <button
        onClick={onSelect}
        className={`w-full bg-gradient-to-r ${template.backgroundColor} text-white py-4 px-6 rounded-2xl font-semibold text-lg hover:shadow-lg transition-all duration-200 transform hover:scale-105 flex items-center justify-center space-x-2`}
      >
        <Sparkles className="w-5 h-5" />
        <span>Start with {template.name}</span>
      </button>
    </div>
  </div>
);

// Existing Wardrobe Card (for users who already have wardrobes)
const ExistingWardrobeCard: React.FC<{ wardrobe: Wardrobe }> = ({ wardrobe }) => (
  <div className="bg-white rounded-2xl border border-gray-100 overflow-hidden hover:shadow-lg transition-all duration-200 group cursor-pointer">
    <div className="relative h-48">
      {wardrobe.coverImage ? (
        <img
          src={wardrobe.coverImage}
          alt={wardrobe.name}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
        />
      ) : (
        <div className="w-full h-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
          <Grid className="w-12 h-12 text-white/80" />
        </div>
      )}
      <div className="absolute inset-0 bg-black/20 opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
    
    <div className="p-6">
      <div className="flex justify-between items-start mb-2">
        <h3 className="font-semibold text-gray-900 text-lg">{wardrobe.name}</h3>
        <span className="text-sm text-gray-500">{wardrobe.garments.length} items</span>
      </div>
      
      {wardrobe.description && (
        <p className="text-sm text-gray-600 mb-4">{wardrobe.description}</p>
      )}
      
      {/* Garment Preview */}
      <div className="flex -space-x-2 mb-4">
        {wardrobe.garments.slice(0, 4).map((garment, index) => (
          <img
            key={garment.id}
            src={garment.thumbnailUrl}
            alt={garment.name}
            className="w-8 h-8 rounded-lg border-2 border-white object-cover"
            style={{ zIndex: 4 - index }}
          />
        ))}
        {wardrobe.garments.length > 4 && (
          <div className="w-8 h-8 rounded-lg border-2 border-white bg-gray-100 flex items-center justify-center text-xs font-medium text-gray-600">
            +{wardrobe.garments.length - 4}
          </div>
        )}
      </div>
      
      <button className="w-full bg-indigo-600 text-white py-3 px-4 rounded-xl text-sm font-medium hover:bg-indigo-700 transition-colors">
        Open Wardrobe
      </button>
    </div>
  </div>
);

// Stats Card Component
const StatCard: React.FC<{
  icon: React.ElementType;
  title: string;
  value: string;
  change: string;
  color: string;
}> = ({ icon: Icon, title, value, change, color }) => (
  <div className="bg-white rounded-2xl p-6 border border-gray-100">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm text-gray-600 mb-1">{title}</p>
        <p className="text-2xl font-bold text-gray-900">{value}</p>
        <p className="text-sm text-green-600 mt-1">{change}</p>
      </div>
      <div className={`w-12 h-12 ${color} rounded-xl flex items-center justify-center`}>
        <Icon className="w-6 h-6 text-white" />
      </div>
    </div>
  </div>
);

// Upload Page Component
const UploadPage: React.FC<{ onImageUpload: (files: File[]) => void }> = ({ onImageUpload }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const files = Array.from(e.dataTransfer.files).filter(file => file.type.startsWith('image/'));
    if (files.length > 0) {
      onImageUpload(files);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      onImageUpload(files);
      e.target.value = ''; // Reset input
    }
  };

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Upload Your Images</h1>
        <p className="text-gray-600">Drag and drop your garment images to get started</p>
      </div>

      {/* Upload Area */}
      <div
        className={`border-2 border-dashed rounded-2xl p-12 text-center transition-colors ${
          isDragging
            ? 'border-indigo-500 bg-indigo-50'
            : 'border-gray-300 hover:border-indigo-400 hover:bg-indigo-50/50'
        }`}
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => setIsDragging(true)}
        onDragLeave={() => setIsDragging(false)}
      >
        <div className="w-16 h-16 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
          <Camera className="w-8 h-8 text-indigo-600" />
        </div>
        <h3 className="text-xl font-semibold text-gray-900 mb-2">Drop your images here</h3>
        <p className="text-gray-600 mb-6">or click to browse from your computer</p>
        <input
          type="file"
          multiple
          accept="image/*"
          onChange={handleFileInput}
          className="hidden"
          id="file-upload"
        />
        <label
          htmlFor="file-upload"
          className="inline-flex items-center space-x-2 bg-indigo-600 text-white px-6 py-3 rounded-xl font-medium hover:bg-indigo-700 transition-colors cursor-pointer"
        >
          <Upload className="w-4 h-4" />
          <span>Choose Files</span>
        </label>
        <p className="text-sm text-gray-500 mt-4">Supports: JPG, PNG, WebP (up to 10MB each)</p>
      </div>
    </div>
  );
};

// Images Page Component
const ImagesPage: React.FC<{ 
  images: UploadedImage[]; 
  onDeleteImage: (id: string) => void;
}> = ({ images, onDeleteImage }) => (
  <div className="space-y-6">
    {/* Header */}
    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Your Images</h1>
        <p className="text-gray-600">{images.length} images uploaded</p>
      </div>
    </div>

    {/* Images Grid */}
    {images.length > 0 ? (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {images.map((image) => (
          <ImageCard key={image.id} image={image} onDelete={() => onDeleteImage(image.id)} />
        ))}
      </div>
    ) : (
      <div className="text-center py-12">
        <Camera className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No images yet</h3>
        <p className="text-gray-500 mb-6">Upload your first garment image to get started</p>
        <button className="bg-indigo-600 text-white px-6 py-3 rounded-xl font-medium hover:bg-indigo-700 transition-colors">
          Upload Images
        </button>
      </div>
    )}
  </div>
);

// Image Card Component
const ImageCard: React.FC<{ 
  image: UploadedImage; 
  onDelete: () => void;
}> = ({ image, onDelete }) => (
  <div className="bg-white rounded-2xl border border-gray-100 overflow-hidden hover:shadow-lg transition-all duration-200 group">
    <div className="relative aspect-square">
      {image.url && image.status === 'success' ? (
        <img
          src={image.url}
          alt={image.name}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
        />
      ) : image.status === 'uploading' ? (
        <div className="w-full h-full bg-gray-100 flex items-center justify-center">
          <div className="text-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
            <p className="text-sm text-gray-500">Uploading...</p>
          </div>
        </div>
      ) : (
        <div className="w-full h-full bg-red-50 flex items-center justify-center">
          <div className="text-center">
            <AlertCircle className="w-8 h-8 text-red-500 mx-auto mb-2" />
            <p className="text-sm text-red-500">Upload failed</p>
          </div>
        </div>
      )}
      
      {/* Action buttons */}
      <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity space-y-2">
        {image.status === 'success' && (
          <button className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors">
            <Eye className="w-4 h-4 text-gray-700" />
          </button>
        )}
        <button 
          onClick={onDelete}
          className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors"
        >
          <Trash2 className="w-4 h-4 text-red-500" />
        </button>
      </div>

      {/* Status indicator */}
      {image.status === 'success' && (
        <div className="absolute top-3 left-3">
          <CheckCircle className="w-5 h-5 text-green-500" />
        </div>
      )}
    </div>
    
    <div className="p-4">
      <h3 className="font-semibold text-gray-900 mb-1 truncate">{image.name}</h3>
      <p className="text-sm text-gray-500 mb-2">
        {(image.size / 1024 / 1024).toFixed(2)} MB • {new Date(image.uploadedAt).toLocaleDateString()}
      </p>
      <div className="flex items-center justify-between">
        <span className={`px-2 py-1 rounded-lg text-xs font-medium ${
          image.status === 'success' ? 'bg-green-100 text-green-700' :
          image.status === 'uploading' ? 'bg-blue-100 text-blue-700' :
          'bg-red-100 text-red-700'
        }`}>
          {image.status === 'success' ? 'Ready' : 
           image.status === 'uploading' ? 'Uploading' : 'Failed'}
        </span>
        {image.status === 'success' && (
          <button className="text-indigo-600 hover:text-indigo-700 text-sm font-medium">
            Create Garment
          </button>
        )}
      </div>
    </div>
  </div>
);

// Garments Page Component (keeping existing implementation)
const GarmentsPage: React.FC<{
  garments: Garment[];
  viewMode: 'grid' | 'list';
  onViewModeChange: (mode: 'grid' | 'list') => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  selectedFilter: string;
  onFilterChange: (filter: string) => void;
  garmentTypes: string[];
}> = ({ garments, viewMode, onViewModeChange, searchQuery, onSearchChange, selectedFilter, onFilterChange, garmentTypes }) => (
  <div className="space-y-6">
    {/* Header */}
    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Your Garments</h1>
        <p className="text-gray-600">{garments.length} items in your collection</p>
      </div>
      <button className="bg-indigo-600 text-white px-6 py-3 rounded-xl font-medium hover:bg-indigo-700 transition-colors flex items-center space-x-2">
        <Plus className="w-4 h-4" />
        <span>Add Garment</span>
      </button>
    </div>

    {/* Search and Filters */}
    <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
      <div className="flex-1 relative">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
        <input
          type="text"
          placeholder="Search garments..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full pl-10 pr-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
        />
      </div>
      <select
        value={selectedFilter}
        onChange={(e) => onFilterChange(e.target.value)}
        className="px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
      >
        {garmentTypes.map(type => (
          <option key={type} value={type}>
            {type === 'all' ? 'All Types' : type.charAt(0).toUpperCase() + type.slice(1)}
          </option>
        ))}
      </select>
      <div className="flex bg-gray-100 rounded-xl p-1">
        <button
          onClick={() => onViewModeChange('grid')}
          className={`p-2 rounded-lg transition-colors ${
            viewMode === 'grid' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
          }`}
        >
          <Grid className="w-4 h-4" />
        </button>
        <button
          onClick={() => onViewModeChange('list')}
          className={`p-2 rounded-lg transition-colors ${
            viewMode === 'list' ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600'
          }`}
        >
          <List className="w-4 h-4" />
        </button>
      </div>
    </div>

    {/* Garments Grid/List */}
    {viewMode === 'grid' ? (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {garments.map((garment) => (
          <GarmentCard key={garment.id} garment={garment} />
        ))}
      </div>
    ) : (
      <div className="bg-white rounded-2xl border border-gray-100 overflow-hidden">
        {garments.map((garment, index) => (
          <GarmentListItem key={garment.id} garment={garment} isLast={index === garments.length - 1} />
        ))}
      </div>
    )}
  </div>
);

// Garment Card Component
const GarmentCard: React.FC<{ garment: Garment }> = ({ garment }) => (
  <div className="bg-white rounded-2xl border border-gray-100 overflow-hidden hover:shadow-lg transition-all duration-200 group">
    <div className="relative">
      <img
        src={garment.imageUrl}
        alt={garment.name}
        className="w-full h-48 object-cover group-hover:scale-105 transition-transform duration-200"
      />
      <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity space-y-2">
        <button className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors">
          <Eye className="w-4 h-4 text-gray-700" />
        </button>
        <button className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors">
          <Edit3 className="w-4 h-4 text-gray-700" />
        </button>
        <button className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors">
          <Heart className="w-4 h-4 text-gray-700" />
        </button>
      </div>
    </div>
    <div className="p-4">
      <h3 className="font-semibold text-gray-900 mb-1">{garment.name}</h3>
      <p className="text-sm text-gray-500 mb-2">{garment.type} • {garment.color}</p>
      {garment.metadata.tags && (
        <div className="flex flex-wrap gap-1">
          {garment.metadata.tags.slice(0, 2).map((tag) => (
            <span key={tag} className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-lg">
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  </div>
);

// Garment List Item Component
const GarmentListItem: React.FC<{ garment: Garment; isLast: boolean }> = ({ garment, isLast }) => (
  <div className={`flex items-center space-x-4 p-6 hover:bg-gray-50 transition-colors ${!isLast ? 'border-b border-gray-100' : ''}`}>
    <img
      src={garment.thumbnailUrl}
      alt={garment.name}
      className="w-16 h-16 rounded-xl object-cover"
    />
    <div className="flex-1">
      <h3 className="font-semibold text-gray-900">{garment.name}</h3>
      <p className="text-sm text-gray-500">{garment.type} • {garment.color}</p>
      <div className="flex items-center space-x-2 mt-1">
        {garment.metadata.brand && (
          <span className="px-2 py-1 bg-blue-100 text-blue-700 text-xs rounded-lg">
            {garment.metadata.brand}
          </span>
        )}
        {garment.metadata.tags && garment.metadata.tags.slice(0, 2).map((tag) => (
          <span key={tag} className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-lg">
            {tag}
          </span>
        ))}
      </div>
    </div>
    <div className="flex items-center space-x-2">
      <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
        <Eye className="w-4 h-4" />
      </button>
      <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
        <Edit3 className="w-4 h-4" />
      </button>
      <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
        <Share2 className="w-4 h-4" />
      </button>
      <button className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors">
        <Trash2 className="w-4 h-4" />
      </button>
    </div>
  </div>
);

// Wardrobes Page Component
const WardrobesPage: React.FC<{ wardrobes: Wardrobe[] }> = ({ wardrobes }) => {
  const [showCreateModal, setShowCreateModal] = useState(false);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center space-y-4 sm:space-y-0">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Your Wardrobes</h1>
          <p className="text-gray-600">Organize your garments into collections</p>
        </div>
        <button 
          onClick={() => setShowCreateModal(true)}
          className="bg-indigo-600 text-white px-6 py-3 rounded-xl font-medium hover:bg-indigo-700 transition-colors flex items-center space-x-2"
        >
          <Plus className="w-4 h-4" />
          <span>Create Wardrobe</span>
        </button>
      </div>

      {/* Wardrobes Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {wardrobes.map((wardrobe) => (
          <WardrobeCard key={wardrobe.id} wardrobe={wardrobe} />
        ))}
        
        {/* Create New Wardrobe Card */}
        <div 
          onClick={() => setShowCreateModal(true)}
          className="border-2 border-dashed border-gray-300 rounded-2xl p-8 text-center hover:border-indigo-400 hover:bg-indigo-50/50 transition-colors cursor-pointer group"
        >
          <div className="w-12 h-12 bg-gray-100 group-hover:bg-indigo-100 rounded-xl flex items-center justify-center mx-auto mb-4 transition-colors">
            <Plus className="w-6 h-6 text-gray-400 group-hover:text-indigo-600 transition-colors" />
          </div>
          <h3 className="font-semibold text-gray-900 mb-1">Create New Wardrobe</h3>
          <p className="text-sm text-gray-500">Organize your garments</p>
        </div>
      </div>

      {/* Create Wardrobe Modal */}
      {showCreateModal && (
        <CreateWardrobeModal onClose={() => setShowCreateModal(false)} />
      )}
    </div>
  );
};

// Wardrobe Card Component
const WardrobeCard: React.FC<{ wardrobe: Wardrobe }> = ({ wardrobe }) => (
  <div className="bg-white rounded-2xl border border-gray-100 overflow-hidden hover:shadow-lg transition-all duration-200 group">
    <div className="relative h-48">
      {wardrobe.coverImage ? (
        <img
          src={wardrobe.coverImage}
          alt={wardrobe.name}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-200"
        />
      ) : (
        <div className="w-full h-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
          <Grid className="w-12 h-12 text-white/80" />
        </div>
      )}
      <div className="absolute inset-0 bg-black/20 opacity-0 group-hover:opacity-100 transition-opacity" />
      <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity">
        <button className="p-2 bg-white/90 rounded-lg hover:bg-white transition-colors">
          <Edit3 className="w-4 h-4 text-gray-700" />
        </button>
      </div>
    </div>
    
    <div className="p-6">
      <div className="flex justify-between items-start mb-2">
        <h3 className="font-semibold text-gray-900">{wardrobe.name}</h3>
        <span className="text-sm text-gray-500">{wardrobe.garments.length} items</span>
      </div>
      
      {wardrobe.description && (
        <p className="text-sm text-gray-600 mb-4">{wardrobe.description}</p>
      )}
      
      {/* Garment Preview */}
      <div className="flex -space-x-2 mb-4">
        {wardrobe.garments.slice(0, 4).map((garment, index) => (
          <img
            key={garment.id}
            src={garment.thumbnailUrl}
            alt={garment.name}
            className="w-8 h-8 rounded-lg border-2 border-white object-cover"
            style={{ zIndex: 4 - index }}
          />
        ))}
        {wardrobe.garments.length > 4 && (
          <div className="w-8 h-8 rounded-lg border-2 border-white bg-gray-100 flex items-center justify-center text-xs font-medium text-gray-600">
            +{wardrobe.garments.length - 4}
          </div>
        )}
      </div>
      
      <div className="flex space-x-2">
        <button className="flex-1 bg-indigo-600 text-white py-2 px-4 rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors">
          View
        </button>
        <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
          <Share2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  </div>
);

// Create Wardrobe Modal Component
const CreateWardrobeModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle wardrobe creation
    console.log('Creating wardrobe:', { name, description });
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl p-6 w-full max-w-md">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-gray-900">Create New Wardrobe</h2>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Wardrobe Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              placeholder="e.g., Summer Collection"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description (Optional)
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-4 py-3 border border-gray-200 rounded-xl focus:ring-2 focus:ring-indigo-500 focus:border-transparent resize-none"
              placeholder="Describe your wardrobe..."
            />
          </div>

          <div className="flex space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-3 text-gray-700 bg-gray-100 rounded-xl font-medium hover:bg-gray-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-3 bg-indigo-600 text-white rounded-xl font-medium hover:bg-indigo-700 transition-colors"
            >
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default App;