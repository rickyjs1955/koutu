"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { 
  Search, 
  Filter, 
  Plus, 
  Shirt, 
  Menu, 
  X, 
  Grid3X3, 
  List,
  Heart,
  Star,
  ShoppingBag,
  Palette,
  Tag,
  Calendar
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

// Utility function for className merging
function cnUtil(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// Types
interface ClothingItem {
  id: string;
  name: string;
  category: string;
  color: string;
  brand: string;
  season: string;
  image: string;
  isFavorite: boolean;
  lastWorn: string;
  tags: string[];
  rating: number;
}

interface FilterState {
  category: string;
  color: string;
  season: string;
  brand: string;
}

interface FloatingActionMenuProps {
  options: {
    label: string;
    onClick: () => void;
    Icon?: React.ReactNode;
  }[];
  className?: string;
}

// Floating Action Menu Component
const FloatingActionMenu = ({ options, className }: FloatingActionMenuProps) => {
  const [isOpen, setIsOpen] = useState(false);

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  return (
    <div className={cnUtil("fixed bottom-8 right-8 z-50", className)}>
      <Button
        onClick={toggleMenu}
        className="w-14 h-14 rounded-full bg-primary hover:bg-primary/90 shadow-lg"
        size="icon"
      >
        <motion.div
          animate={{ rotate: isOpen ? 45 : 0 }}
          transition={{
            duration: 0.3,
            ease: "easeInOut",
            type: "spring",
            stiffness: 300,
            damping: 20,
          }}
        >
          <Plus className="w-6 h-6" />
        </motion.div>
      </Button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, x: 10, y: 10, filter: "blur(10px)" }}
            animate={{ opacity: 1, x: 0, y: 0, filter: "blur(0px)" }}
            exit={{ opacity: 0, x: 10, y: 10, filter: "blur(10px)" }}
            transition={{
              duration: 0.6,
              type: "spring",
              stiffness: 300,
              damping: 20,
              delay: 0.1,
            }}
            className="absolute bottom-16 right-0 mb-2"
          >
            <div className="flex flex-col items-end gap-2">
              {options.map((option, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  transition={{
                    duration: 0.3,
                    delay: index * 0.05,
                  }}
                >
                  <Button
                    onClick={option.onClick}
                    size="sm"
                    className="flex items-center gap-2 bg-background hover:bg-accent shadow-lg border rounded-xl backdrop-blur-sm"
                    variant="outline"
                  >
                    {option.Icon}
                    <span>{option.label}</span>
                  </Button>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// Header Component
const WardrobeHeader = ({ 
  onMenuToggle, 
  searchQuery, 
  onSearchChange 
}: { 
  onMenuToggle: () => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between px-4">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={onMenuToggle}
            className="md:hidden"
          >
            <Menu className="h-5 w-5" />
          </Button>
          <div className="flex items-center gap-2">
            <Shirt className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-semibold">My Wardrobe</h1>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="relative w-64 hidden sm:block">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search your wardrobe..."
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              className="pl-9"
            />
          </div>
          <Button variant="outline" size="icon">
            <Filter className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  );
};

// Filter Bar Component
const FilterBar = ({ 
  filters, 
  onFilterChange, 
  viewMode, 
  onViewModeChange 
}: {
  filters: FilterState;
  onFilterChange: (key: keyof FilterState, value: string) => void;
  viewMode: 'grid' | 'list';
  onViewModeChange: (mode: 'grid' | 'list') => void;
}) => {
  const categories = ['All', 'Shirts', 'Pants', 'Dresses', 'Jackets', 'Shoes', 'Accessories'];
  const colors = ['All', 'Black', 'White', 'Blue', 'Red', 'Green', 'Gray', 'Brown'];
  const seasons = ['All', 'Spring', 'Summer', 'Fall', 'Winter'];

  return (
    <div className="border-b bg-background p-4">
      <div className="container">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Category:</span>
              <select
                value={filters.category}
                onChange={(e) => onFilterChange('category', e.target.value)}
                className="rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                {categories.map((cat) => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Color:</span>
              <select
                value={filters.color}
                onChange={(e) => onFilterChange('color', e.target.value)}
                className="rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                {colors.map((color) => (
                  <option key={color} value={color}>{color}</option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Season:</span>
              <select
                value={filters.season}
                onChange={(e) => onFilterChange('season', e.target.value)}
                className="rounded-md border border-input bg-background px-3 py-1 text-sm"
              >
                {seasons.map((season) => (
                  <option key={season} value={season}>{season}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant={viewMode === 'grid' ? 'default' : 'outline'}
              size="sm"
              onClick={() => onViewModeChange('grid')}
            >
              <Grid3X3 className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'list' ? 'default' : 'outline'}
              size="sm"
              onClick={() => onViewModeChange('list')}
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Clothing Item Card Component
const ClothingItemCard = ({ 
  item, 
  viewMode, 
  onToggleFavorite 
}: { 
  item: ClothingItem; 
  viewMode: 'grid' | 'list';
  onToggleFavorite: (id: string) => void;
}) => {
  if (viewMode === 'list') {
    return (
      <Card className="p-4">
        <div className="flex items-center gap-4">
          <div className="h-16 w-16 rounded-lg bg-muted flex items-center justify-center">
            <Shirt className="h-8 w-8 text-muted-foreground" />
          </div>
          <div className="flex-1">
            <div className="flex items-center justify-between">
              <h3 className="font-medium">{item.name}</h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onToggleFavorite(item.id)}
              >
                <Heart className={`h-4 w-4 ${item.isFavorite ? 'fill-red-500 text-red-500' : ''}`} />
              </Button>
            </div>
            <div className="flex items-center gap-4 mt-1">
              <Badge variant="secondary">{item.category}</Badge>
              <span className="text-sm text-muted-foreground">{item.brand}</span>
              <span className="text-sm text-muted-foreground">•</span>
              <span className="text-sm text-muted-foreground">{item.color}</span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              {item.tags.map((tag) => (
                <Badge key={tag} variant="outline" className="text-xs">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden group hover:shadow-lg transition-shadow">
      <div className="aspect-square bg-muted relative">
        <div className="absolute inset-0 flex items-center justify-center">
          <Shirt className="h-16 w-16 text-muted-foreground" />
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={() => onToggleFavorite(item.id)}
        >
          <Heart className={`h-4 w-4 ${item.isFavorite ? 'fill-red-500 text-red-500' : ''}`} />
        </Button>
      </div>
      <div className="p-4">
        <h3 className="font-medium truncate">{item.name}</h3>
        <div className="flex items-center justify-between mt-1">
          <Badge variant="secondary">{item.category}</Badge>
          <div className="flex items-center gap-1">
            <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
            <span className="text-xs text-muted-foreground">{item.rating}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-2 text-sm text-muted-foreground">
          <span>{item.brand}</span>
          <span>•</span>
          <span>{item.color}</span>
        </div>
        <div className="flex flex-wrap gap-1 mt-2">
          {item.tags.slice(0, 2).map((tag) => (
            <Badge key={tag} variant="outline" className="text-xs">
              {tag}
            </Badge>
          ))}
          {item.tags.length > 2 && (
            <Badge variant="outline" className="text-xs">
              +{item.tags.length - 2}
            </Badge>
          )}
        </div>
      </div>
    </Card>
  );
};

// Main Wardrobe Management Component
const WardrobeScreen = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [filters, setFilters] = useState<FilterState>({
    category: 'All',
    color: 'All',
    season: 'All',
    brand: 'All'
  });
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Sample clothing data
  const [clothingItems, setClothingItems] = useState<ClothingItem[]>([
    {
      id: '1',
      name: 'Classic White Shirt',
      category: 'Shirts',
      color: 'White',
      brand: 'Uniqlo',
      season: 'All',
      image: '',
      isFavorite: true,
      lastWorn: '2024-01-15',
      tags: ['formal', 'work'],
      rating: 4.5
    },
    {
      id: '2',
      name: 'Blue Denim Jeans',
      category: 'Pants',
      color: 'Blue',
      brand: 'Levi\'s',
      season: 'All',
      image: '',
      isFavorite: false,
      lastWorn: '2024-01-10',
      tags: ['casual', 'weekend'],
      rating: 4.8
    },
    {
      id: '3',
      name: 'Black Blazer',
      category: 'Jackets',
      color: 'Black',
      brand: 'Zara',
      season: 'Fall',
      image: '',
      isFavorite: true,
      lastWorn: '2024-01-08',
      tags: ['formal', 'business'],
      rating: 4.2
    },
    {
      id: '4',
      name: 'Summer Dress',
      category: 'Dresses',
      color: 'Red',
      brand: 'H&M',
      season: 'Summer',
      image: '',
      isFavorite: false,
      lastWorn: '2023-08-20',
      tags: ['casual', 'party'],
      rating: 4.0
    },
    {
      id: '5',
      name: 'Running Shoes',
      category: 'Shoes',
      color: 'Gray',
      brand: 'Nike',
      season: 'All',
      image: '',
      isFavorite: true,
      lastWorn: '2024-01-12',
      tags: ['sport', 'casual'],
      rating: 4.7
    },
    {
      id: '6',
      name: 'Leather Handbag',
      category: 'Accessories',
      color: 'Brown',
      brand: 'Coach',
      season: 'All',
      image: '',
      isFavorite: false,
      lastWorn: '2024-01-05',
      tags: ['formal', 'work'],
      rating: 4.3
    }
  ]);

  const handleFilterChange = (key: keyof FilterState, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleToggleFavorite = (id: string) => {
    setClothingItems(prev => 
      prev.map(item => 
        item.id === id ? { ...item, isFavorite: !item.isFavorite } : item
      )
    );
  };

  const filteredItems = clothingItems.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         item.brand.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         item.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesCategory = filters.category === 'All' || item.category === filters.category;
    const matchesColor = filters.color === 'All' || item.color === filters.color;
    const matchesSeason = filters.season === 'All' || item.season === filters.season || item.season === 'All';

    return matchesSearch && matchesCategory && matchesColor && matchesSeason;
  });

  const floatingMenuOptions = [
    {
      label: "Add Garment",
      Icon: <Shirt className="w-4 h-4" />,
      onClick: () => console.log("Add garment clicked"),
    },
    {
      label: "Scan Barcode",
      Icon: <Tag className="w-4 h-4" />,
      onClick: () => console.log("Scan barcode clicked"),
    },
    {
      label: "Create Outfit",
      Icon: <Palette className="w-4 h-4" />,
      onClick: () => console.log("Create outfit clicked"),
    },
    {
      label: "Plan Outfits",
      Icon: <Calendar className="w-4 h-4" />,
      onClick: () => console.log("Plan outfits clicked"),
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <WardrobeHeader
        onMenuToggle={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
      />

      <FilterBar
        filters={filters}
        onFilterChange={handleFilterChange}
        viewMode={viewMode}
        onViewModeChange={setViewMode}
      />

      <main className="container py-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-semibold">Your Collection</h2>
            <p className="text-muted-foreground">
              {filteredItems.length} item{filteredItems.length !== 1 ? 's' : ''} found
            </p>
          </div>
        </div>

        {/* Mobile Search */}
        <div className="sm:hidden mb-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search your wardrobe..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
            />
          </div>
        </div>

        {filteredItems.length === 0 ? (
          <div className="text-center py-12">
            <ShoppingBag className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-medium mb-2">No items found</h3>
            <p className="text-muted-foreground mb-4">
              Try adjusting your search or filters, or add some new items to your wardrobe.
            </p>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Your First Item
            </Button>
          </div>
        ) : (
          <div className={
            viewMode === 'grid' 
              ? "grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4"
              : "space-y-4"
          }>
            {filteredItems.map((item) => (
              <ClothingItemCard
                key={item.id}
                item={item}
                viewMode={viewMode}
                onToggleFavorite={handleToggleFavorite}
              />
            ))}
          </div>
        )}
      </main>

      <FloatingActionMenu options={floatingMenuOptions} />
    </div>
  );
};

export default WardrobeScreen;