// frontend/src/components/polygon/PolygonList.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import PolygonList from './PolygonList';
import { useImagePolygons, useDeletePolygon } from '../../hooks/usePolygons';

// Mock the hooks
jest.mock('../../hooks/usePolygons', () => ({
  useImagePolygons: jest.fn(),
  useDeletePolygon: jest.fn()
}));

describe('PolygonList Component', () => {
  const mockPolygons = [
    {
      id: '1',
      original_image_id: 'image1',
      points: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 10 }, { x: 0, y: 10 }],
      label: 'shirt',
      created_at: new Date('2023-01-01'),
      updated_at: new Date('2023-01-01')
    },
    {
      id: '2',
      original_image_id: 'image1',
      points: [{ x: 20, y: 20 }, { x: 30, y: 20 }, { x: 30, y: 30 }, { x: 20, y: 30 }],
      label: 'pants',
      created_at: new Date('2023-01-02'),
      updated_at: new Date('2023-01-02')
    }
  ];

  const mockDeletePolygonFn = jest.fn();
  
  beforeEach(() => {
    // Set up mocks
    (useImagePolygons as jest.Mock).mockReturnValue({
      data: mockPolygons,
      isLoading: false,
      error: null
    });
    
    (useDeletePolygon as jest.Mock).mockReturnValue({
      mutate: mockDeletePolygonFn,
      isLoading: false,
      variables: null
    });
    
    // Mock window.confirm
    window.confirm = jest.fn().mockReturnValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test('renders loading state', () => {
    (useImagePolygons as jest.Mock).mockReturnValue({
      data: null,
      isLoading: true,
      error: null
    });
    
    render(<PolygonList imageId="image1" />);
    expect(screen.getByText(/Loading polygons/i)).toBeInTheDocument();
  });

  test('renders error state', () => {
    (useImagePolygons as jest.Mock).mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('Failed to load polygons')
    });
    
    render(<PolygonList imageId="image1" />);
    expect(screen.getByText(/Error loading polygons/i)).toBeInTheDocument();
  });

  test('renders empty state when no polygons', () => {
    (useImagePolygons as jest.Mock).mockReturnValue({
      data: [],
      isLoading: false,
      error: null
    });
    
    render(<PolygonList imageId="image1" />);
    expect(screen.getByText(/No polygons found/i)).toBeInTheDocument();
    expect(screen.getByText(/Use the drawing tool/i)).toBeInTheDocument();
  });

  test('renders list of polygons', () => {
    render(<PolygonList imageId="image1" />);
    
    // Check if all polygon labels are displayed
    expect(screen.getByText('shirt')).toBeInTheDocument();
    expect(screen.getByText('pants')).toBeInTheDocument();
    
    // Check if we have the expected number of delete buttons
    const deleteButtons = screen.getAllByText(/Delete/i);
    expect(deleteButtons).toHaveLength(2);
  });

  test('calls onSelectPolygon when polygon is clicked', () => {
    const onSelectPolygon = jest.fn();
    render(<PolygonList imageId="image1" onSelectPolygon={onSelectPolygon} />);
    
    // Click on the first polygon
    fireEvent.click(screen.getByText('shirt').closest('.list-group-item')!);
    
    // Check if onSelectPolygon was called with the correct polygon
    expect(onSelectPolygon).toHaveBeenCalledWith(mockPolygons[0]);
  });

  test('deletes polygon when delete button is clicked', async () => {
    render(<PolygonList imageId="image1" />);
    
    // Click the first delete button
    fireEvent.click(screen.getAllByText(/Delete/i)[0]);
    
    // Confirm the delete
    expect(window.confirm).toHaveBeenCalled();
    
    // Check if delete function was called with correct id
    expect(mockDeletePolygonFn).toHaveBeenCalledWith('1');
  });

  test('does not delete polygon when confirmation is cancelled', () => {
    // Override the confirm mock to return false
    (window.confirm as jest.Mock).mockReturnValueOnce(false);
    
    render(<PolygonList imageId="image1" />);
    
    // Click the first delete button
    fireEvent.click(screen.getAllByText(/Delete/i)[0]);
    
    // Confirm the delete dialog was shown
    expect(window.confirm).toHaveBeenCalled();
    
    // But delete function should not have been called
    expect(mockDeletePolygonFn).not.toHaveBeenCalled();
  });

  test('highlights selected polygon', () => {
    render(<PolygonList imageId="image1" selectedPolygonId="2" />);
    
    // Get all list items
    const listItems = screen.getAllByRole('listitem');
    
    // The second one should have the 'active' class
    expect(listItems[1]).toHaveClass('active');
  });
});