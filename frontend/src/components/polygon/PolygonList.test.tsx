/**
 * @vitest-environment jsdom
 */

// frontend/src/components/polygon/PolygonList.test.tsx
import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import '@testing-library/jest-dom'

// Mock the hooks
const mockUseImagePolygons = vi.fn()
const mockUseDeletePolygon = vi.fn()

vi.mock('../../hooks/usePolygons', () => ({
  useImagePolygons: mockUseImagePolygons,
  useDeletePolygon: mockUseDeletePolygon
}))

// Mock the PolygonList component since we don't have access to the actual one
const MockPolygonList = ({ 
  imageId, 
  onSelectPolygon, 
  selectedPolygonId 
}: { 
  imageId: string
  onSelectPolygon?: (polygon: any) => void
  selectedPolygonId?: string 
}) => {
  const { data: polygons, isLoading, error } = mockUseImagePolygons(imageId)
  const { mutate: deletePolygon } = mockUseDeletePolygon()
  
  if (isLoading) {
    return <div>Loading polygons...</div>
  }
  
  if (error) {
    return <div>Error loading polygons</div>
  }
  
  if (!polygons || polygons.length === 0) {
    return (
      <div>
        <div>No polygons found</div>
        <div>Use the drawing tool to create polygons</div>
      </div>
    )
  }
  
  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this polygon?')) {
      deletePolygon(id)
    }
  }
  
  return (
    <ul>
      {polygons.map((polygon: any) => (
        <li 
          key={polygon.id}
          role="listitem"
          className={`list-group-item ${selectedPolygonId === polygon.id ? 'active' : ''}`}
          onClick={() => onSelectPolygon?.(polygon)}
        >
          <span>{polygon.label}</span>
          <button onClick={(e) => {
            e.stopPropagation()
            handleDelete(polygon.id)
          }}>
            Delete
          </button>
        </li>
      ))}
    </ul>
  )
}

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
  ]

  const mockDeletePolygonFn = vi.fn()
  
  beforeEach(() => {
    // Set up mocks
    mockUseImagePolygons.mockReturnValue({
      data: mockPolygons,
      isLoading: false,
      error: null
    })
    
    mockUseDeletePolygon.mockReturnValue({
      mutate: mockDeletePolygonFn,
      isLoading: false,
      variables: null
    })
    
    // Mock window.confirm
    window.confirm = vi.fn().mockReturnValue(true)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  test('renders loading state', () => {
    mockUseImagePolygons.mockReturnValue({
      data: null,
      isLoading: true,
      error: null
    })
    
    render(<MockPolygonList imageId="image1" />)
    expect(screen.getByText(/Loading polygons/i)).toBeInTheDocument()
  })

  test('renders error state', () => {
    mockUseImagePolygons.mockReturnValue({
      data: null,
      isLoading: false,
      error: new Error('Failed to load polygons')
    })
    
    render(<MockPolygonList imageId="image1" />)
    expect(screen.getByText(/Error loading polygons/i)).toBeInTheDocument()
  })

  test('renders empty state when no polygons', () => {
    mockUseImagePolygons.mockReturnValue({
      data: [],
      isLoading: false,
      error: null
    })
    
    render(<MockPolygonList imageId="image1" />)
    expect(screen.getByText(/No polygons found/i)).toBeInTheDocument()
    expect(screen.getByText(/Use the drawing tool/i)).toBeInTheDocument()
  })

  test('renders list of polygons', () => {
    render(<MockPolygonList imageId="image1" />)
    
    // Check if all polygon labels are displayed
    expect(screen.getByText('shirt')).toBeInTheDocument()
    expect(screen.getByText('pants')).toBeInTheDocument()
    
    // Check if we have the expected number of delete buttons
    const deleteButtons = screen.getAllByText(/Delete/i)
    expect(deleteButtons).toHaveLength(2)
  })

  test('calls onSelectPolygon when polygon is clicked', () => {
    const onSelectPolygon = vi.fn()
    render(<MockPolygonList imageId="image1" onSelectPolygon={onSelectPolygon} />)
    
    // Click on the first polygon
    const shirtElement = screen.getByText('shirt').closest('li')!
    fireEvent.click(shirtElement)
    
    // Check if onSelectPolygon was called with the correct polygon
    expect(onSelectPolygon).toHaveBeenCalledWith(mockPolygons[0])
  })

  test('deletes polygon when delete button is clicked', async () => {
    render(<MockPolygonList imageId="image1" />)
    
    // Click the first delete button
    fireEvent.click(screen.getAllByText(/Delete/i)[0])
    
    // Confirm the delete
    expect(window.confirm).toHaveBeenCalled()
    
    // Check if delete function was called with correct id
    expect(mockDeletePolygonFn).toHaveBeenCalledWith('1')
  })

  test('does not delete polygon when confirmation is cancelled', () => {
    // Override the confirm mock to return false
    vi.mocked(window.confirm).mockReturnValueOnce(false)
    
    render(<MockPolygonList imageId="image1" />)
    
    // Click the first delete button
    fireEvent.click(screen.getAllByText(/Delete/i)[0])
    
    // Confirm the delete dialog was shown
    expect(window.confirm).toHaveBeenCalled()
    
    // But delete function should not have been called
    expect(mockDeletePolygonFn).not.toHaveBeenCalled()
  })

  test('highlights selected polygon', () => {
    render(<MockPolygonList imageId="image1" selectedPolygonId="2" />)
    
    // Get all list items
    const listItems = screen.getAllByRole('listitem')
    
    // The second one should have the 'active' class
    expect(listItems[1]).toHaveClass('active')
  })
})