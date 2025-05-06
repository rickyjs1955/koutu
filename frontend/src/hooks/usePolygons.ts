// /frontend/src/hooks/usePolygons.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { polygonApi } from '../api/polygonApi';
import { 
  Polygon,
  CreatePolygonInput, 
  UpdatePolygonInput 
} from '../../../shared/src/schemas/polygon';

// Hook to fetch all polygons for an image
export const useImagePolygons = (imageId: string) => {
  return useQuery({
    queryKey: ['polygons', 'image', imageId],
    queryFn: () => polygonApi.getImagePolygons(imageId),
    enabled: !!imageId, // Only run the query if we have an image ID
  });
};

// Hook to fetch a single polygon
export const usePolygon = (id: string) => {
  return useQuery({
    queryKey: ['polygons', id],
    queryFn: () => polygonApi.getPolygon(id),
    enabled: !!id, // Only run the query if we have a polygon ID
  });
};

// Hook to create a new polygon
export const useCreatePolygon = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: CreatePolygonInput) => polygonApi.createPolygon(data),
    onSuccess: (newPolygon) => {
      // Update the polygons for this image in the cache
      queryClient.setQueryData<Polygon[] | undefined>(
        ['polygons', 'image', newPolygon.original_image_id],
        (oldData) => oldData ? [...oldData, newPolygon] : [newPolygon]
      );
      
      // Add the individual polygon to the cache
      queryClient.setQueryData(['polygons', newPolygon.id], newPolygon);
    },
  });
};

// Hook to update a polygon
export const useUpdatePolygon = (id: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: UpdatePolygonInput) => polygonApi.updatePolygon(id, data),
    onSuccess: (updatedPolygon) => {
      if (!updatedPolygon) return;
      
      // Update the individual polygon in the cache
      queryClient.setQueryData(['polygons', id], updatedPolygon);
      
      // Update the polygon in the image polygons list cache
      queryClient.setQueryData<Polygon[] | undefined>(
        ['polygons', 'image', updatedPolygon.original_image_id],
        (oldData) => oldData?.map(polygon => 
          polygon.id === id ? updatedPolygon : polygon
        )
      );
    },
  });
};

// Hook to delete a polygon
export const useDeletePolygon = () => {
    const queryClient = useQueryClient();
    
    return useMutation({
        mutationFn: (id: string) => polygonApi.deletePolygon(id),
        onSuccess: (_, id) => {
        // Get the polygon from the cache to find its image ID
        const polygon = queryClient.getQueryData<Polygon>(['polygons', id]);
        const imageId = polygon?.original_image_id;
        
        // Remove the polygon from the cache
        queryClient.removeQueries({ queryKey: ['polygons', id] });
        
        // If we have the image ID, update the image polygons list
        if (imageId) {
            queryClient.setQueryData<Polygon[] | undefined>(
            ['polygons', 'image', imageId],
            (oldData) => oldData?.filter(p => p.id !== id)
            );
        }
        },
    });
};