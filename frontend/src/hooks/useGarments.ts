// /frontend/src/hooks/useGarments.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { garmentApi } from '../api/garmentApi';
import { 
  CreateGarmentInput, 
  GarmentResponse, 
  UpdateGarmentMetadata 
} from '../../../shared/src/schemas/garment';

// Fetch all garments
export const useGarments = () => {
  return useQuery({
    queryKey: ['garments'],
    queryFn: () => garmentApi.getGarments(),
  });
};

// Fetch a single garment by ID
export const useGarment = (id: string) => {
  return useQuery({
    queryKey: ['garments', id],
    queryFn: () => garmentApi.getGarment(id),
    enabled: !!id, // Only run the query if we have an ID
  });
};

// Create a new garment
export const useCreateGarment = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: CreateGarmentInput) => garmentApi.createGarment(data),
    onSuccess: (newGarment) => {
      // Update the garments list query cache
      queryClient.setQueryData<GarmentResponse[] | undefined>(
        ['garments'],
        (oldData) => oldData ? [...oldData, newGarment] : [newGarment]
      );
      
      // Add the individual garment to the cache
      queryClient.setQueryData(['garments', newGarment.id], newGarment);
    },
  });
};

// Update garment metadata
export const useUpdateGarmentMetadata = (id: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: UpdateGarmentMetadata) => garmentApi.updateGarmentMetadata(id, data),
    onSuccess: (updatedGarment) => {
      // Update the individual garment in the cache
      queryClient.setQueryData(['garments', id], updatedGarment);
      
      // Update the garment in the garments list cache
      queryClient.setQueryData<GarmentResponse[] | undefined>(
        ['garments'],
        (oldData) => oldData?.map(garment => 
          garment.id === id ? updatedGarment : garment
        )
      );
    },
  });
};

// Delete a garment
export const useDeleteGarment = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: string) => garmentApi.deleteGarment(id),
    onSuccess: (_, id) => {
      // Remove the garment from the cache
      queryClient.removeQueries({ queryKey: ['garments', id] });
      
      // Update the garments list in the cache
      queryClient.setQueryData<GarmentResponse[] | undefined>(
        ['garments'],
        (oldData) => oldData?.filter(garment => garment.id !== id)
      );
    },
  });
};