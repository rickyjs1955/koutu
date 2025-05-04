// /frontend/src/hooks/useWardrobes.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { wardrobeApi } from '../api/wardrobeApi';
import { 
  CreateWardrobeInput, 
  UpdateWardrobeInput, 
  AddGarmentToWardrobeInput, 
  Wardrobe 
} from '../../../shared/src/schemas';

// Hook to fetch all wardrobes
export const useWardrobes = () => {
  return useQuery({
    queryKey: ['wardrobes'],
    queryFn: () => wardrobeApi.getWardrobes(),
  });
};

// Hook to fetch a single wardrobe
export const useWardrobe = (id: string) => {
  return useQuery({
    queryKey: ['wardrobes', id],
    queryFn: () => wardrobeApi.getWardrobe(id),
    enabled: !!id, // Only run the query if we have an ID
  });
};

// Hook to create a new wardrobe
export const useCreateWardrobe = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: CreateWardrobeInput) => wardrobeApi.createWardrobe(data),
    onSuccess: (newWardrobe) => {
      // Update the wardrobes list query cache
      queryClient.setQueryData<Wardrobe[] | undefined>(
        ['wardrobes'],
        (oldData) => oldData ? [...oldData, newWardrobe] : [newWardrobe]
      );
      
      // Add the individual wardrobe to the cache
      queryClient.setQueryData(['wardrobes', newWardrobe.id], newWardrobe);
    },
  });
};

// Hook to update a wardrobe
export const useUpdateWardrobe = (id: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: UpdateWardrobeInput) => wardrobeApi.updateWardrobe(id, data),
    onSuccess: (updatedWardrobe) => {
      // Update the individual wardrobe in the cache
      queryClient.setQueryData(['wardrobes', id], updatedWardrobe);
      
      // Update the wardrobe in the wardrobes list cache
      queryClient.setQueryData<Wardrobe[] | undefined>(
        ['wardrobes'],
        (oldData) => oldData?.map(wardrobe => 
          wardrobe.id === id ? updatedWardrobe : wardrobe
        )
      );
    },
  });
};

// Hook to add a garment to a wardrobe
export const useAddGarmentToWardrobe = (wardrobeId: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: AddGarmentToWardrobeInput) => 
      wardrobeApi.addGarmentToWardrobe(wardrobeId, data),
    onSuccess: () => {
      // Invalidate the specific wardrobe query to refetch with the new garment
      queryClient.invalidateQueries({ queryKey: ['wardrobes', wardrobeId] });
    },
  });
};

// Hook to remove a garment from a wardrobe
export const useRemoveGarmentFromWardrobe = (wardrobeId: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (garmentId: string) => 
      wardrobeApi.removeGarmentFromWardrobe(wardrobeId, garmentId),
    onSuccess: () => {
      // Invalidate the specific wardrobe query to refetch without the removed garment
      queryClient.invalidateQueries({ queryKey: ['wardrobes', wardrobeId] });
    },
  });
};

// Hook to delete a wardrobe
export const useDeleteWardrobe = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: string) => wardrobeApi.deleteWardrobe(id),
    onSuccess: (_, id) => {
      // Remove the wardrobe from the cache
      queryClient.removeQueries({ queryKey: ['wardrobes', id] });
      
      // Update the wardrobes list in the cache
      queryClient.setQueryData<Wardrobe[] | undefined>(
        ['wardrobes'],
        (oldData) => oldData?.filter(wardrobe => wardrobe.id !== id)
      );
    },
  });
};