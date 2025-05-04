// /frontend/src/hooks/useImages.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { imageApi } from '../api/imageApi';
import { ImageResponse } from '../../../shared/src/schemas';

// Hook to fetch all images
export const useImages = () => {
  return useQuery({
    queryKey: ['images'],
    queryFn: () => imageApi.getImages(),
  });
};

// Hook to fetch a single image
export const useImage = (id: string) => {
  return useQuery({
    queryKey: ['images', id],
    queryFn: () => imageApi.getImage(id),
    enabled: !!id, // Only run the query if we have an ID
  });
};

// Hook to upload an image
export const useUploadImage = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (file: File) => imageApi.uploadImage(file),
    onSuccess: (newImage) => {
      // Update the images list query cache
      queryClient.setQueryData<ImageResponse[] | undefined>(
        ['images'],
        (oldData) => oldData ? [...oldData, newImage] : [newImage]
      );
      
      // Add the individual image to the cache
      queryClient.setQueryData(['images', newImage.id], newImage);
    },
  });
};

// Hook to delete an image
export const useDeleteImage = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (id: string) => imageApi.deleteImage(id),
    onSuccess: (_, id) => {
      // Remove the image from the cache
      queryClient.removeQueries({ queryKey: ['images', id] });
      
      // Update the images list in the cache
      queryClient.setQueryData<ImageResponse[] | undefined>(
        ['images'],
        (oldData) => oldData?.filter(image => image.id !== id)
      );
    },
  });
};

// Helper hook to get the image URL
export const useImageUrl = (filePath: string | undefined) => {
  if (!filePath) return '';
  return imageApi.getImageUrl(filePath);
};

// Hook to get unlabeled images (status !== 'labeled')
export const useUnlabeledImages = () => {
  const { data: images, ...rest } = useImages();
  
  const unlabeledImages = images?.filter(image => image.status !== 'labeled') || [];
  
  return {
    ...rest,
    data: unlabeledImages
  };
};