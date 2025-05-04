// /frontend/src/components/forms/GarmentForm.tsx
import React from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { 
  CreateGarmentSchema, 
  CreateGarmentInput
} from '../../../../shared/src/schemas/garment';
import { garmentApi } from '../../api/garmentApi';
import { FieldError } from 'react-hook-form';

// Define an interface for the nested error structure
interface NestedFieldError extends FieldError {
  message: string;
}

interface GarmentFormProps {
  originalImageId: string; // We'll keep the prop name in camelCase for React conventions
  maskData: {
    width: number;
    height: number;
    data: number[];
  };
  onSuccess: (garmentId: string) => void;
}

const GarmentForm: React.FC<GarmentFormProps> = ({ 
  originalImageId,
  maskData,
  onSuccess
}) => {
  const { 
    register, 
    handleSubmit, 
    formState: { errors, isSubmitting } 
  } = useForm<CreateGarmentInput>({
    resolver: zodResolver(CreateGarmentSchema),
    defaultValues: {
      // Convert camelCase props to snake_case for the schema
      original_image_id: originalImageId,
      mask_data: maskData,
      // These properties are needed by the schema but will be set by the server
      file_path: '', // Will be set by the server
      mask_path: '', // Will be set by the server
      metadata: {
        type: 'other',
        color: '',
        season: 'all'
      }
    }
  });
  
  // Explicitly type the onSubmit function to match CreateGarmentInput
  const onSubmit = async (data: CreateGarmentInput) => {
    try {
      const garment = await garmentApi.createGarment(data);
      onSuccess(garment.id as string);
    } catch (error) {
      console.error('Error creating garment:', error);
      // Handle error (show toast, etc.)
    }
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit as any)} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Garment Type
        </label>
        <select
          {...register('metadata.type')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        >
          <option value="shirt">Shirt</option>
          <option value="pants">Pants</option>
          <option value="dress">Dress</option>
          <option value="jacket">Jacket</option>
          <option value="skirt">Skirt</option>
          <option value="other">Other</option>
        </select>
        {errors.metadata?.type && (
          <p className="mt-1 text-sm text-red-600">
            {(errors.metadata.type as NestedFieldError).message}
          </p>
        )}
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Color
        </label>
        <input
          type="text"
          {...register('metadata.color')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        />
        {errors.metadata?.color && (
          <p className="mt-1 text-sm text-red-600">
            {(errors.metadata.color as NestedFieldError).message}
          </p>
        )}
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Pattern
        </label>
        <select
          {...register('metadata.pattern')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        >
          <option value="">Select a pattern (optional)</option>
          <option value="solid">Solid</option>
          <option value="striped">Striped</option>
          <option value="plaid">Plaid</option>
          <option value="floral">Floral</option>
          <option value="geometric">Geometric</option>
          <option value="other">Other</option>
        </select>
        {errors.metadata?.pattern && (
          <p className="mt-1 text-sm text-red-600">
            {(errors.metadata.pattern as NestedFieldError).message}
          </p>
        )}
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Season
        </label>
        <select
          {...register('metadata.season')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        >
          <option value="spring">Spring</option>
          <option value="summer">Summer</option>
          <option value="fall">Fall</option>
          <option value="winter">Winter</option>
          <option value="all">All Seasons</option>
        </select>
        {errors.metadata?.season && (
          <p className="mt-1 text-sm text-red-600">
            {(errors.metadata.season as NestedFieldError).message}
          </p>
        )}
      </div>
      
      <div>
        <label className="block text-sm font-medium text-gray-700">
          Brand (Optional)
        </label>
        <input
          type="text"
          {...register('metadata.brand')}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
        />
        {errors.metadata?.brand && (
          <p className="mt-1 text-sm text-red-600">
            {(errors.metadata.brand as NestedFieldError).message}
          </p>
        )}
      </div>
      
      <div>
        <button
          type="submit"
          disabled={isSubmitting}
          className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          {isSubmitting ? 'Saving...' : 'Save Garment'}
        </button>
      </div>
    </form>
  );
};

export default GarmentForm;