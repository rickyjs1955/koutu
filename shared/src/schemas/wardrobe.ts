// /shared/src/schemas/wardrobe.ts
import { z } from 'zod';

export const WardrobeSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(100),
  description: z.string().max(1000).optional(),
  created_at: z.date().optional(),
  updated_at: z.date().optional(),
});

export const CreateWardrobeSchema = WardrobeSchema.omit({ 
  id: true, 
  created_at: true, 
  updated_at: true 
});

export const UpdateWardrobeSchema = CreateWardrobeSchema.partial();

export const AddGarmentToWardrobeSchema = z.object({
  garmentId: z.string().uuid(),
  position: z.number().int().nonnegative().optional().default(0),
});

export const WardrobeResponseSchema = WardrobeSchema.extend({
  garments: z.array(z.any()).optional(), // This would be the GarmentSchema in practice
});

export type Wardrobe = z.infer<typeof WardrobeSchema>;
export type CreateWardrobeInput = z.infer<typeof CreateWardrobeSchema>;
export type UpdateWardrobeInput = z.infer<typeof UpdateWardrobeSchema>;
export type AddGarmentToWardrobeInput = z.infer<typeof AddGarmentToWardrobeSchema>;
export type WardrobeResponse = z.infer<typeof WardrobeResponseSchema>;