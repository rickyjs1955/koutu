import { z } from 'zod';
export declare const WardrobeSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
}, "strip", z.ZodTypeAny, {
    name: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    description?: string | undefined;
}, {
    name: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    description?: string | undefined;
}>;
export declare const CreateWardrobeSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
}, "id" | "created_at" | "updated_at">, "strip", z.ZodTypeAny, {
    name: string;
    description?: string | undefined;
}, {
    name: string;
    description?: string | undefined;
}>;
export declare const UpdateWardrobeSchema: z.ZodObject<{
    name: z.ZodOptional<z.ZodString>;
    description: z.ZodOptional<z.ZodOptional<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    name?: string | undefined;
    description?: string | undefined;
}, {
    name?: string | undefined;
    description?: string | undefined;
}>;
export declare const AddGarmentToWardrobeSchema: z.ZodObject<{
    garmentId: z.ZodString;
    position: z.ZodDefault<z.ZodOptional<z.ZodNumber>>;
}, "strip", z.ZodTypeAny, {
    garmentId: string;
    position: number;
}, {
    garmentId: string;
    position?: number | undefined;
}>;
export declare const WardrobeResponseSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
} & {
    garments: z.ZodOptional<z.ZodArray<z.ZodAny, "many">>;
}, "strip", z.ZodTypeAny, {
    name: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    garments?: any[] | undefined;
    description?: string | undefined;
}, {
    name: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    garments?: any[] | undefined;
    description?: string | undefined;
}>;
export type Wardrobe = z.infer<typeof WardrobeSchema>;
export type CreateWardrobeInput = z.infer<typeof CreateWardrobeSchema>;
export type UpdateWardrobeInput = z.infer<typeof UpdateWardrobeSchema>;
export type AddGarmentToWardrobeInput = z.infer<typeof AddGarmentToWardrobeSchema>;
export type WardrobeResponse = z.infer<typeof WardrobeResponseSchema>;
//# sourceMappingURL=wardrobe.d.ts.map