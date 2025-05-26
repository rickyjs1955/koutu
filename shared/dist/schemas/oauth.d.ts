import { z } from 'zod';
export declare const OAuthProviderSchema: z.ZodEnum<["google", "microsoft", "github", "instagram"]>;
export declare const OAuthUserInfoSchema: z.ZodObject<{
    id: z.ZodString;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    picture: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    id: string;
    email: string;
    name?: string | undefined;
    picture?: string | undefined;
}, {
    id: string;
    email: string;
    name?: string | undefined;
    picture?: string | undefined;
}>;
export declare const LinkedProvidersSchema: z.ZodArray<z.ZodEnum<["google", "microsoft", "github", "instagram"]>, "many">;
export type OAuthProvider = z.infer<typeof OAuthProviderSchema>;
export type OAuthUserInfo = z.infer<typeof OAuthUserInfoSchema>;
export type LinkedProviders = z.infer<typeof LinkedProvidersSchema>;
//# sourceMappingURL=oauth.d.ts.map