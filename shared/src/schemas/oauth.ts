// /shared/src/schemas/oauth.ts
import { z } from 'zod';

// OAuth provider schema
export const OAuthProviderSchema = z.enum([
  'google',
  'microsoft',
  'github',
  'instagram'
]);

// OAuth user info schema
export const OAuthUserInfoSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string().optional(),
  picture: z.string().optional()
});

// OAuth linked providers schema
export const LinkedProvidersSchema = z.array(OAuthProviderSchema);

// Derived TypeScript types
export type OAuthProvider = z.infer<typeof OAuthProviderSchema>;
export type OAuthUserInfo = z.infer<typeof OAuthUserInfoSchema>;
export type LinkedProviders = z.infer<typeof LinkedProvidersSchema>;