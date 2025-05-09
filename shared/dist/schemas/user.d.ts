import { z } from 'zod';
export declare const UserSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    password_hash: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    oauth_provider: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}>;
export declare const RegisterUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const LoginUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const UserResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    password_hash: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    oauth_provider: z.ZodOptional<z.ZodString>;
}, "password_hash">, "strip", z.ZodTypeAny, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}>;
export declare const AuthResponseSchema: z.ZodObject<{
    user: z.ZodObject<Omit<{
        id: z.ZodOptional<z.ZodString>;
        email: z.ZodString;
        name: z.ZodOptional<z.ZodString>;
        password_hash: z.ZodOptional<z.ZodString>;
        created_at: z.ZodOptional<z.ZodDate>;
        updated_at: z.ZodOptional<z.ZodDate>;
        linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        oauth_provider: z.ZodOptional<z.ZodString>;
    }, "password_hash">, "strip", z.ZodTypeAny, {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }, {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }>;
    token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
}, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
}>;
export type User = z.infer<typeof UserSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;
//# sourceMappingURL=user.d.ts.map