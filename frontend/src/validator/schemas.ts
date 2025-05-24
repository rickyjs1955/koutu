// /mobile/src/validation/schemas.ts (React Native Optimized)
import { 
  // Import lightweight schemas optimized for mobile
  CreateGarmentSchema,
  GarmentMetadataSchema,
  CreatePolygonSchema,
  CreateWardrobeSchema,
  RegisterUserSchema,
  LoginUserSchema
} from '@koutu/shared/schemas/api';

import { 
  MobileValidator,
  createValidationMiddleware,
  transformErrors,
  schemaUtils
} from '@koutu/shared/validators';

import { z } from 'zod';

// ==================== MOBILE-OPTIMIZED SCHEMAS ====================

// Lightweight garment creation (exclude heavy mask processing)
export const MobileCreateGarmentSchema = schemaUtils.pick(CreateGarmentSchema, [
  'original_image_id', 
  'metadata'
]);

// Simplified polygon creation for mobile drawing
export const MobileCreatePolygonSchema = CreatePolygonSchema.extend({
  points: z.array(z.object({
    x: z.number(),
    y: z.number()
  })).min(3).max(100) // Reduced max points for mobile performance
});

// Quick validation schemas for form fields
export const QuickValidationSchemas = {
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password too short'),
  wardrobeName: z.string().min(1, 'Name required').max(50, 'Name too long'),
  garmentColor: z.string().min(1, 'Color required').max(30, 'Color name too long'),
  garmentType: z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'other'])
};

// ==================== FORM VALIDATION HOOKS ====================

/**
 * React Hook for real-time form validation
 */
export const useFormValidation = <T>(schema: z.ZodSchema<T>) => {
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const [isValid, setIsValid] = React.useState(false);

  const validate = React.useCallback((data: unknown) => {
    const result = MobileValidator.validateLightweight(schema, data);
    
    if (result.success) {
      setErrors({});
      setIsValid(true);
      return result.data;
    } else {
      setErrors({ general: result.error || 'Validation failed' });
      setIsValid(false);
      return null;
    }
  }, [schema]);

  const validateField = React.useCallback((fieldName: string, value: unknown) => {
    try {
      // Extract field schema
      const fieldSchema = (schema as any).shape?.[fieldName];
      if (!fieldSchema) return;

      const result = MobileValidator.validateLightweight(fieldSchema, value);
      
      setErrors(prev => ({
        ...prev,
        [fieldName]: result.success ? '' : (result.error || 'Invalid')
      }));
    } catch (error) {
      console.warn('Field validation error:', error);
    }
  }, [schema]);

  const clearErrors = React.useCallback(() => {
    setErrors({});
  }, []);

  return {
    errors,
    isValid,
    validate,
    validateField,
    clearErrors
  };
};

/**
 * React Hook for offline validation queue
 */
export const useOfflineValidation = () => {
  const [queue, setQueue] = React.useState<Array<{
    id: string;
    schema: z.ZodSchema;
    data: unknown;
    timestamp: number;
  }>>([]);

  const addToQueue = React.useCallback((id: string, schema: z.ZodSchema, data: unknown) => {
    setQueue(prev => [...prev, {
      id,
      schema,
      data,
      timestamp: Date.now()
    }]);
  }, []);

  const processQueue = React.useCallback(() => {
    const results = queue.map(item => {
      const result = MobileValidator.validateLightweight(item.schema, item.data);
      return {
        ...item,
        valid: result.success,
        validatedData: result.data,
        error: result.error
      };
    });

    // Clear processed items
    setQueue([]);
    
    return results;
  }, [queue]);

  const clearQueue = React.useCallback(() => {
    setQueue([]);
  }, []);

  return {
    queue,
    addToQueue,
    processQueue,
    clearQueue,
    queueSize: queue.length
  };
};

// ==================== FORM COMPONENTS ====================

/**
 * Validated Input Component
 */
interface ValidatedInputProps {
  schema: z.ZodSchema;
  value: string;
  onChangeText: (text: string) => void;
  placeholder?: string;
  error?: string;
}

export const ValidatedInput: React.FC<ValidatedInputProps> = ({
  schema,
  value,
  onChangeText,
  placeholder,
  error: externalError
}) => {
  const [internalError, setInternalError] = React.useState<string>('');
  
  const validateInput = React.useCallback((text: string) => {
    const result = MobileValidator.validateLightweight(schema, text);
    setInternalError(result.success ? '' : (result.error || 'Invalid input'));
    onChangeText(text);
  }, [schema, onChangeText]);

  const displayError = externalError || internalError;

  return (
    <View>
      <TextInput
        value={value}
        onChangeText={validateInput}
        placeholder={placeholder}
        style={[
          styles.input,
          displayError ? styles.inputError : null
        ]}
      />
      {displayError && (
        <Text style={styles.errorText}>{displayError}</Text>
      )}
    </View>
  );
};

/**
 * Validated Form Component
 */
interface ValidatedFormProps<T> {
  schema: z.ZodSchema<T>;
  onSubmit: (data: T) => void;
  children: React.ReactNode;
}

export function ValidatedForm<T>({ 
  schema, 
  onSubmit, 
  children 
}: ValidatedFormProps<T>) {
  const [formData, setFormData] = React.useState<Partial<T>>({});
  const { errors, isValid, validate } = useFormValidation(schema);

  const handleSubmit = React.useCallback(() => {
    const validatedData = validate(formData);
    if (validatedData) {
      onSubmit(validatedData);
    }
  }, [formData, validate, onSubmit]);

  const updateField = React.useCallback((field: keyof T, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  }, []);

  return (
    <View style={styles.form}>
      {React.Children.map(children, child => {
        if (React.isValidElement(child)) {
          return React.cloneElement(child, {
            formData,
            updateField,
            errors
          });
        }
        return child;
      })}
      
      <TouchableOpacity
        style={[styles.submitButton, !isValid && styles.submitButtonDisabled]}
        onPress={handleSubmit}
        disabled={!isValid}
      >
        <Text style={styles.submitButtonText}>Submit</Text>
      </TouchableOpacity>
      
      {Object.keys(errors).length > 0 && (
        <View style={styles.errorContainer}>
          {Object.entries(errors).map(([field, error]) => (
            <Text key={field} style={styles.errorText}>
              {field}: {error}
            </Text>
          ))}
        </View>
      )}
    </View>
  );
}

// ==================== PERFORMANCE OPTIMIZATIONS ====================

/**
 * Memoized validators for expensive schemas
 */
const memoizedValidators = {
  createGarment: MobileValidator.createValidator(MobileCreateGarmentSchema),
  createPolygon: MobileValidator.createValidator(MobileCreatePolygonSchema),
  createWardrobe: MobileValidator.createValidator(CreateWardrobeSchema),
  register: MobileValidator.createValidator(RegisterUserSchema),
  login: MobileValidator.createValidator(LoginUserSchema)
};

/**
 * Batch validation for offline sync
 */
export const validateOfflineSync = {
  garments: (garments: unknown[]) => 
    MobileValidator.validateBatch(MobileCreateGarmentSchema, garments),
    
  polygons: (polygons: unknown[]) => 
    MobileValidator.validateBatch(MobileCreatePolygonSchema, polygons),
    
  wardrobes: (wardrobes: unknown[]) => 
    MobileValidator.validateBatch(CreateWardrobeSchema, wardrobes)
};

// ==================== UTILITY FUNCTIONS ====================

/**
 * Quick field validation for real-time feedback
 */
export const quickValidate = {
  email: (value: string) => 
    MobileValidator.validateLightweight(QuickValidationSchemas.email, value),
    
  password: (value: string) => 
    MobileValidator.validateLightweight(QuickValidationSchemas.password, value),
    
  wardrobeName: (value: string) => 
    MobileValidator.validateLightweight(QuickValidationSchemas.wardrobeName, value),
    
  garmentColor: (value: string) => 
    MobileValidator.validateLightweight(QuickValidationSchemas.garmentColor, value),
    
  garmentType: (value: string) => 
    MobileValidator.validateLightweight(QuickValidationSchemas.garmentType, value)
};

/**
 * Convert validation errors to user-friendly messages
 */
export const formatErrorForUser = (error: string): string => {
  const errorMappings: Record<string, string> = {
    'Invalid email format': 'Please enter a valid email address',
    'Password too short': 'Password must be at least 8 characters',
    'Name required': 'Please enter a name',
    'Invalid UUID format': 'Invalid selection',
    'Polygon must have at least 3 points': 'Please select more points',
    'Too many points': 'Selection is too complex'
  };

  return errorMappings[error] || error;
};

// ==================== STYLES ====================

const styles = StyleSheet.create({
  form: {
    padding: 16,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    padding: 12,
    fontSize: 16,
    marginBottom: 8,
  },
  inputError: {
    borderColor: '#ff0000',
  },
  errorText: {
    color: '#ff0000',
    fontSize: 12,
    marginBottom: 8,
  },
  submitButton: {
    backgroundColor: '#007AFF',
    padding: 16,
    borderRadius: 8,
    alignItems: 'center',
    marginTop: 16,
  },
  submitButtonDisabled: {
    backgroundColor: '#ccc',
  },
  submitButtonText: {
    color: 'white',
    fontSize: 16,
    fontWeight: 'bold',
  },
  errorContainer: {
    marginTop: 8,
    padding: 8,
    backgroundColor: '#ffebee',
    borderRadius: 4,
  },
});

// ==================== EXPORTS ====================

export {
  memoizedValidators,
  validateOfflineSync,
  quickValidate,
  formatErrorForUser
};

export default {
  useFormValidation,
  useOfflineValidation,
  ValidatedInput,
  ValidatedForm,
  quickValidate,
  formatErrorForUser
};