import { sanitization } from '../../utils/sanitize';
import { ApiError } from '../../utils/ApiError';

// Mock dependencies
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    internal: jest.fn().mockReturnValue(new Error('Sanitized Error'))
  }
}));

describe('sanitization utilities', () => {
  let mockNext: jest.Mock;
  
  beforeEach(() => {
    jest.clearAllMocks();
    mockNext = jest.fn();
    console.error = jest.fn(); // Silence console.error in tests
  });
  
  describe('handleError', () => {
    it('should sanitize errors and call next with generic message', () => {
      const sensitiveError = new Error('Password: abc123 failed validation');
      
      sanitization.handleError(sensitiveError, 'Something went wrong', mockNext);
      
      expect(ApiError.internal).toHaveBeenCalledWith('Something went wrong');
      expect(mockNext).toHaveBeenCalled();
      expect(console.error).toHaveBeenCalledWith('Original error:', sensitiveError);
    });
  });
  
  describe('sanitizePath', () => {
    it('should convert file paths to API routes', () => {
      const result = sanitization.sanitizePath('garments', 'garment-123', 'image');
      
      expect(result).toBe('/api/garments/garment-123/image');
    });
  });
  
  describe('createSanitizedResponse', () => {
    it('should filter object to only allowed fields', () => {
      const object = {
        id: '123',
        user_id: 'user-456',
        password_hash: 'abcdef123456',
        secret_key: 'verysecret'
      };
      
      const result = sanitization.createSanitizedResponse(
        object, 
        ['id', 'user_id']
      );
      
      expect(result).toEqual({
        id: '123',
        user_id: 'user-456'
      });
      expect(result).not.toHaveProperty('password_hash');
      expect(result).not.toHaveProperty('secret_key');
    });
    
    it('should sanitize paths when pathFields are provided', () => {
      const object = {
        id: 'garment-123',
        file_path: '/var/storage/images/garment-123.jpg',
        mask_path: '/var/storage/masks/garment-123.png'
      };
      
      const result = sanitization.createSanitizedResponse(
        object,
        ['id', 'file_path', 'mask_path'],
        {
          'file_path': { resourceType: 'garments', pathType: 'image' },
          'mask_path': { resourceType: 'garments', pathType: 'mask' }
        }
      );
      
      expect(result).toEqual({
        id: 'garment-123',
        file_path: '/api/garments/garment-123/image',
        mask_path: '/api/garments/garment-123/mask'
      });
    });
  });
  
  describe('wrapController', () => {
    it('should wrap controller function in try/catch with sanitized error', async () => {
      const mockController = jest.fn().mockRejectedValue(new Error('Database connection failed'));
      const wrappedController = sanitization.wrapController(mockController, 'Controller error occurred');
      
      const mockReq = {} as any;
      const mockRes = {} as any;
      
      await wrappedController(mockReq, mockRes, mockNext);
      
      expect(mockController).toHaveBeenCalledWith(mockReq, mockRes, mockNext);
      expect(ApiError.internal).toHaveBeenCalledWith('Controller error occurred');
      expect(mockNext).toHaveBeenCalled();
    });
    
    it('should pass through successful controller execution', async () => {
      const mockController = jest.fn().mockResolvedValue(undefined);
      const wrappedController = sanitization.wrapController(mockController, 'Controller error occurred');
      
      const mockReq = {} as any;
      const mockRes = {} as any;
      
      await wrappedController(mockReq, mockRes, mockNext);
      
      expect(mockController).toHaveBeenCalledWith(mockReq, mockRes, mockNext);
      expect(ApiError.internal).not.toHaveBeenCalled();
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});