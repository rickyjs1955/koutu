// src/controllers/exportController.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { exportService } from '../services/exportService';
import path from 'path';

export const exportController = {
  async exportData(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Export user data
      const exportData = await exportService.exportUserData(req.user.id);
      
      // Return the exported data
      res.status(200).json({
        status: 'success',
        data: exportData
      });
    } catch (error) {
      next(error);
    }
  },
  
  async exportDataToFile(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Export user data
      const exportData = await exportService.exportUserData(req.user.id);
      
      // Save to file
      const filePath = await exportService.saveExportToFile(exportData);
      
      // Return the file path
      res.status(200).json({
        status: 'success',
        data: {
          message: 'Data exported successfully',
          filePath: path.basename(filePath)
        }
      });
    } catch (error) {
      next(error);
    }
  }
};