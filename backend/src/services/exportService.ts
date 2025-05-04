// /backend/src/services/exportService.ts
import { garmentModel } from '../models/garmentModel';
import { wardrobeModel } from '../models/wardrobeModel';
import { imageModel } from '../models/imageModel';
import fs from 'fs';
import path from 'path';
import { config } from '../config';

interface ExportedData {
  version: string;
  exportDate: string;
  userId: string;
  images: any[];
  garments: any[];
  wardrobes: any[];
  wardrobeItems: Record<string, any[]>;
}

export const exportService = {
  async exportUserData(userId: string): Promise<ExportedData> {
    // Get all user data
    const images = await imageModel.findByUserId(userId);
    const garments = await garmentModel.findByUserId(userId);
    const wardrobes = await wardrobeModel.findByUserId(userId);
    
    // Get wardrobe items
    const wardrobeItems: Record<string, any[]> = {};
    
    for (const wardrobe of wardrobes) {
      wardrobeItems[wardrobe.id] = await wardrobeModel.getGarments(wardrobe.id);
    }
    
    // Create export data structure
    const exportData: ExportedData = {
      version: '1.0',
      exportDate: new Date().toISOString(),
      userId,
      images,
      garments,
      wardrobes,
      wardrobeItems
    };
    
    return exportData;
  },
  
  async saveExportToFile(exportData: ExportedData): Promise<string> {
    // Create exports directory if it doesn't exist
    const exportsDir = path.join(config.uploadsDir, '../exports');
    if (!fs.existsSync(exportsDir)) {
      fs.mkdirSync(exportsDir, { recursive: true });
    }
    
    // Create filename with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `export_${exportData.userId}_${timestamp}.json`;
    const filePath = path.join(exportsDir, filename);
    
    // Write to file
    await fs.promises.writeFile(filePath, JSON.stringify(exportData, null, 2));
    
    return filePath;
  }
};