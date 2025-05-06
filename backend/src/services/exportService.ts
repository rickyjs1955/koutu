// backend/src/services/exportService.ts
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { ExportFormat, MLExportOptions, MLExportBatchJob } from '@koutu/shared/schemas/export';
import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { storageService } from './storageService';
import { imageProcessingService } from './imageProcessingService';
import { db } from '../models/db';
import archiver from 'archiver';
import sharp from 'sharp';

class ExportService {
  private readonly EXPORTS_PATH = path.join(__dirname, '../../exports');
  private readonly TEMP_PATH = path.join(__dirname, '../../temp');

  constructor() {
    // Ensure export and temp directories exist
    if (!fs.existsSync(this.EXPORTS_PATH)) {
      fs.mkdirSync(this.EXPORTS_PATH, { recursive: true });
    }
    if (!fs.existsSync(this.TEMP_PATH)) {
      fs.mkdirSync(this.TEMP_PATH, { recursive: true });
    }
  }

  /**
   * Export user data in various formats for machine learning
   */
  async exportMLData(userId: string, options: MLExportOptions): Promise<string> {
    const batchJobId = uuidv4();
    const batchJob: MLExportBatchJob = {
      id: batchJobId,
      userId,
      status: 'pending',
      options,
      progress: 0,
      totalItems: 0,
      processedItems: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Create batch job in database
    await this.createBatchJob(batchJob);

    // Start processing in background
    this.processMLExport(batchJob).catch(error => {
      console.error('Error processing ML export:', error);
      this.updateBatchJobStatus(batchJobId, 'failed', error.message);
    });

    return batchJobId;
  }

  /**
   * Process ML export in background
   */
  private async processMLExport(batchJob: MLExportBatchJob): Promise<void> {
    try {
      // Update status to processing
      await this.updateBatchJobStatus(batchJob.id, 'processing');

      // Create a directory for this export
      const exportDir = path.join(this.TEMP_PATH, batchJob.id);
      fs.mkdirSync(exportDir, { recursive: true });
      
      // Fetch garments based on filters
      const garments = await this.fetchFilteredGarments(
        batchJob.userId, 
        batchJob.options.garmentIds, 
        batchJob.options.categoryFilter
      );
      
      batchJob.totalItems = garments.length;
      await this.updateBatchJob(batchJob);

      // Process based on the requested format
      let outputPath: string;
      switch (batchJob.options.format) {
        case 'coco':
          outputPath = await this.exportCOCOFormat(garments, exportDir, batchJob);
          break;
        case 'yolo':
          outputPath = await this.exportYOLOFormat(garments, exportDir, batchJob);
          break;
        case 'pascal_voc':
          outputPath = await this.exportPascalVOCFormat(garments, exportDir, batchJob);
          break;
        case 'csv':
          outputPath = await this.exportCSVFormat(garments, exportDir, batchJob);
          break;
        case 'raw_json':
        default:
          outputPath = await this.exportRawJSONFormat(garments, exportDir, batchJob);
          break;
      }

      // Create a zip file of the export directory
      const zipPath = path.join(this.EXPORTS_PATH, `${batchJob.id}.zip`);
      await this.createZipArchive(exportDir, zipPath);

      // Clean up temp directory
      fs.rmSync(exportDir, { recursive: true, force: true });

      // Update batch job with completion status and output URL
      batchJob.status = 'completed';
      batchJob.progress = 100;
      batchJob.outputUrl = `/api/v1/export/download/${batchJob.id}.zip`;
      batchJob.completedAt = new Date().toISOString();
      batchJob.updatedAt = new Date().toISOString();
      await this.updateBatchJob(batchJob);
    } catch (error) {
      console.error('Error in ML export processing:', error);
      await this.updateBatchJobStatus(batchJob.id, 'failed', error.message);
      throw error;
    }
  }

  /**
   * Fetch garments with applied filters
   */
  private async fetchFilteredGarments(
    userId: string, 
    garmentIds?: string[], 
    categoryFilter?: string[]
  ) {
    let query = garmentModel.query().where('user_id', userId);
    
    if (garmentIds && garmentIds.length > 0) {
      query = query.whereIn('id', garmentIds);
    }
    
    if (categoryFilter && categoryFilter.length > 0) {
      query = query.whereIn('category', categoryFilter);
    }
    
    const garments = await query.withGraphFetched('image');
    return garments;
  }

  /**
   * Export data in COCO format (Common Objects in Context)
   * Used by many computer vision frameworks
   */
  private async exportCOCOFormat(garments, exportDir, batchJob: MLExportBatchJob): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'images');
    fs.mkdirSync(imagesDir, { recursive: true });
    
    // Initialize COCO format structure
    const cocoData = {
      info: {
        year: new Date().getFullYear(),
        version: '1.0',
        description: 'Koutu Fashion Dataset',
        contributor: 'Koutu',
        date_created: new Date().toISOString()
      },
      images: [],
      annotations: [],
      categories: []
    };
    
    // Create a map of categories
    const categoryMap = new Map();
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Add category if not exists
      if (!categoryMap.has(garment.category)) {
        const categoryId = categoryMap.size + 1;
        categoryMap.set(garment.category, categoryId);
        cocoData.categories.push({
          id: categoryId,
          name: garment.category,
          supercategory: 'garment'
        });
      }
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment.image, 
        imagesDir, 
        batchJob.options.imageFormat, 
        batchJob.options.compressionQuality
      );
      
      // Get image dimensions
      const imageMetadata = await sharp(imageFilePath).metadata();
      
      // Add image to COCO format
      const imageId = i + 1;
      cocoData.images.push({
        id: imageId,
        file_name: path.basename(imageFilePath),
        width: imageMetadata.width,
        height: imageMetadata.height,
        date_captured: garment.image.createdAt
      });
      
      // Add annotation
      cocoData.annotations.push({
        id: i + 1,
        image_id: imageId,
        category_id: categoryMap.get(garment.category),
        segmentation: [this.flattenPolygonPoints(garment.polygonPoints)],
        area: this.calculatePolygonArea(garment.polygonPoints),
        bbox: this.calculateBoundingBox(garment.polygonPoints),
        iscrowd: 0,
        attributes: garment.attributes || {}
      });
      
      // Export mask if requested
      if (batchJob.options.includeMasks) {
        const maskPath = path.join(exportDir, 'masks', `${imageId}.png`);
        fs.mkdirSync(path.dirname(maskPath), { recursive: true });
        await this.exportMaskFromPolygon(garment.polygonPoints, imageMetadata.width, imageMetadata.height, maskPath);
      }
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    // Write COCO JSON file
    const cocoFilePath = path.join(exportDir, 'annotations.json');
    fs.writeFileSync(cocoFilePath, JSON.stringify(cocoData, null, 2));
    
    return exportDir;
  }

  /**
   * Export data in YOLO format
   * Used for YOLO object detection models
   */
  private async exportYOLOFormat(garments, exportDir, batchJob: MLExportBatchJob): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'images');
    const labelsDir = path.join(exportDir, 'labels');
    fs.mkdirSync(imagesDir, { recursive: true });
    fs.mkdirSync(labelsDir, { recursive: true });
    
    // Create a map of categories and write classes.txt
    const categories = [...new Set(garments.map(g => g.category))];
    const categoryMap = new Map(categories.map((cat, idx) => [cat, idx]));
    fs.writeFileSync(
      path.join(exportDir, 'classes.txt'), 
      categories.join('\n')
    );
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment.image, 
        imagesDir, 
        batchJob.options.imageFormat, 
        batchJob.options.compressionQuality
      );
      
      // Get image dimensions for normalization
      const imageMetadata = await sharp(imageFilePath).metadata();
      const width = imageMetadata.width;
      const height = imageMetadata.height;
      
      // Calculate bounding box
      const bbox = this.calculateBoundingBox(garment.polygonPoints);
      
      // Convert to YOLO format: <class> <x_center> <y_center> <width> <height>
      // Where all values are normalized to [0, 1]
      const x_center = (bbox[0] + bbox[2] / 2) / width;
      const y_center = (bbox[1] + bbox[3] / 2) / height;
      const bbox_width = bbox[2] / width;
      const bbox_height = bbox[3] / height;
      
      // Create label file
      const categoryId = categoryMap.get(garment.category);
      const labelContent = `${categoryId} ${x_center} ${y_center} ${bbox_width} ${bbox_height}`;
      
      // Write label file with same name as image but .txt extension
      const baseName = path.basename(imageFilePath, path.extname(imageFilePath));
      fs.writeFileSync(path.join(labelsDir, `${baseName}.txt`), labelContent);
      
      // If polygon points are requested, save them separately
      if (batchJob.options.includeRawPolygons) {
        const polygonsDir = path.join(exportDir, 'polygons');
        fs.mkdirSync(polygonsDir, { recursive: true });
        
        // Normalize polygon points to [0, 1]
        const normalizedPoints = garment.polygonPoints.map(p => ({
          x: p.x / width,
          y: p.y / height
        }));
        
        fs.writeFileSync(
          path.join(polygonsDir, `${baseName}.json`), 
          JSON.stringify(normalizedPoints, null, 2)
        );
      }
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    return exportDir;
  }

  /**
   * Export data in Pascal VOC format
   * Used for object detection and segmentation
   */
  private async exportPascalVOCFormat(garments, exportDir, batchJob: MLExportBatchJob): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'JPEGImages');
    const annotationsDir = path.join(exportDir, 'Annotations');
    const segmentationDir = path.join(exportDir, 'SegmentationClass');
    const imageSetDir = path.join(exportDir, 'ImageSets', 'Main');
    
    fs.mkdirSync(imagesDir, { recursive: true });
    fs.mkdirSync(annotationsDir, { recursive: true });
    fs.mkdirSync(segmentationDir, { recursive: true });
    fs.mkdirSync(imageSetDir, { recursive: true });
    
    // Create a map of categories
    const categories = [...new Set(garments.map(g => g.category))];
    
    // Create imagesets for each category
    const categoryImages = {};
    categories.forEach(cat => {
      categoryImages[cat] = [];
    });
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment.image, 
        imagesDir, 
        batchJob.options.imageFormat === 'jpg' ? 'jpg' : 'png', // VOC uses jpg or png
        batchJob.options.compressionQuality
      );
      
      const baseName = path.basename(imageFilePath, path.extname(imageFilePath));
      
      // Add to category image list
      categoryImages[garment.category].push(baseName);
      
      // Get image dimensions
      const imageMetadata = await sharp(imageFilePath).metadata();
      const width = imageMetadata.width;
      const height = imageMetadata.height;
      
      // Create XML annotation file
      const xmlContent = this.createPascalVOCXML(
        baseName,
        width,
        height,
        garment.category,
        this.calculateBoundingBox(garment.polygonPoints),
        garment.polygonPoints
      );
      
      fs.writeFileSync(path.join(annotationsDir, `${baseName}.xml`), xmlContent);
      
      // Create segmentation mask if requested
      if (batchJob.options.includeMasks) {
        await this.exportMaskFromPolygon(
          garment.polygonPoints, 
          width, 
          height, 
          path.join(segmentationDir, `${baseName}.png`)
        );
      }
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    // Write imagesets files
    const allImages = [];
    categories.forEach(category => {
      const images = categoryImages[category];
      allImages.push(...images);
      
      // Write positive examples
      fs.writeFileSync(
        path.join(imageSetDir, `${category}_train.txt`),
        images.slice(0, Math.floor(images.length * 0.8)).join('\n')
      );
      
      // Write test examples
      fs.writeFileSync(
        path.join(imageSetDir, `${category}_test.txt`),
        images.slice(Math.floor(images.length * 0.8)).join('\n')
      );
    });
    
    // Write all trainval examples
    fs.writeFileSync(
      path.join(imageSetDir, 'trainval.txt'),
      allImages.join('\n')
    );
    
    return exportDir;
  }

  /**
   * Export data in raw JSON format
   * Custom format with all data
   */
  private async exportRawJSONFormat(garments, exportDir, batchJob: MLExportBatchJob): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'images');
    fs.mkdirSync(imagesDir, { recursive: true });
    
    const masksDir = path.join(exportDir, 'masks');
    if (batchJob.options.includeMasks) {
      fs.mkdirSync(masksDir, { recursive: true });
    }
    
    // Initialize data structure
    const dataset = {
      info: {
        description: 'Koutu Fashion Dataset - Raw JSON Format',
        createdAt: new Date().toISOString(),
        totalGarments: garments.length,
        format: 'raw_json'
      },
      garments: []
    };
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment.image, 
        imagesDir, 
        batchJob.options.imageFormat, 
        batchJob.options.compressionQuality
      );
      
      // Get image dimensions
      const imageMetadata = await sharp(imageFilePath).metadata();
      const width = imageMetadata.width;
      const height = imageMetadata.height;
      
      // Calculate bounding box
      const bbox = this.calculateBoundingBox(garment.polygonPoints);
      
      // Create garment entry
      const garmentEntry = {
        id: garment.id,
        imageFile: path.basename(imageFilePath),
        category: garment.category,
        attributes: garment.attributes || {},
        imageWidth: width,
        imageHeight: height,
        boundingBox: {
          x: bbox[0],
          y: bbox[1],
          width: bbox[2],
          height: bbox[3]
        },
        polygonPoints: garment.polygonPoints
      };
      
      // Add mask file reference if requested
      if (batchJob.options.includeMasks) {
        const maskPath = path.join(masksDir, `${garment.id}.png`);
        await this.exportMaskFromPolygon(garment.polygonPoints, width, height, maskPath);
        garmentEntry['maskFile'] = `masks/${garment.id}.png`;
      }
      
      dataset.garments.push(garmentEntry);
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    // Write dataset JSON file
    fs.writeFileSync(
      path.join(exportDir, 'dataset.json'),
      JSON.stringify(dataset, null, 2)
    );
    
    // Create Python loader script
    this.createPythonLoaderScript(exportDir, 'raw_json');
    
    return exportDir;
  }

  /**
   * Export data in CSV format
   * Simple tabular format for analysis
   */
  private async exportCSVFormat(garments, exportDir, batchJob: MLExportBatchJob): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'images');
    fs.mkdirSync(imagesDir, { recursive: true });
    
    // Prepare CSV headers
    let csvContent = 'garment_id,image_file,category,width,height,bounding_box_x,bounding_box_y,bounding_box_width,bounding_box_height,polygon_points\n';
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment.image, 
        imagesDir, 
        batchJob.options.imageFormat, 
        batchJob.options.compressionQuality
      );
      
      // Get image dimensions
      const imageMetadata = await sharp(imageFilePath).metadata();
      const width = imageMetadata.width;
      const height = imageMetadata.height;
      
      // Calculate bounding box
      const bbox = this.calculateBoundingBox(garment.polygonPoints);
      
      // Format polygon points as a string
      const polygonString = JSON.stringify(garment.polygonPoints);
      
      // Add CSV row
      csvContent += `${garment.id},${path.basename(imageFilePath)},${garment.category},${width},${height},${bbox[0]},${bbox[1]},${bbox[2]},${bbox[3]},${polygonString.replace(/,/g, ';')}\n`;
      
      // Export mask if requested
      if (batchJob.options.includeMasks) {
        const masksDir = path.join(exportDir, 'masks');
        fs.mkdirSync(masksDir, { recursive: true });
        await this.exportMaskFromPolygon(
          garment.polygonPoints, 
          width, 
          height, 
          path.join(masksDir, `${garment.id}.png`)
        );
      }
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    // Write CSV file
    fs.writeFileSync(path.join(exportDir, 'dataset.csv'), csvContent);
    
    // Create Python loader script
    this.createPythonLoaderScript(exportDir, 'csv');
    
    return exportDir;
  }

  /**
   * Generate a Python loader script based on the format
   */
  private createPythonLoaderScript(exportDir: string, format: ExportFormat): void {
    let scriptContent = '';
    
    switch (format) {
      case 'coco':
        scriptContent = `
import json
import os
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from pycocotools.coco import COCO

def load_koutu_dataset(dataset_dir):
    """
    Load Koutu dataset in COCO format
    
    Args:
        dataset_dir: Directory containing the exported dataset
        
    Returns:
        coco: COCO API object
    """
    annotation_file = os.path.join(dataset_dir, 'annotations.json')
    coco = COCO(annotation_file)
    return coco

def display_sample(coco, img_id=None):
    """
    Display a sample image with annotations
    
    Args:
        coco: COCO API object
        img_id: Image ID to display, random if None
    """
    # Get image ID if not provided
    if img_id is None:
        img_ids = list(coco.imgs.keys())
        img_id = np.random.choice(img_ids)
    
    # Load image
    img_data = coco.loadImgs(img_id)[0]
    image_path = os.path.join(os.path.dirname(coco.annotation_file), 'images', img_data['file_name'])
    img = np.array(Image.open(image_path))
    
    # Plot image
    plt.figure(figsize=(10, 10))
    plt.imshow(img)
    
    # Load and plot annotations
    ann_ids = coco.getAnnIds(imgIds=img_id)
    anns = coco.loadAnns(ann_ids)
    coco.showAnns(anns)
    
    plt.axis('off')
    plt.title(f"Image ID: {img_id}")
    plt.show()

# Example usage
if __name__ == "__main__":
    # Update this path to your dataset directory
    dataset_dir = '.'
    
    # Load dataset
    coco = load_koutu_dataset(dataset_dir)
    
    # Print dataset info
    cats = coco.loadCats(coco.getCatIds())
    print(f"Categories: {cats}")
    print(f"Total images: {len(coco.imgs)}")
    print(f"Total annotations: {len(coco.anns)}")
    
    # Display a random sample
    display_sample(coco)
"""

    elif format == 'yolo':
        scriptContent = """
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image
import json

def load_koutu_dataset(dataset_dir):
    """
    Load Koutu dataset in YOLO format
    
    Args:
        dataset_dir: Directory containing the exported dataset
        
    Returns:
        classes: List of class names
        images_dir: Path to images directory
        labels_dir: Path to labels directory
        polygons_dir: Path to polygons directory (if available)
    """
    classes_file = os.path.join(dataset_dir, 'classes.txt')
    with open(classes_file, 'r') as f:
        classes = [line.strip() for line in f.readlines()]
    
    images_dir = os.path.join(dataset_dir, 'images')
    labels_dir = os.path.join(dataset_dir, 'labels')
    polygons_dir = os.path.join(dataset_dir, 'polygons')
    
    if not os.path.exists(polygons_dir):
        polygons_dir = None
    
    return classes, images_dir, labels_dir, polygons_dir

def display_sample(classes, images_dir, labels_dir, polygons_dir=None, img_file=None):
    """
    Display a sample image with annotations
    
    Args:
        classes: List of class names
        images_dir: Path to images directory
        labels_dir: Path to labels directory
        polygons_dir: Path to polygons directory (if available)
        img_file: Image filename to display, random if None
    """
    # Get image file if not provided
    if img_file is None:
        img_files = [f for f in os.listdir(images_dir) if f.endswith(('.jpg', '.png'))]
        if not img_files:
            print("No images found")
            return
        img_file = np.random.choice(img_files)
    
    # Load image
    image_path = os.path.join(images_dir, img_file)
    img = np.array(Image.open(image_path))
    height, width = img.shape[:2]
    
    # Load label
    base_name = os.path.splitext(img_file)[0]
    label_path = os.path.join(labels_dir, f"{base_name}.txt")
    
    # Plot image
    fig, ax = plt.subplots(1, figsize=(10, 10))
    ax.imshow(img)
    
    # Load and plot annotations
    if os.path.exists(label_path):
        with open(label_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                class_id = int(parts[0])
                x_center = float(parts[1]) * width
                y_center = float(parts[2]) * height
                bbox_width = float(parts[3]) * width
                bbox_height = float(parts[4]) * height
                
                # Create rectangle patch
                rect = patches.Rectangle(
                    (x_center - bbox_width/2, y_center - bbox_height/2),
                    bbox_width, bbox_height,
                    linewidth=2, edgecolor='r', facecolor='none'
                )
                ax.add_patch(rect)
                
                # Add label
                class_name = classes[class_id] if class_id < len(classes) else f"Class {class_id}"
                ax.text(
                    x_center - bbox_width/2, y_center - bbox_height/2 - 5,
                    class_name,
                    color='white', fontsize=12, backgroundcolor='red'
                )
    
    # Plot polygon if available
    if polygons_dir:
        polygon_path = os.path.join(polygons_dir, f"{base_name}.json")
        if os.path.exists(polygon_path):
            with open(polygon_path, 'r') as f:
                points = json.load(f)
                # Denormalize points
                points = [(p['x'] * width, p['y'] * height) for p in points]
                # Draw polygon
                poly = plt.Polygon(points, fill=False, edgecolor='g', linewidth=2)
                ax.add_patch(poly)
    
    ax.axis('off')
    ax.set_title(f"Image: {img_file}")
    plt.tight_layout()
    plt.show()

# Example usage
if __name__ == "__main__":
    # Update this path to your dataset directory
    dataset_dir = '.'
    
    # Load dataset
    classes, images_dir, labels_dir, polygons_dir = load_koutu_dataset(dataset_dir)
    
    # Print dataset info
    print(f"Classes: {classes}")
    print(f"Total images: {len([f for f in os.listdir(images_dir) if f.endswith(('.jpg', '.png'))])}")
    
    # Display a random sample
    display_sample(classes, images_dir, labels_dir, polygons_dir)
"""

    elif format == 'pascal_voc':
        scriptContent = """
import os
import numpy as np
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image
import random

def load_koutu_dataset(dataset_dir):
    """
    Load Koutu dataset in Pascal VOC format
    
    Args:
        dataset_dir: Directory containing the exported dataset
        
    Returns:
        images_dir: Path to images directory
        annotations_dir: Path to annotations directory
        segmentation_dir: Path to segmentation directory (if available)
        imagesets_dir: Path to imagesets directory
    """
    images_dir = os.path.join(dataset_dir, 'JPEGImages')
    annotations_dir = os.path.join(dataset_dir, 'Annotations')
    segmentation_dir = os.path.join(dataset_dir, 'SegmentationClass')
    imagesets_dir = os.path.join(dataset_dir, 'ImageSets', 'Main')
    
    if not os.path.exists(segmentation_dir):
        segmentation_dir = None
    
    return images_dir, annotations_dir, segmentation_dir, imagesets_dir

def get_categories(annotations_dir):
    """
    Get unique categories from annotations
    
    Args:
        annotations_dir: Path to annotations directory
        
    Returns:
        categories: List of unique categories
    """
    categories = set()
    for xml_file in os.listdir(annotations_dir):
        if not xml_file.endswith('.xml'):
            continue
        
        tree = ET.parse(os.path.join(annotations_dir, xml_file))
        root = tree.getroot()
        
        for obj in root.findall('./object'):
            name = obj.find('name').text
            categories.add(name)
    
    return sorted(list(categories))

def display_sample(images_dir, annotations_dir, segmentation_dir=None, img_file=None):
    """
    Display a sample image with annotations
    
    Args:
        images_dir: Path to images directory
        annotations_dir: Path to annotations directory
        segmentation_dir: Path to segmentation directory (if available)
        img_file: Image filename to display, random if None
    """
    # Get image file if not provided
    if img_file is None:
        img_files = [f for f in os.listdir(images_dir) if f.endswith(('.jpg', '.png'))]
        if not img_files:
            print("No images found")
            return
        img_file = random.choice(img_files)
    
    # Load image
    image_path = os.path.join(images_dir, img_file)
    img = np.array(Image.open(image_path))
    
    # Load annotation
    base_name = os.path.splitext(img_file)[0]
    xml_path = os.path.join(annotations_dir, f"{base_name}.xml")
    
    # Set up subplots
    n_plots = 2 if segmentation_dir and os.path.exists(os.path.join(segmentation_dir, f"{base_name}.png")) else 1
    fig, axes = plt.subplots(1, n_plots, figsize=(15, 10) if n_plots > 1 else (10, 10))
    
    if n_plots == 1:
        axes = [axes]
    
    # Plot original image with bounding boxes
    axes[0].imshow(img)
    
    # Load and plot annotations
    if os.path.exists(xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        for obj in root.findall('./object'):
            name = obj.find('name').text
            bndbox = obj.find('bndbox')
            xmin = int(bndbox.find('xmin').text)
            ymin = int(bndbox.find('ymin').text)
            xmax = int(bndbox.find('xmax').text)
            ymax = int(bndbox.find('ymax').text)
            
            # Create rectangle patch
            rect = patches.Rectangle(
                (xmin, ymin), xmax - xmin, ymax - ymin,
                linewidth=2, edgecolor='r', facecolor='none'
            )
            axes[0].add_patch(rect)
            
            # Add label
            axes[0].text(
                xmin, ymin - 5, name,
                color='white', fontsize=12, backgroundcolor='red'
            )
            
            # Draw polygon if available
            polygon = obj.find('polygon')
            if polygon is not None:
                points = []
                for pt in polygon.findall('./pt'):
                    x = int(pt.find('x').text)
                    y = int(pt.find('y').text)
                    points.append((x, y))
                
                if points:
                    poly = plt.Polygon(points, fill=False, edgecolor='g', linewidth=2)
                    axes[0].add_patch(poly)
    
    axes[0].axis('off')
    axes[0].set_title(f"Image: {img_file}")
    
    # Plot segmentation mask if available
    if n_plots > 1:
        mask_path = os.path.join(segmentation_dir, f"{base_name}.png")
        mask = np.array(Image.open(mask_path))
        axes[1].imshow(mask)
        axes[1].axis('off')
        axes[1].set_title(f"Segmentation Mask: {base_name}.png")
    
    plt.tight_layout()
    plt.show()

# Example usage
if __name__ == "__main__":
    # Update this path to your dataset directory
    dataset_dir = '.'
    
    # Load dataset
    images_dir, annotations_dir, segmentation_dir, imagesets_dir = load_koutu_dataset(dataset_dir)
    
    # Get categories
    categories = get_categories(annotations_dir)
    
    # Print dataset info
    print(f"Categories: {categories}")
    print(f"Total images: {len([f for f in os.listdir(images_dir) if f.endswith(('.jpg', '.png'))])}")
    
    # Display a random sample
    display_sample(images_dir, annotations_dir, segmentation_dir)
"""

    elif format == 'csv':
        scriptContent = """
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image
import json
import ast

def load_koutu_dataset(dataset_dir):
    """
    Load Koutu dataset in CSV format
    
    Args:
        dataset_dir: Directory containing the exported dataset
        
    Returns:
        df: Pandas DataFrame with dataset information
        images_dir: Path to images directory
        masks_dir: Path to masks directory (if available)
    """
    csv_file = os.path.join(dataset_dir, 'dataset.csv')
    df = pd.read_csv(csv_file)
    
    # Convert polygon points string to list of dicts
    df['polygon_points'] = df['polygon_points'].apply(
        lambda x: ast.literal_eval(x.replace(';', ',')) if isinstance(x, str) else x
    )
    
    images_dir = os.path.join(dataset_dir, 'images')
    masks_dir = os.path.join(dataset_dir, 'masks')
    
    if not os.path.exists(masks_dir):
        masks_dir = None
    
    return df, images_dir, masks_dir

def display_sample(df, images_dir, masks_dir=None, idx=None):
    """
    Display a sample image with annotations
    
    Args:
        df: Pandas DataFrame with dataset information
        images_dir: Path to images directory
        masks_dir: Path to masks directory (if available)
        idx: Index in DataFrame to display, random if None
    """
    # Get row if index not provided
    if idx is None:
        idx = np.random.randint(len(df))
    
    row = df.iloc[idx]
    
    # Load image
    image_path = os.path.join(images_dir, row['image_file'])
    img = np.array(Image.open(image_path))
    
    # Set up subplots
    n_plots = 2 if masks_dir and os.path.exists(os.path.join(masks_dir, f"{row['garment_id']}.png")) else 1
    fig, axes = plt.subplots(1, n_plots, figsize=(15, 10) if n_plots > 1 else (10, 10))
    
    if n_plots == 1:
        axes = [axes]
    
    # Plot original image with bounding box
    axes[0].imshow(img)
    
    # Draw bounding box
    rect = patches.Rectangle(
        (row['bounding_box_x'], row['bounding_box_y']),
        row['bounding_box_width'], row['bounding_box_height'],
        linewidth=2, edgecolor='r', facecolor='none'
    )
    axes[0].add_patch(rect)
    
    # Add label
    axes[0].text(
        row['bounding_box_x'], row['bounding_box_y'] - 5,
        row['category'],
        color='white', fontsize=12, backgroundcolor='red'
    )
    
    # Draw polygon
    if row['polygon_points'] and len(row['polygon_points']) > 0:
        points = [(p['x'], p['y']) for p in row['polygon_points']]
        poly = plt.Polygon(points, fill=False, edgecolor='g', linewidth=2)
        axes[0].add_patch(poly)
    
    axes[0].axis('off')
    axes[0].set_title(f"Image: {row['image_file']}")
    
    # Plot mask if available
    if n_plots > 1:
        mask_path = os.path.join(masks_dir, f"{row['garment_id']}.png")
        mask = np.array(Image.open(mask_path))
        axes[1].imshow(mask)
        axes[1].axis('off')
        axes[1].set_title(f"Segmentation Mask: {row['garment_id']}.png")
    
    plt.tight_layout()
    plt.show()

# Example usage
if __name__ == "__main__":
    # Update this path to your dataset directory
    dataset_dir = '.'
    
    # Load dataset
    df, images_dir, masks_dir = load_koutu_dataset(dataset_dir)
    
    # Print dataset info
    print(f"Total garments: {len(df)}")
    print(f"Categories: {df['category'].unique()}")
    
    # Display statistics
    print("\nCategory distribution:")
    print(df['category'].value_counts())
    
    # Display a random sample
    display_sample(df, images_dir, masks_dir)
"""

    else:  // Default raw_json format
        scriptContent = """
import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image
import random

def load_koutu_dataset(dataset_dir):
    """
    Load Koutu dataset in raw JSON format
    
    Args:
        dataset_dir: Directory containing the exported dataset
        
    Returns:
        dataset: Dictionary containing dataset information
        images_dir: Path to images directory
        masks_dir: Path to masks directory (if available)
    """
    json_file = os.path.join(dataset_dir, 'dataset.json')
    with open(json_file, 'r') as f:
        dataset = json.load(f)
    
    images_dir = os.path.join(dataset_dir, 'images')
    masks_dir = os.path.join(dataset_dir, 'masks')
    
    if not os.path.exists(masks_dir):
        masks_dir = None
    
    return dataset, images_dir, masks_dir

def display_sample(dataset, images_dir, masks_dir=None, garment_idx=None):
    """
    Display a sample image with annotations
    
    Args:
        dataset: Dictionary containing dataset information
        images_dir: Path to images directory
        masks_dir: Path to masks directory (if available)
        garment_idx: Index in dataset to display, random if None
    """
    # Get garment if index not provided
    garments = dataset['garments']
    if garment_idx is None:
        garment_idx = random.randint(0, len(garments) - 1)
    
    garment = garments[garment_idx]
    
    # Load image
    image_path = os.path.join(images_dir, garment['imageFile'])
    img = np.array(Image.open(image_path))
    
    # Set up subplots
    has_mask = masks_dir and 'maskFile' in garment and os.path.exists(os.path.join(dataset_dir, garment['maskFile']))
    n_plots = 2 if has_mask else 1
    fig, axes = plt.subplots(1, n_plots, figsize=(15, 10) if n_plots > 1 else (10, 10))
    
    if n_plots == 1:
        axes = [axes]
    
    # Plot original image with bounding box
    axes[0].imshow(img)
    
    # Draw bounding box
    bbox = garment['boundingBox']
    rect = patches.Rectangle(
        (bbox['x'], bbox['y']), bbox['width'], bbox['height'],
        linewidth=2, edgecolor='r', facecolor='none'
    )
    axes[0].add_patch(rect)
    
    # Add label
    axes[0].text(
        bbox['x'], bbox['y'] - 5,
        garment['category'],
        color='white', fontsize=12, backgroundcolor='red'
    )
    
    # Draw polygon
    if 'polygonPoints' in garment and len(garment['polygonPoints']) > 0:
        points = [(p['x'], p['y']) for p in garment['polygonPoints']]
        poly = plt.Polygon(points, fill=False, edgecolor='g', linewidth=2)
        axes[0].add_patch(poly)
    
    axes[0].axis('off')
    axes[0].set_title(f"Image: {garment['imageFile']}")
    
    # Plot mask if available
    if n_plots > 1:
        mask_path = os.path.join(dataset_dir, garment['maskFile'])
        mask = np.array(Image.open(mask_path))
        axes[1].imshow(mask)
        axes[1].axis('off')
        axes[1].set_title(f"Segmentation Mask")
    
    plt.tight_layout()
    plt.show()

# Example usage
if __name__ == "__main__":
    # Update this path to your dataset directory
    dataset_dir = '.'
    
    # Load dataset
    dataset, images_dir, masks_dir = load_koutu_dataset(dataset_dir)
    
    # Print dataset info
    print(f"Dataset description: {dataset['info']['description']}")
    print(f"Total garments: {len(dataset['garments'])}")
    
    # Count categories
    categories = {}
    for garment in dataset['garments']:
        cat = garment['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    print("\nCategory distribution:")
    for cat, count in categories.items():
        print(f"{cat}: {count}")
    
    # Display a random sample
    display_sample(dataset, images_dir, masks_dir)
"""
    
    // Write the Python script
    fs.writeFileSync(path.join(exportDir, 'load_dataset.py'), scriptContent);
  }

  /**
   * Create a ZIP archive from a directory
   */
  private async createZipArchive(sourceDir: string, outputPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(outputPath);
      const archive = archiver('zip', {
        zlib: { level: 9 } // Maximum compression
      });
      
      output.on('close', () => {
        resolve();
      });
      
      archive.on('error', (err) => {
        reject(err);
      });
      
      archive.pipe(output);
      archive.directory(sourceDir, false);
      archive.finalize();
    });
  }

  /**
   * Calculate polygon area using Shoelace formula
   */
  private calculatePolygonArea(points: Array<{x: number, y: number}>): number {
    if (points.length < 3) return 0;
    
    let area = 0;
    for (let i = 0; i < points.length; i++) {
      const j = (i + 1) % points.length;
      area += points[i].x * points[j].y;
      area -= points[j].x * points[i].y;
    }
    
    return Math.abs(area / 2);
  }

  /**
   * Calculate bounding box from polygon points
   * Returns [x, y, width, height]
   */
  private calculateBoundingBox(points: Array<{x: number, y: number}>): [number, number, number, number] {
    if (points.length === 0) return [0, 0, 0, 0];
    
    let minX = points[0].x;
    let minY = points[0].y;
    let maxX = points[0].x;
    let maxY = points[0].y;
    
    for (let i = 1; i < points.length; i++) {
      const point = points[i];
      minX = Math.min(minX, point.x);
      minY = Math.min(minY, point.y);
      maxX = Math.max(maxX, point.x);
      maxY = Math.max(maxY, point.y);
    }
    
    return [minX, minY, maxX - minX, maxY - minY];
  }

  /**
   * Flatten polygon points for COCO format
   */
  private flattenPolygonPoints(points: Array<{x: number, y: number}>): number[] {
    const result = [];
    for (const point of points) {
      result.push(point.x, point.y);
    }
    return result;
  }

  /**
   * Create a Pascal VOC XML annotation file content
   */
  private createPascalVOCXML(
    filename: string,
    width: number,
    height: number,
    category: string,
    bbox: [number, number, number, number],
    polygonPoints: Array<{x: number, y: number}>
  ): string {
    const [xmin, ymin, w, h] = bbox;
    const xmax = xmin + w;
    const ymax = ymin + h;
    
    let xml = `<?xml version="1.0" encoding="UTF-8"?>
<annotation>
    <folder>JPEGImages</folder>
    <filename>${filename}</filename>
    <size>
        <width>${width}</width>
        <height>${height}</height>
        <depth>3</depth>
    </size>
    <segmented>1</segmented>
    <object>
        <name>${category}</name>
        <pose>Unspecified</pose>
        <truncated>0</truncated>
        <difficult>0</difficult>
        <bndbox>
            <xmin>${Math.round(xmin)}</xmin>
            <ymin>${Math.round(ymin)}</ymin>
            <xmax>${Math.round(xmax)}</xmax>
            <ymax>${Math.round(ymax)}</ymax>
        </bndbox>`;
        
    // Add polygon points if available
    if (polygonPoints && polygonPoints.length > 0) {
      xml += '\n        <polygon>\n';
      for (const point of polygonPoints) {
        xml += `            <pt>
                <x>${Math.round(point.x)}</x>
                <y>${Math.round(point.y)}</y>
            </pt>\n`;
      }
      xml += '        </polygon>';
    }
    
    xml += '\n    </object>\n</annotation>';
    
    return xml;
  }

  /**
   * Create a binary mask image from polygon points
   */
  private async exportMaskFromPolygon(
    points: Array<{x: number, y: number}>,
    width: number,
    height: number,
    outputPath: string
  ): Promise<void> {
    // Ensure directory exists
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    
    // Create an SVG path from the polygon points
    let svgPath = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">`;
    svgPath += '<path d="';
    
    for (let i = 0; i < points.length; i++) {
      const prefix = i === 0 ? 'M' : 'L';
      svgPath += `${prefix}${points[i].x},${points[i].y} `;
    }
    
    svgPath += 'Z" fill="white" /></svg>';
    
    // Use sharp to create a mask image
    await sharp(Buffer.from(svgPath))
      .toFormat('png')
      .toFile(outputPath);
  }

  /**
   * Copy and prepare image for export
   */
  private async prepareImageForExport(
    image: any,
    outputDir: string,
    format: string = 'jpg',
    quality: number = 90
  ): Promise<string> {
    // Generate output filename
    const outputExt = format === 'jpg' ? 'jpg' : 'png';
    const outputFilename = `${image.id}.${outputExt}`;
    const outputPath = path.join(outputDir, outputFilename);
    
    // Get image buffer from storage
    const imageBuffer = await storageService.getFile(image.path);
    
    // Process the image
    if (format === 'jpg') {
      await sharp(imageBuffer)
        .jpeg({ quality })
        .toFile(outputPath);
    } else {
      await sharp(imageBuffer)
        .png({ quality: quality / 100 * 9 }) // PNG quality is 0-9
        .toFile(outputPath);
    }
    
    return outputPath;
  }

  /**
   * Create a batch job in the database
   */
  private async createBatchJob(batchJob: MLExportBatchJob): Promise<void> {
    await db.table('export_batch_jobs').insert({
      id: batchJob.id,
      user_id: batchJob.userId,
      status: batchJob.status,
      options: JSON.stringify(batchJob.options),
      progress: batchJob.progress,
      total_items: batchJob.totalItems,
      processed_items: batchJob.processedItems,
      created_at: batchJob.createdAt,
      updated_at: batchJob.updatedAt
    });
  }

  /**
   * Update batch job status in the database
   */
  private async updateBatchJobStatus(batchJobId: string, status: string, errorMessage?: string): Promise<void> {
    const updates: any = {
      status,
      updated_at: new Date().toISOString()
    };
    
    if (status === 'completed') {
      updates.completed_at = new Date().toISOString();
    }
    
    if (errorMessage) {
      updates.error = errorMessage;
    }
    
    await db.table('export_batch_jobs')
      .where('id', batchJobId)
      .update(updates);
  }

  /**
   * Update batch job in the database
   */
  private async updateBatchJob(batchJob: MLExportBatchJob): Promise<void> {
    await db.table('export_batch_jobs')
      .where('id', batchJob.id)
      .update({
        status: batchJob.status,
        progress: batchJob.progress,
        total_items: batchJob.totalItems,
        processed_items: batchJob.processedItems,
        output_url: batchJob.outputUrl,
        error: batchJob.error,
        updated_at: batchJob.updatedAt,
        completed_at: batchJob.completedAt
      });
  }

  /**
   * Get batch job by ID
   */
  async getBatchJob(batchJobId: string): Promise<MLExportBatchJob | null> {
    const job = await db.table('export_batch_jobs')
      .where('id', batchJobId)
      .first();
    
    if (!job) return null;
    
    return {
      id: job.id,
      userId: job.user_id,
      status: job.status,
      options: JSON.parse(job.options),
      progress: job.progress,
      totalItems: job.total_items,
      processedItems: job.processed_items,
      outputUrl: job.output_url,
      error: job.error,
      createdAt: job.created_at,
      updatedAt: job.updated_at,
      completedAt: job.completed_at
    }));
  }

  /**
   * Get dataset statistics for ML
   */
  async getDatasetStats(userId: string): Promise<any> {
    // Get all garments for the user
    const garments = await garmentModel.query()
      .where('user_id', userId)
      .withGraphFetched('image');
    
    if (!garments || garments.length === 0) {
      return {
        totalImages: 0,
        totalGarments: 0,
        categoryCounts: {},
        attributeCounts: {},
        averagePolygonPoints: 0
      };
    }
    
    // Count unique images
    const uniqueImageIds = new Set(garments.map(g => g.image_id));
    
    // Count categories
    const categoryCounts = {};
    garments.forEach(g => {
      categoryCounts[g.category] = (categoryCounts[g.category] || 0) + 1;
    });
    
    // Count attributes
    const attributeCounts = {};
    garments.forEach(g => {
      if (!g.attributes) return;
      
      const attrs = typeof g.attributes === 'string' 
        ? JSON.parse(g.attributes) 
        : g.attributes;
      
      Object.entries(attrs).forEach(([key, value]) => {
        if (!attributeCounts[key]) {
          attributeCounts[key] = {};
        }
        
        const strValue = String(value);
        attributeCounts[key][strValue] = (attributeCounts[key][strValue] || 0) + 1;
      });
    });
    
    // Calculate average polygon points
    let totalPoints = 0;
    let garmentWithPolygons = 0;
    
    garments.forEach(g => {
      if (g.polygon_points && Array.isArray(g.polygon_points)) {
        totalPoints += g.polygon_points.length;
        garmentWithPolygons++;
      }
    });
    
    const averagePolygonPoints = garmentWithPolygons > 0 
      ? Math.round(totalPoints / garmentWithPolygons) 
      : 0;
    
    return {
      totalImages: uniqueImageIds.size,
      totalGarments: garments.length,
      categoryCounts,
      attributeCounts,
      averagePolygonPoints
    };
  }

  /**
   * Download batch job export file
   */
  async downloadExport(batchJobId: string): Promise<{path: string, filename: string}> {
    const job = await this.getBatchJob(batchJobId);
    
    if (!job) {
      throw new Error('Export job not found');
    }
    
    if (job.status !== 'completed') {
      throw new Error(`Export job status is ${job.status}, not ready for download`);
    }
    
    const zipPath = path.join(this.EXPORTS_PATH, `${batchJobId}.zip`);
    if (!fs.existsSync(zipPath)) {
      throw new Error('Export file not found');
    }
    
    return {
      path: zipPath,
      filename: `koutu-export-${batchJobId.slice(0, 8)}.zip`
    };
  }
}

export const exportService = new ExportService();d_items,
      outputUrl: job.output_url,
      error: job.error,
      createdAt: job.created_at,
      updatedAt: job.updated_at,
      completedAt: job.completed_at
    };
  }

  /**
   * Get user batch jobs
   */
  async getUserBatchJobs(userId: string): Promise<MLExportBatchJob[]> {
    const jobs = await db.table('export_batch_jobs')
      .where('user_id', userId)
      .orderBy('created_at', 'desc');
    
    return jobs.map(job => ({
      id: job.id,
      userId: job.user_id,
      status: job.status,
      options: JSON.parse(job.options),
      progress: job.progress,
      totalItems: job.total_items,
      processedItems: job.processe