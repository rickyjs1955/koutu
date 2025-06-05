// /backend/scripts/add-garment-columns.ts
// Script to add only the missing columns to existing garment_items table

import { TestDatabaseConnection } from '../src/utils/testDatabaseConnection';

async function addMissingColumns() {
  console.log('🔧 Adding missing columns to garment_items table...');
  
  try {
    await TestDatabaseConnection.initialize();
    
    // Check what columns currently exist
    const existingColumns = await TestDatabaseConnection.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'garment_items'
      ORDER BY column_name
    `);
    
    const columnNames = existingColumns.rows.map((row: any) => row.column_name);
    console.log('Existing columns:', columnNames);
    
    // Define the columns we need for garmentModel.ts
    const requiredColumns = [
      { name: 'file_path', type: 'TEXT' },
      { name: 'mask_path', type: 'TEXT' },
      { name: 'metadata', type: 'JSONB DEFAULT \'{}\'', },
      { name: 'data_version', type: 'INTEGER DEFAULT 1' }
    ];
    
    // Add missing columns one by one
    for (const column of requiredColumns) {
      if (!columnNames.includes(column.name)) {
        console.log(`Adding column: ${column.name}`);
        await TestDatabaseConnection.query(
          `ALTER TABLE garment_items ADD COLUMN ${column.name} ${column.type}`
        );
        console.log(`✅ Added ${column.name}`);
      } else {
        console.log(`✅ Column ${column.name} already exists`);
      }
    }
    
    // Verify all columns are now present
    const updatedColumns = await TestDatabaseConnection.query(`
      SELECT column_name FROM information_schema.columns
      WHERE table_name = 'garment_items'
      ORDER BY column_name
    `);
    
    const updatedColumnNames = updatedColumns.rows.map((row: any) => row.column_name);
    console.log('Updated columns:', updatedColumnNames);
    
    // Check that all required columns are present
    const missingColumns = requiredColumns
      .map(col => col.name)
      .filter(name => !updatedColumnNames.includes(name));
    
    if (missingColumns.length === 0) {
      console.log('🎉 All required columns are now present!');
    } else {
      console.error('❌ Still missing columns:', missingColumns);
    }
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await TestDatabaseConnection.cleanup();
  }
}

// Run if called directly
if (require.main === module) {
  addMissingColumns().catch(error => {
    console.error('Column migration failed:', error);
    process.exit(1);
  });
}

export { addMissingColumns };