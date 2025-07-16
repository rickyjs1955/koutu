const wardrobeController = require('./src/controllers/wardrobeController').wardrobeController;

console.log('wardrobeController keys:', Object.keys(wardrobeController));
console.log('reorderGarments type:', typeof wardrobeController.reorderGarments);
console.log('reorderGarments exists:', 'reorderGarments' in wardrobeController);
console.log('reorderGarments value:', wardrobeController.reorderGarments);
EOF < /dev/null
