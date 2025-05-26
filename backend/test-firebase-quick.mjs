// test-firebase-quick.mjs
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
process.env.NODE_ENV = 'test';

import admin from 'firebase-admin';

async function testFirebase() {
  console.log('🧪 Quick Firebase Test Starting...');
  
  try {
    // Initialize Firebase
    const app = admin.initializeApp({
      projectId: 'demo-test-project',
      storageBucket: 'demo-test-project.appspot.com'
    }, 'quick-test');

    const auth = admin.auth(app);
    const storage = admin.storage(app);
    const bucket = storage.bucket();

    console.log('✅ Firebase initialized');

    // Test 1: Create a user
    console.log('\n🔐 Testing Auth...');
    const user = await auth.createUser({
      email: 'test@example.com',
      displayName: 'Test User'
    });
    console.log(`✅ User created: ${user.uid}`);

    // Test 2: Upload a file
    console.log('\n📁 Testing Storage...');
    const file = bucket.file('test.txt');
    await file.save(Buffer.from('Hello Firebase!'));
    console.log('✅ File uploaded');

    // Test 3: Download the file
    const [content] = await file.download();
    console.log(`✅ File downloaded: ${content.toString()}`);

    // Test 4: Clean up
    await auth.deleteUser(user.uid);
    await file.delete();
    console.log('✅ Cleanup completed');

    await app.delete();
    console.log('\n🎉 ALL FIREBASE OPERATIONS SUCCESSFUL!');
    console.log('Your Firebase emulators are working perfectly! 🚀');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  }
}

testFirebase();