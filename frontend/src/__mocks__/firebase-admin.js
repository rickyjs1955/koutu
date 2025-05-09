// Mock for firebase-admin
const mockStorage = {
    bucket: jest.fn().mockReturnValue({
      file: jest.fn().mockReturnValue({
        createWriteStream: jest.fn().mockReturnValue({
          on: jest.fn().mockImplementation(function(event, callback) {
            if (event === 'finish') {
              setTimeout(callback, 0);
            }
            return this;
          }),
          end: jest.fn()
        }),
        exists: jest.fn().mockResolvedValue([true]),
        delete: jest.fn().mockResolvedValue(),
        getSignedUrl: jest.fn().mockResolvedValue(['https://example.com/signed-url'])
      }),
      upload: jest.fn().mockResolvedValue([{}])
    })
  };
  
  const mockFirebaseAdmin = {
    apps: [],
    initializeApp: jest.fn(),
    credential: {
      cert: jest.fn().mockReturnValue({})
    },
    storage: jest.fn().mockReturnValue(mockStorage),
    auth: jest.fn().mockReturnValue({
      verifyIdToken: jest.fn().mockResolvedValue({ uid: 'test-uid' })
    })
  };
  
  module.exports = mockFirebaseAdmin;