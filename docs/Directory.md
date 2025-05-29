Frontend:
1. /frontend/src/api/wardrobeApi.ts
2. /frontend/src/api/imageApi.ts
3. /frontend/src/api/authApi.ts
4. /frontend/src/api/index.ts
5. /frontend/src/api/garmentApi.ts
6. /frontend/src/api/polygonApi.ts
7. /frontend/src/components/forms/ImageForm.tsx
8. /frontend/src/components/forms/GarmentForm.tsx
9. /frontend/src/components/garments/GarmentList.tsx
10. /frontend/src/components/polygon/PolygonDrawer.tsx
11. /frontend/src/components/polygon/PolygonList.tsx
12. /frontend/src/components/polygon/PolygonViewer.tsx
13. /frontend/src/components/export/MLExportForm.tsx
14. /frontend/src/components/export/MLExportJobsList.tsx
15. /frontend/src/components/auth/SSOButtons.tsx NEED MODIFY FOR IG
16. /frontend/src/components/auth/OAuthCallback.tsx
17. /frontend/src/hooks/useAuth.ts
18. /frontend/src/hooks/useWardrobes.ts
19. /frontend/src/hooks/useGarments.ts
20. /frontend/src/hooks/useImages.ts
21. /frontend/src/hooks/usePolygons.ts
22. /frontend/src/hooks/useExportML.ts
23. /frontend/src/pages/ImageAnnotationPage.tsx
24. /frontend/src/pages/MLExportDashboard.tsx
25. /frontend/src/pages/OAuthCallbackPage.tsx
26. /frontend/src/pages/Login.tsx
27. /frontend/src/pages/UserProfile.tsx 
28. /frontend/src/app.tsx
29. /frontend/src/main.tsx
Shared:
1. /shared/src/schemas/wardrobe.ts
2. /shared/src/schemas/garment.ts
3. /shared/src/schemas/user.ts
4. /shared/src/schemas/export.ts
5. /shared/src/schemas/image.ts
6. /shared/src/schemas/polygon.ts
7. /shared/src/schemas/oauth.ts NEED MODIFY FOR IG
8. /shared/src/schemas/index.ts
Backend:
1. /backend/src/config/index.ts (UIS) NEED MODIFY FOR IG
2. /backend/src/config/firebase.ts (UIS) 
3. /backend/src/config/oauth.ts (UIS) NEED MODIFY FOR IG
4. /backend/src/controllers/garmentController.ts (UIS)
5. /backend/src/controllers/imageController.ts
6. /backend/src/controllers/exportController.ts
7. /backend/src/controllers/authController.ts
8. /backend/src/controllers/wardrobeController.ts
9. /backend/src/controllers/polygonController.ts
10. /backend/src/controllers/oauthController.ts
11. /backend/src/middlewares/auth.ts (UIS)
12. /backend/src/middlewares/errorHandler.ts (UIS)
13. /backend/src/middlewares/validate.ts (UIS)
14. /backend/src/models/userModel.ts
15. /backend/src/models/db.ts (UIS)
16. /backend/src/models/wardrobeModel.ts
17. /backend/src/models/imageModel.ts
18. /backend/src/models/garmentModel.ts (UIS)
19. /backend/src/models/polygonModel.ts
20. /backend/src/routes/authRoutes.ts
21. /backend/src/routes/wardrobeRoutes.ts
22. /backend/src/routes/garmentRoutes.ts (UIS)
23. /backend/src/routes/exportRoutes.ts
24. /backend/src/routes/imageRoutes.ts
25. /backend/src/routes/fileRoutes.ts
26. /backend/src/routes/polygonRoutes.ts
27. /backend/src/routes/oauthRoutes.ts
28. /backend/src/services/labelingService.ts
29. /backend/src/services/exportService.ts
30. /backend/src/services/imageProcessingService.ts
31. /backend/src/services/storageService.ts
32. /backend/src/services/oauthService.ts NEED MODIFY FOR IG
33. /backend/src/utils/ApiError.ts (UIS)
34. /backend/src/validators/index.ts
35. /backend/src/app.ts


























✅ Test Passed
❌ Test Not Available
🔔 Test Not Applicable

Backend:
1. /backend/src/config/index.ts                         ✅Unit ✅Integration ✅Security
2. /backend/src/config/firebase.ts                      ✅Unit ✅Integration ✅Security
3. /backend/src/config/oauth.ts                         ✅Unit ✅Integration ✅Security
4. /backend/src/controllers/garmentController.ts        
5. /backend/src/controllers/imageController.ts          
6. /backend/src/controllers/exportController.ts         
7. /backend/src/controllers/authController.ts          
8. /backend/src/controllers/wardrobeController.ts       
9. /backend/src/controllers/polygonController.ts        
10. /backend/src/controllers/oauthController.ts         
11. /backend/src/middlewares/auth.ts                    ✅Unit ✅Integration ✅Security
12. /backend/src/middlewares/errorHandler.ts            ✅Unit ✅Integration ✅Security
13. /backend/src/middlewares/validate.ts                ✅Unit ✅Integration ✅Security
14. /backend/src/models/userModel.ts                    ✅Unit ✅Integration ✅Security
15. /backend/src/models/db.ts                           ✅Unit ✅Integration ✅Security
16. /backend/src/models/wardrobeModel.ts
17. /backend/src/models/imageModel.ts
18. /backend/src/models/garmentModel.ts
19. /backend/src/models/polygonModel.ts
20. /backend/src/models/exportModel.ts
21. /backend/src/routes/authRoutes.ts
22. /backend/src/routes/wardrobeRoutes.ts
23. /backend/src/routes/garmentRoutes.ts
24. /backend/src/routes/exportRoutes.ts
25. /backend/src/routes/imageRoutes.ts
26. /backend/src/routes/fileRoutes.ts
27. /backend/src/routes/polygonRoutes.ts
28. /backend/src/routes/oauthRoutes.ts
29. /backend/src/services/labelingService.ts
30. /backend/src/services/exportService.ts
31. /backend/src/services/imageProcessingService.ts
32. /backend/src/services/storageService.ts
33. /backend/src/services/oauthService.ts
34. /backend/src/services/authService.ts
35. /backend/src/services/garmentService.ts
36. /backend/src/services/imageService.ts
37. /backend/src/services/polygonService.ts
38. /backend/src/utils/ApiError.ts                        ✅Unit ✅Integration ✅Security
39. /backend/src/utils/sanitize.ts                        ✅Unit ✅Integration ✅Security
40. /backend/src/utils/modelUtils.ts                      ✅Unit 🔔Integration 🔔Security
41. /backend/src/utils/testSetup.ts                       ✅Unit ✅Integration ✅Security
42. /backend/src/utils/PolygonServiceUtils.ts             ✅Unit ✅Integration 🔔Security
43. /backend/src/utils/testConfig.ts                      🔔Unit 🔔Integration ✅Security
44. /backend/src/utils/testDatabase.ts                    🔔Unit ✅Integration 🔔Security
45. /backend/src/utils/testDatabaseConnection.ts          ✅Unit ✅Integration 🔔Security
46. /backend/src/utils/testUserModel.ts                   ✅Unit 🔔Integration ✅Security
47. /backend/src/validators/index.ts                      🔔Unit 🔔Integration 🔔Security
48. /backend/src/validators/schemas.ts                    ✅Unit ✅Integration ✅Security
49. /backend/src/app.ts