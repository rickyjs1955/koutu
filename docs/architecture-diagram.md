flowchart TB
    subgraph MonorepoStructure["Koutu Monorepo"]
        subgraph SharedPackage["Shared Package"]
            SharedSchemas["Zod Schemas"]
            DerivedTypes["TypeScript Types"]
            
            SharedSchemas --> DerivedTypes
        end

        subgraph FrontendPackage["Frontend Package"]
            ReactApp["React Application"]
            subgraph FrontendModules["Frontend Modules"]
                Components["UI Components"]
                Hooks["React Hooks"]
                APIClient["API Client"]
                ReactQuery["React Query Integration"]
                FormValidation["Form Validation"]
            end

            ReactApp --> FrontendModules
            DerivedTypes -.-> APIClient
            SharedSchemas -.-> FormValidation
            APIClient -.-> ReactQuery
            ReactQuery -.-> Hooks
            Hooks -.-> Components
        end

        subgraph BackendPackage["Backend Package"]
            subgraph Core["Core Application"]
                App[Express App]
                Auth[Authentication]
                ErrorHandler[Error Handler]
                Config[Configuration]
                ValidationMiddleware[Validation Middleware]

                App --> Auth
                App --> ErrorHandler
                App --> Config
                App --> ValidationMiddleware
                SharedSchemas -.-> ValidationMiddleware
            end

            subgraph Routes["API Routes"]
                AuthRoutes[Auth Routes]
                ImageRoutes[Image Routes]
                GarmentRoutes[Garment Routes]
                WardrobeRoutes[Wardrobe Routes]
                ExportRoutes[Export Routes]

                App --> AuthRoutes
                App --> ImageRoutes
                App --> GarmentRoutes
                App --> WardrobeRoutes
                App --> ExportRoutes
            end

            subgraph Controllers["Controllers"]
                AuthController[Auth Controller]
                ImageController[Image Controller]
                GarmentController[Garment Controller]
                WardrobeController[Wardrobe Controller]
                ExportController[Export Controller]

                AuthRoutes --> AuthController
                ImageRoutes --> ImageController
                GarmentRoutes --> GarmentController
                WardrobeRoutes --> WardrobeController
                ExportRoutes --> ExportController
                DerivedTypes -.-> Controllers
            end

            subgraph Models["Data Models"]
                UserModel[User Model]
                ImageModel[Image Model]
                GarmentModel[Garment Model]
                WardrobeModel[Wardrobe Model]
                DB[(PostgreSQL Database)]

                UserModel --> DB
                ImageModel --> DB
                GarmentModel --> DB
                WardrobeModel --> DB
                DerivedTypes -.-> Models
            end

            subgraph Services["Business Services"]
                StorageService[Storage Service]
                ImageProcessingService[Image Processing]
                LabelingService[Labeling Service]
                ExportService[Export Service]
            end

            subgraph Storage["File Storage"]
                Uploads[(Uploads Directory)]
                Exports[(Exports Directory)]
                
                StorageService --> Uploads
                ExportService --> Exports
            end

            AuthController --> UserModel
            ImageController --> ImageModel
            ImageController --> StorageService
            ImageController --> ImageProcessingService
            GarmentController --> GarmentModel
            GarmentController --> LabelingService
            WardrobeController --> WardrobeModel
            WardrobeController --> GarmentModel
            ExportController --> ExportService
            ExportController --> UserModel
            ExportController --> ImageModel
            ExportController --> GarmentModel
            ExportController --> WardrobeModel
        end
    end

    Client[Browser Client] <--> APIClient
    APIClient <--> AuthRoutes
    APIClient <--> ImageRoutes
    APIClient <--> GarmentRoutes
    APIClient <--> WardrobeRoutes
    APIClient <--> ExportRoutes

    classDef sharedNode fill:#f9d,stroke:#333,stroke-width:2px;
    classDef frontendNode fill:#aef,stroke:#333,stroke-width:1px;
    classDef frontendModuleNode fill:#bdf,stroke:#333,stroke-width:1px;
    classDef backendNode fill:#fdb,stroke:#333,stroke-width:1px;
    classDef coreNode fill:#f9f,stroke:#333,stroke-width:1px;
    classDef routeNode fill:#bbf,stroke:#333,stroke-width:1px;
    classDef controllerNode fill:#dfd,stroke:#333,stroke-width:1px;
    classDef modelNode fill:#fdb,stroke:#333,stroke-width:1px;
    classDef serviceNode fill:#ddd,stroke:#333,stroke-width:1px;
    classDef storageNode fill:#fdd,stroke:#333,stroke-width:1px;
    classDef databaseNode fill:#ddf,stroke:#333,stroke-width:2px;
    classDef clientNode fill:#dfd,stroke:#333,stroke-width:2px;

    class SharedSchemas,DerivedTypes sharedNode;
    class ReactApp frontendNode;
    class Components,Hooks,APIClient,ReactQuery,FormValidation frontendModuleNode;
    class App,Auth,ErrorHandler,Config,ValidationMiddleware coreNode;
    class AuthRoutes,ImageRoutes,GarmentRoutes,WardrobeRoutes,ExportRoutes routeNode;
    class AuthController,ImageController,GarmentController,WardrobeController,ExportController controllerNode;
    class UserModel,ImageModel,GarmentModel,WardrobeModel modelNode;
    class StorageService,ImageProcessingService,LabelingService,ExportService serviceNode;
    class Uploads,Exports storageNode;
    class DB databaseNode;
    class Client clientNode;