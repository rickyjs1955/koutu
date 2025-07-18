import 'package:freezed_annotation/freezed_annotation.dart';

part 'garment_3d_model.freezed.dart';
part 'garment_3d_model.g.dart';

/// 3D garment model for visualization
@freezed
class Garment3DModel with _$Garment3DModel {
  const factory Garment3DModel({
    required String modelId,
    required String garmentId,
    required String modelUrl,
    required String? textureUrl,
    required Model3DFormat format,
    required Model3DMetadata metadata,
    required List<Model3DMaterial> materials,
    required Model3DBoundingBox boundingBox,
    required DateTime createdAt,
    required bool isProcessed,
    Map<String, dynamic>? processingData,
  }) = _Garment3DModel;

  factory Garment3DModel.fromJson(Map<String, dynamic> json) =>
      _$Garment3DModelFromJson(json);
}

/// 3D model format
enum Model3DFormat {
  @JsonValue('gltf')
  gltf,
  @JsonValue('glb')
  glb,
  @JsonValue('obj')
  obj,
  @JsonValue('fbx')
  fbx,
  @JsonValue('usdz')
  usdz,
}

/// 3D model metadata
@freezed
class Model3DMetadata with _$Model3DMetadata {
  const factory Model3DMetadata({
    required int vertexCount,
    required int polygonCount,
    required int textureCount,
    required double fileSizeBytes,
    required List<String> animations,
    required Map<String, double> dimensions,
    required Map<String, dynamic> exportSettings,
  }) = _Model3DMetadata;

  factory Model3DMetadata.fromJson(Map<String, dynamic> json) =>
      _$Model3DMetadataFromJson(json);
}

/// 3D model material
@freezed
class Model3DMaterial with _$Model3DMaterial {
  const factory Model3DMaterial({
    required String materialId,
    required String name,
    required MaterialType type,
    required Map<String, double> baseColor,
    required double metalness,
    required double roughness,
    required double opacity,
    required Map<String, String> textures,
    required Map<String, dynamic> properties,
  }) = _Model3DMaterial;

  factory Model3DMaterial.fromJson(Map<String, dynamic> json) =>
      _$Model3DMaterialFromJson(json);
}

/// Material type
enum MaterialType {
  @JsonValue('fabric')
  fabric,
  @JsonValue('leather')
  leather,
  @JsonValue('metal')
  metal,
  @JsonValue('plastic')
  plastic,
  @JsonValue('rubber')
  rubber,
  @JsonValue('other')
  other,
}

/// 3D model bounding box
@freezed
class Model3DBoundingBox with _$Model3DBoundingBox {
  const factory Model3DBoundingBox({
    required List<double> min, // x, y, z
    required List<double> max, // x, y, z
    required List<double> center, // x, y, z
    required List<double> size, // width, height, depth
  }) = _Model3DBoundingBox;

  factory Model3DBoundingBox.fromJson(Map<String, dynamic> json) =>
      _$Model3DBoundingBoxFromJson(json);
}

/// 3D viewer configuration
@freezed
class Viewer3DConfiguration with _$Viewer3DConfiguration {
  const factory Viewer3DConfiguration({
    required bool autoRotate,
    required double rotationSpeed,
    required bool enableZoom,
    required double minZoom,
    required double maxZoom,
    required bool enablePan,
    required bool enableAR,
    required String backgroundColor,
    required LightingConfiguration lighting,
    required CameraConfiguration camera,
    required Map<String, dynamic> advancedSettings,
  }) = _Viewer3DConfiguration;

  factory Viewer3DConfiguration.fromJson(Map<String, dynamic> json) =>
      _$Viewer3DConfigurationFromJson(json);
}

/// Lighting configuration
@freezed
class LightingConfiguration with _$LightingConfiguration {
  const factory LightingConfiguration({
    required double ambientIntensity,
    required String ambientColor,
    required List<DirectionalLight> directionalLights,
    required List<PointLight> pointLights,
    required bool enableShadows,
    required double shadowIntensity,
    required bool enableEnvironmentMap,
    String? environmentMapUrl,
  }) = _LightingConfiguration;

  factory LightingConfiguration.fromJson(Map<String, dynamic> json) =>
      _$LightingConfigurationFromJson(json);
}

/// Directional light
@freezed
class DirectionalLight with _$DirectionalLight {
  const factory DirectionalLight({
    required String lightId,
    required List<double> direction,
    required String color,
    required double intensity,
    required bool castShadows,
  }) = _DirectionalLight;

  factory DirectionalLight.fromJson(Map<String, dynamic> json) =>
      _$DirectionalLightFromJson(json);
}

/// Point light
@freezed
class PointLight with _$PointLight {
  const factory PointLight({
    required String lightId,
    required List<double> position,
    required String color,
    required double intensity,
    required double range,
    required double decay,
  }) = _PointLight;

  factory PointLight.fromJson(Map<String, dynamic> json) =>
      _$PointLightFromJson(json);
}

/// Camera configuration
@freezed
class CameraConfiguration with _$CameraConfiguration {
  const factory CameraConfiguration({
    required CameraType type,
    required List<double> position,
    required List<double> target,
    required double fieldOfView,
    required double near,
    required double far,
    required Map<String, dynamic> controls,
  }) = _CameraConfiguration;

  factory CameraConfiguration.fromJson(Map<String, dynamic> json) =>
      _$CameraConfigurationFromJson(json);
}

/// Camera type
enum CameraType {
  @JsonValue('perspective')
  perspective,
  @JsonValue('orthographic')
  orthographic,
}

/// 3D interaction event
@freezed
class Interaction3DEvent with _$Interaction3DEvent {
  const factory Interaction3DEvent({
    required String eventId,
    required InteractionType type,
    required DateTime timestamp,
    required Map<String, double> position,
    required Map<String, double> rotation,
    required double zoom,
    required Map<String, dynamic> additionalData,
  }) = _Interaction3DEvent;

  factory Interaction3DEvent.fromJson(Map<String, dynamic> json) =>
      _$Interaction3DEventFromJson(json);
}

/// Interaction type
enum InteractionType {
  @JsonValue('rotate')
  rotate,
  @JsonValue('zoom')
  zoom,
  @JsonValue('pan')
  pan,
  @JsonValue('tap')
  tap,
  @JsonValue('double_tap')
  doubleTap,
  @JsonValue('long_press')
  longPress,
}

/// 3D model processing status
@freezed
class Model3DProcessingStatus with _$Model3DProcessingStatus {
  const factory Model3DProcessingStatus({
    required String processingId,
    required ProcessingStage stage,
    required double progress,
    required String? currentStep,
    required DateTime startedAt,
    DateTime? completedAt,
    String? errorMessage,
    Map<String, dynamic>? results,
  }) = _Model3DProcessingStatus;

  factory Model3DProcessingStatus.fromJson(Map<String, dynamic> json) =>
      _$Model3DProcessingStatusFromJson(json);
}

/// Processing stage
enum ProcessingStage {
  @JsonValue('uploading')
  uploading,
  @JsonValue('analyzing')
  analyzing,
  @JsonValue('converting')
  converting,
  @JsonValue('optimizing')
  optimizing,
  @JsonValue('texturing')
  texturing,
  @JsonValue('finalizing')
  finalizing,
  @JsonValue('completed')
  completed,
  @JsonValue('failed')
  failed,
}