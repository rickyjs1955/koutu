import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:koutu/data/models/garment/garment_model.dart';

part 'ar_session_model.freezed.dart';
part 'ar_session_model.g.dart';

/// AR session model for virtual try-on
@freezed
class ARSessionModel with _$ARSessionModel {
  const factory ARSessionModel({
    required String sessionId,
    required String userId,
    required DateTime startedAt,
    DateTime? endedAt,
    required ARSessionStatus status,
    required ARDeviceInfo deviceInfo,
    required AREnvironmentInfo environmentInfo,
    List<ARGarmentPlacement>? garmentPlacements,
    ARBodyTracking? bodyTracking,
    Map<String, dynamic>? metadata,
  }) = _ARSessionModel;

  factory ARSessionModel.fromJson(Map<String, dynamic> json) =>
      _$ARSessionModelFromJson(json);
}

/// AR session status
enum ARSessionStatus {
  @JsonValue('initializing')
  initializing,
  @JsonValue('ready')
  ready,
  @JsonValue('tracking')
  tracking,
  @JsonValue('paused')
  paused,
  @JsonValue('error')
  error,
  @JsonValue('ended')
  ended,
}

/// AR device information
@freezed
class ARDeviceInfo with _$ARDeviceInfo {
  const factory ARDeviceInfo({
    required String deviceModel,
    required String osVersion,
    required bool supportsARCore,
    required bool supportsARKit,
    required bool supportsFaceTracking,
    required bool supportsBodyTracking,
    required bool supportsOcclusion,
    required bool supportsLidar,
    required ARCameraInfo cameraInfo,
  }) = _ARDeviceInfo;

  factory ARDeviceInfo.fromJson(Map<String, dynamic> json) =>
      _$ARDeviceInfoFromJson(json);
}

/// AR camera information
@freezed
class ARCameraInfo with _$ARCameraInfo {
  const factory ARCameraInfo({
    required double focalLength,
    required double sensorWidth,
    required double sensorHeight,
    required List<double> intrinsics,
    required List<double> distortionCoefficients,
  }) = _ARCameraInfo;

  factory ARCameraInfo.fromJson(Map<String, dynamic> json) =>
      _$ARCameraInfoFromJson(json);
}

/// AR environment information
@freezed
class AREnvironmentInfo with _$AREnvironmentInfo {
  const factory AREnvironmentInfo({
    required double lightIntensity,
    required double lightTemperature,
    required List<double> lightDirection,
    required ARPlaneDetection planeDetection,
    required ARSceneUnderstanding sceneUnderstanding,
  }) = _AREnvironmentInfo;

  factory AREnvironmentInfo.fromJson(Map<String, dynamic> json) =>
      _$AREnvironmentInfoFromJson(json);
}

/// AR plane detection data
@freezed
class ARPlaneDetection with _$ARPlaneDetection {
  const factory ARPlaneDetection({
    required bool horizontalPlanesDetected,
    required bool verticalPlanesDetected,
    required int planeCount,
    required List<ARPlane> planes,
  }) = _ARPlaneDetection;

  factory ARPlaneDetection.fromJson(Map<String, dynamic> json) =>
      _$ARPlaneDetectionFromJson(json);
}

/// AR plane data
@freezed
class ARPlane with _$ARPlane {
  const factory ARPlane({
    required String planeId,
    required ARPlaneType type,
    required List<double> center,
    required List<double> normal,
    required double width,
    required double height,
    required List<List<double>> boundaryPolygon,
  }) = _ARPlane;

  factory ARPlane.fromJson(Map<String, dynamic> json) =>
      _$ARPlaneFromJson(json);
}

/// AR plane type
enum ARPlaneType {
  @JsonValue('horizontal_up')
  horizontalUp,
  @JsonValue('horizontal_down')
  horizontalDown,
  @JsonValue('vertical')
  vertical,
  @JsonValue('unknown')
  unknown,
}

/// AR scene understanding data
@freezed
class ARSceneUnderstanding with _$ARSceneUnderstanding {
  const factory ARSceneUnderstanding({
    required bool meshingEnabled,
    required bool occlusionEnabled,
    required bool semanticSegmentationEnabled,
    required int meshTriangleCount,
    required Map<String, int> detectedObjects,
  }) = _ARSceneUnderstanding;

  factory ARSceneUnderstanding.fromJson(Map<String, dynamic> json) =>
      _$ARSceneUnderstandingFromJson(json);
}

/// AR garment placement data
@freezed
class ARGarmentPlacement with _$ARGarmentPlacement {
  const factory ARGarmentPlacement({
    required String placementId,
    required String garmentId,
    required GarmentModel garment,
    required DateTime placedAt,
    required ARTransform transform,
    required ARRenderingOptions renderingOptions,
    required bool isVisible,
    required bool isOccluded,
    required double confidence,
    Map<String, dynamic>? adjustments,
  }) = _ARGarmentPlacement;

  factory ARGarmentPlacement.fromJson(Map<String, dynamic> json) =>
      _$ARGarmentPlacementFromJson(json);
}

/// AR transform data
@freezed
class ARTransform with _$ARTransform {
  const factory ARTransform({
    required List<double> position, // x, y, z
    required List<double> rotation, // quaternion: x, y, z, w
    required List<double> scale, // x, y, z
    required List<List<double>> matrix, // 4x4 transformation matrix
  }) = _ARTransform;

  factory ARTransform.fromJson(Map<String, dynamic> json) =>
      _$ARTransformFromJson(json);
}

/// AR rendering options
@freezed
class ARRenderingOptions with _$ARRenderingOptions {
  const factory ARRenderingOptions({
    required double opacity,
    required bool castsShadows,
    required bool receivesShadows,
    required bool usePhysicallyBasedRendering,
    required String shaderType,
    required Map<String, double> materialProperties,
    Map<String, String>? textureOverrides,
  }) = _ARRenderingOptions;

  factory ARRenderingOptions.fromJson(Map<String, dynamic> json) =>
      _$ARRenderingOptionsFromJson(json);
}

/// AR body tracking data
@freezed
class ARBodyTracking with _$ARBodyTracking {
  const factory ARBodyTracking({
    required String trackingId,
    required bool isTracking,
    required double confidence,
    required ARBodyPose bodyPose,
    required ARBodyMeasurements measurements,
    required Map<String, ARJoint> joints,
  }) = _ARBodyTracking;

  factory ARBodyTracking.fromJson(Map<String, dynamic> json) =>
      _$ARBodyTrackingFromJson(json);
}

/// AR body pose data
@freezed
class ARBodyPose with _$ARBodyPose {
  const factory ARBodyPose({
    required List<double> rootPosition,
    required List<double> rootRotation,
    required String poseType,
    required double poseConfidence,
  }) = _ARBodyPose;

  factory ARBodyPose.fromJson(Map<String, dynamic> json) =>
      _$ARBodyPoseFromJson(json);
}

/// AR body measurements
@freezed
class ARBodyMeasurements with _$ARBodyMeasurements {
  const factory ARBodyMeasurements({
    required double height,
    required double shoulderWidth,
    required double chestCircumference,
    required double waistCircumference,
    required double hipCircumference,
    required double armLength,
    required double inseamLength,
    required Map<String, double> additionalMeasurements,
  }) = _ARBodyMeasurements;

  factory ARBodyMeasurements.fromJson(Map<String, dynamic> json) =>
      _$ARBodyMeasurementsFromJson(json);
}

/// AR joint data
@freezed
class ARJoint with _$ARJoint {
  const factory ARJoint({
    required String jointName,
    required List<double> position,
    required List<double> rotation,
    required double confidence,
    required bool isTracked,
  }) = _ARJoint;

  factory ARJoint.fromJson(Map<String, dynamic> json) =>
      _$ARJointFromJson(json);
}

/// AR capture result
@freezed
class ARCaptureResult with _$ARCaptureResult {
  const factory ARCaptureResult({
    required String captureId,
    required String sessionId,
    required DateTime capturedAt,
    required String imageUrl,
    required String? depthMapUrl,
    required List<ARGarmentPlacement> garmentPlacements,
    required ARCaptureMetadata metadata,
  }) = _ARCaptureResult;

  factory ARCaptureResult.fromJson(Map<String, dynamic> json) =>
      _$ARCaptureResultFromJson(json);
}

/// AR capture metadata
@freezed
class ARCaptureMetadata with _$ARCaptureMetadata {
  const factory ARCaptureMetadata({
    required int imageWidth,
    required int imageHeight,
    required double fieldOfView,
    required List<double> cameraPosition,
    required List<double> cameraRotation,
    required double exposureTime,
    required double iso,
    required Map<String, dynamic> additionalData,
  }) = _ARCaptureMetadata;

  factory ARCaptureMetadata.fromJson(Map<String, dynamic> json) =>
      _$ARCaptureMetadataFromJson(json);
}