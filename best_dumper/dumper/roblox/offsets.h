#pragma once

#include <cstdint>
#include <string>

namespace offsets {
    inline std::string ClientVersion = "";

    namespace AirProperties {
        inline uintptr_t AirDensity = 0;
        inline uintptr_t GlobalWind = 0;
    }

    namespace AnimationTrack {
        inline uintptr_t Animation = 0;
        inline uintptr_t Animator = 0;
        inline uintptr_t IsPlaying = 0;
        inline uintptr_t Looped = 0;
        inline uintptr_t Speed = 0;
    }

    namespace Animator {
        inline uintptr_t ActiveAnimations = 0;
    }

    namespace Atmosphere {
        inline uintptr_t Color = 0;
        inline uintptr_t Decay = 0;
        inline uintptr_t Density = 0;
        inline uintptr_t Glare = 0;
        inline uintptr_t Haze = 0;
        inline uintptr_t Offset = 0;
    }

    namespace Attachment {
        inline uintptr_t Position = 0;
    }

    namespace BasePart {
        inline uintptr_t Color3 = 0;
        inline uintptr_t Primitive = 0;
        inline uintptr_t Shape = 0;
        inline uintptr_t Transparency = 0;
    }

    namespace BloomEffect {
        inline uintptr_t Enabled = 0;
        inline uintptr_t Intensity = 0;
        inline uintptr_t Size = 0;
        inline uintptr_t Threshold = 0;
    }

    namespace BlurEffect {
        inline uintptr_t Enabled = 0;
        inline uintptr_t Size = 0;
    }

    namespace ByteCode {
        inline uintptr_t Pointer = 0;
        inline uintptr_t Size = 0;
    }

    namespace Camera {
        inline uintptr_t CameraSubject = 0;
        inline uintptr_t CameraType = 0;
        inline uintptr_t CFrame = 0;
        inline uintptr_t FieldOfView = 0;
        inline uintptr_t Position = 0;
        inline uintptr_t Rotation = 0;
        inline uintptr_t Viewport = 0;
        inline uintptr_t ViewportSize = 0;
    }

    namespace CharacterMesh {
        inline uintptr_t BaseTextureId = 0;
        inline uintptr_t BodyPart = 0;
        inline uintptr_t MeshId = 0;
        inline uintptr_t OverlayTextureId = 0;
    }

    namespace ClickDetector {
        inline uintptr_t MaxActivationDistance = 0;
        inline uintptr_t MouseIcon = 0;
    }

    namespace Clothing {
        inline uintptr_t Color3 = 0;
        inline uintptr_t Template = 0;
    }

    namespace ColorCorrectionEffect {
        inline uintptr_t Brightness = 0;
        inline uintptr_t Contrast = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t TintColor = 0;
    }

    namespace ColorGradingEffect {
        inline uintptr_t Enabled = 0;
        inline uintptr_t TonemapperPreset = 0;
    }

    namespace DataModel {
        inline uintptr_t CreatorId = 0;
        inline uintptr_t GameId = 0;
        inline uintptr_t GameLoaded = 0;
        inline uintptr_t JobId = 0;
        inline uintptr_t PlaceId = 0;
        inline uintptr_t PlaceVersion = 0;
        inline uintptr_t Pointer = 0;
        inline uintptr_t PrimitiveCount = 0;
        inline uintptr_t ScriptContext = 0;
        inline uintptr_t ServerIP = 0;
        inline uintptr_t Workspace = 0;
    }

    namespace DepthOfFieldEffect {
        inline uintptr_t Enabled = 0;
        inline uintptr_t FarIntensity = 0;
        inline uintptr_t FocusDistance = 0;
        inline uintptr_t InFocusRadius = 0;
        inline uintptr_t NearIntensity = 0;
    }

    namespace FakeDataModel {
        inline uintptr_t Pointer = 0;
        inline uintptr_t RealDataModel = 0;
    }

    namespace GuiBase2D {
        inline uintptr_t AbsolutePosition = 0;
        inline uintptr_t AbsoluteRotation = 0;
        inline uintptr_t AbsoluteSize = 0;
    }

    namespace GuiObject {
        inline uintptr_t BackgroundColor3 = 0;
        inline uintptr_t BackgroundTransparency = 0;
        inline uintptr_t BorderColor3 = 0;
        inline uintptr_t Image = 0;
        inline uintptr_t LayoutOrder = 0;
        inline uintptr_t Position = 0;
        inline uintptr_t RichText = 0;
        inline uintptr_t Rotation = 0;
        inline uintptr_t ScreenGui_Enabled = 0;
        inline uintptr_t Size = 0;
        inline uintptr_t Text = 0;
        inline uintptr_t TextColor3 = 0;
        inline uintptr_t Visible = 0;
        inline uintptr_t ZIndex = 0;
    }

    namespace Humanoid {
        inline uintptr_t AutoJumpEnabled = 0;
        inline uintptr_t AutoRotate = 0;
        inline uintptr_t AutomaticScalingEnabled = 0;
        inline uintptr_t BreakJointsOnDeath = 0;
        inline uintptr_t CameraOffset = 0;
        inline uintptr_t DisplayDistanceType = 0;
        inline uintptr_t DisplayName = 0;
        inline uintptr_t EvaluateStateMachine = 0;
        inline uintptr_t FloorMaterial = 0;
        inline uintptr_t Health = 0;
        inline uintptr_t HealthDisplayDistance = 0;
        inline uintptr_t HealthDisplayType = 0;
        inline uintptr_t HipHeight = 0;
        inline uintptr_t HumanoidRootPart = 0;
        inline uintptr_t HumanoidState = 0;
        inline uintptr_t HumanoidStateID = 0;
        inline uintptr_t IsWalking = 0;
        inline uintptr_t Jump = 0;
        inline uintptr_t JumpHeight = 0;
        inline uintptr_t JumpPower = 0;
        inline uintptr_t MaxHealth = 0;
        inline uintptr_t MaxSlopeAngle = 0;
        inline uintptr_t MoveDirection = 0;
        inline uintptr_t MoveToPart = 0;
        inline uintptr_t MoveToPoint = 0;
        inline uintptr_t NameDisplayDistance = 0;
        inline uintptr_t NameOcclusion = 0;
        inline uintptr_t PlatformStand = 0;
        inline uintptr_t RequiresNeck = 0;
        inline uintptr_t RigType = 0;
        inline uintptr_t SeatPart = 0;
        inline uintptr_t Sit = 0;
        inline uintptr_t TargetPoint = 0;
        inline uintptr_t UseJumpPower = 0;
        inline uintptr_t Walkspeed = 0;
        inline uintptr_t WalkspeedCheck = 0;
    }

    namespace InputObject {
        inline uintptr_t MousePosition = 0;
    }

    namespace Instance {
        inline uintptr_t AttributeContainer = 0;
        inline uintptr_t AttributeList = 0;
        inline uintptr_t AttributeToNext = 0;
        inline uintptr_t AttributeToValue = 0;
        inline uintptr_t ChildrenEnd = 0;
        inline uintptr_t ChildrenStart = 0;
        inline uintptr_t ClassBase = 0;
        inline uintptr_t ClassDescriptor = 0;
        inline uintptr_t ClassName = 0;
        inline uintptr_t Name = 0;
        inline uintptr_t Parent = 0;
        inline uintptr_t This = 0;
    }

    namespace Lighting {
        inline uintptr_t Ambient = 0;
        inline uintptr_t Brightness = 0;
        inline uintptr_t ClockTime = 0;
        inline uintptr_t ColorShift_Bottom = 0;
        inline uintptr_t ColorShift_Top = 0;
        inline uintptr_t EnvironmentDiffuseScale = 0;
        inline uintptr_t EnvironmentSpecularScale = 0;
        inline uintptr_t ExposureCompensation = 0;
        inline uintptr_t FogColor = 0;
        inline uintptr_t FogEnd = 0;
        inline uintptr_t FogStart = 0;
        inline uintptr_t GeographicLatitude = 0;
        inline uintptr_t GlobalShadows = 0;
        inline uintptr_t GradientBottom = 0;
        inline uintptr_t GradientTop = 0;
        inline uintptr_t LightColor = 0;
        inline uintptr_t LightDirection = 0;
        inline uintptr_t MoonPosition = 0;
        inline uintptr_t OutdoorAmbient = 0;
        inline uintptr_t Sky = 0;
        inline uintptr_t Source = 0;
        inline uintptr_t SunPosition = 0;
    }

    namespace LocalScript {
        inline uintptr_t ByteCode = 0;
        inline uintptr_t GUID = 0;
        inline uintptr_t Hash = 0;
    }

    namespace MaterialColors {
        inline uintptr_t Asphalt = 0;
        inline uintptr_t Basalt = 0;
        inline uintptr_t Brick = 0;
        inline uintptr_t Cobblestone = 0;
        inline uintptr_t Concrete = 0;
        inline uintptr_t CrackedLava = 0;
        inline uintptr_t Glacier = 0;
        inline uintptr_t Grass = 0;
        inline uintptr_t Ground = 0;
        inline uintptr_t Ice = 0;
        inline uintptr_t LeafyGrass = 0;
        inline uintptr_t Limestone = 0;
        inline uintptr_t Mud = 0;
        inline uintptr_t Pavement = 0;
        inline uintptr_t Rock = 0;
        inline uintptr_t Salt = 0;
        inline uintptr_t Sand = 0;
        inline uintptr_t Sandstone = 0;
        inline uintptr_t Slate = 0;
        inline uintptr_t Snow = 0;
        inline uintptr_t WoodPlanks = 0;
    }

    namespace MeshPart {
        inline uintptr_t MeshId = 0;
        inline uintptr_t Texture = 0;
    }

    namespace Misc {
        inline uintptr_t Adornee = 0;
        inline uintptr_t AnimationId = 0;
        inline uintptr_t StringLength = 0;
        inline uintptr_t Value = 0;
    }

    namespace Model {
        inline uintptr_t PrimaryPart = 0;
        inline uintptr_t Scale = 0;
    }

    namespace ModuleScript {
        inline uintptr_t ByteCode = 0;
        inline uintptr_t GUID = 0;
        inline uintptr_t Hash = 0;
    }

    namespace MouseService {
        inline uintptr_t InputObject = 0;
        inline uintptr_t MousePosition = 0;
        inline uintptr_t SensitivityPointer = 0;
    }

    namespace Player {
        inline uintptr_t CameraMode = 0;
        inline uintptr_t Character = 0;
        inline uintptr_t Country = 0;
        inline uintptr_t DisplayName = 0;
        inline uintptr_t HealthDisplayDistance = 0;
        inline uintptr_t LocalPlayer = 0;
        inline uintptr_t MaxZoomDistance = 0;
        inline uintptr_t MinZoomDistance = 0;
        inline uintptr_t ModelInstance = 0;
        inline uintptr_t Mouse = 0;
        inline uintptr_t NameDisplayDistance = 0;
        inline uintptr_t Team = 0;
        inline uintptr_t UserId = 0;
    }

    namespace PlayerConfigurer {
        inline uintptr_t Pointer = 0;
    }

    namespace PlayerMouse {
        inline uintptr_t Icon = 0;
        inline uintptr_t Workspace = 0;
    }

    namespace Primitive {
        inline uintptr_t AssemblyAngularVelocity = 0;
        inline uintptr_t AssemblyLinearVelocity = 0;
        inline uintptr_t Flags = 0;
        inline uintptr_t Material = 0;
        inline uintptr_t Owner = 0;
        inline uintptr_t Position = 0;
        inline uintptr_t Rotation = 0;
        inline uintptr_t Size = 0;
        inline uintptr_t Validate = 0;
    }

    namespace PrimitiveFlags {
        inline uintptr_t Anchored = 0;
        inline uintptr_t CanCollide = 0;
        inline uintptr_t CanTouch = 0;
    }

    namespace ProximityPrompt {
        inline uintptr_t ActionText = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t GamepadKeyCode = 0;
        inline uintptr_t HoldDuration = 0;
        inline uintptr_t KeyboardKeyCode = 0;
        inline uintptr_t MaxActivationDistance = 0;
        inline uintptr_t ObjectText = 0;
        inline uintptr_t RequiresLineOfSight = 0;
    }

    namespace RenderJob {
        inline uintptr_t FakeDataModel = 0;
        inline uintptr_t RealDataModel = 0;
        inline uintptr_t RenderView = 0;
    }

    namespace RenderView {
        inline uintptr_t DeviceD3D11 = 0;
        inline uintptr_t LightingValid = 0;
        inline uintptr_t SkyValid = 0;
        inline uintptr_t VisualEngine = 0;
    }

    namespace RunService {
        inline uintptr_t HeartbeatFPS = 0;
        inline uintptr_t HeartbeatTask = 0;
    }

    namespace Seat {
        inline uintptr_t Occupant = 0;
    }

    namespace Sky {
        inline uintptr_t MoonAngularSize = 0;
        inline uintptr_t MoonTextureId = 0;
        inline uintptr_t SkyboxBk = 0;
        inline uintptr_t SkyboxDn = 0;
        inline uintptr_t SkyboxFt = 0;
        inline uintptr_t SkyboxLf = 0;
        inline uintptr_t SkyboxOrientation = 0;
        inline uintptr_t SkyboxRt = 0;
        inline uintptr_t SkyboxUp = 0;
        inline uintptr_t StarCount = 0;
        inline uintptr_t SunAngularSize = 0;
        inline uintptr_t SunTextureId = 0;
    }

    namespace Sound {
        inline uintptr_t Looped = 0;
        inline uintptr_t PlaybackSpeed = 0;
        inline uintptr_t RollOffMaxDistance = 0;
        inline uintptr_t RollOffMinDistance = 0;
        inline uintptr_t SoundGroup = 0;
        inline uintptr_t SoundId = 0;
        inline uintptr_t Volume = 0;
    }

    namespace SpawnLocation {
        inline uintptr_t AllowTeamChangeOnTouch = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t ForcefieldDuration = 0;
        inline uintptr_t Neutral = 0;
        inline uintptr_t TeamColor = 0;
    }

    namespace SpecialMesh {
        inline uintptr_t MeshId = 0;
        inline uintptr_t Scale = 0;
    }

    namespace StatsItem {
        inline uintptr_t Value = 0;
    }

    namespace SunRaysEffect {
        inline uintptr_t Enabled = 0;
        inline uintptr_t Intensity = 0;
        inline uintptr_t Spread = 0;
    }

    namespace TaskScheduler {
        inline uintptr_t JobEnd = 0;
        inline uintptr_t JobName = 0;
        inline uintptr_t JobStart = 0;
        inline uintptr_t MaxFPS = 0;
        inline uintptr_t Pointer = 0;
    }

    namespace Team {
        inline uintptr_t BrickColor = 0;
    }

    namespace Terrain {
        inline uintptr_t GrassLength = 0;
        inline uintptr_t MaterialColors = 0;
        inline uintptr_t WaterColor = 0;
        inline uintptr_t WaterReflectance = 0;
        inline uintptr_t WaterTransparency = 0;
        inline uintptr_t WaterWaveSize = 0;
        inline uintptr_t WaterWaveSpeed = 0;
    }

    namespace Textures {
        inline uintptr_t Decal_Texture = 0;
        inline uintptr_t Texture_Texture = 0;
    }

    namespace Tool {
        inline uintptr_t CanBeDropped = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Grip = 0;
        inline uintptr_t ManualActivationOnly = 0;
        inline uintptr_t RequiresHandle = 0;
        inline uintptr_t TextureId = 0;
        inline uintptr_t Tooltip = 0;
    }

    namespace VisualEngine {
        inline uintptr_t Dimensions = 0;
        inline uintptr_t FakeDataModel = 0;
        inline uintptr_t Pointer = 0;
        inline uintptr_t RenderView = 0;
        inline uintptr_t ViewMatrix = 0;
    }

    namespace Workspace {
        inline uintptr_t CurrentCamera = 0;
        inline uintptr_t DistributedGameTime = 0;
        inline uintptr_t ReadOnlyGravity = 0;
        inline uintptr_t Terrain = 0;
        inline uintptr_t World = 0;
    }

    namespace World {
        inline uintptr_t AirProperties = 0;
        inline uintptr_t FallenPartsDestroyHeight = 0;
        inline uintptr_t Gravity = 0;
        inline uintptr_t Primitives = 0;
        inline uintptr_t worldStepsPerSec = 0;
    }

    namespace Highlight {
        inline uintptr_t Adornee = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t FillColor = 0;
        inline uintptr_t FillTransparency = 0;
        inline uintptr_t OutlineColor = 0;
        inline uintptr_t OutlineTransparency = 0;
    }

    namespace Beam {
        inline uintptr_t Attachment0 = 0;
        inline uintptr_t Attachment1 = 0;
        inline uintptr_t Color = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Width0 = 0;
        inline uintptr_t Width1 = 0;
    }

    namespace ParticleEmitter {
        inline uintptr_t Color = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Rate = 0;
        inline uintptr_t Texture = 0;
    }

    namespace SurfaceGui {
        inline uintptr_t Adornee = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Face = 0;
    }

    namespace BillboardGui {
        inline uintptr_t Adornee = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t MaxDistance = 0;
        inline uintptr_t Size = 0;
    }

    namespace WeldConstraint {
        inline uintptr_t Enabled = 0;
        inline uintptr_t Part0 = 0;
        inline uintptr_t Part1 = 0;
    }

    namespace BodyVelocity {
        inline uintptr_t MaxForce = 0;
        inline uintptr_t Velocity = 0;
    }

    namespace BodyGyro {
        inline uintptr_t CFrame = 0;
        inline uintptr_t MaxTorque = 0;
    }

    namespace ForceField {
        inline uintptr_t Visible = 0;
    }

    namespace Explosion {
        inline uintptr_t BlastPressure = 0;
        inline uintptr_t BlastRadius = 0;
        inline uintptr_t Position = 0;
    }

    namespace Fire {
        inline uintptr_t Color = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Size = 0;
    }

    namespace Smoke {
        inline uintptr_t Color = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Size = 0;
    }

    namespace Sparkles {
        inline uintptr_t Enabled = 0;
        inline uintptr_t SparkleColor = 0;
    }

    namespace PointLight {
        inline uintptr_t Brightness = 0;
        inline uintptr_t Color = 0;
        inline uintptr_t Enabled = 0;
        inline uintptr_t Range = 0;
    }

    namespace StarterPlayer {
        inline uintptr_t CharacterJumpHeight = 0;
        inline uintptr_t CharacterJumpPower = 0;
        inline uintptr_t CharacterMaxHealth = 0;
        inline uintptr_t CharacterWalkSpeed = 0;
    }

    namespace Backpack {
        inline uintptr_t Player = 0;
    }

    namespace Accessory {
        inline uintptr_t AccessoryType = 0;
        inline uintptr_t Handle = 0;
    }

    namespace HeadAccessory {
        inline uintptr_t Offset = 0;
        inline uintptr_t Scale = 0;
    }

    namespace NetworkMarker {
        inline uintptr_t Time = 0;
    }

}