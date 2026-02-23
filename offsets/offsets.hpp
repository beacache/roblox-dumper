#pragma once
/* =============================================================
                       leafy dumper                            
 -------------------------------------------------------------
  Roblox Version  : version-df7528517c6849f7
  Dumper Version  : v1.2.1ar (alpha rewrite)
  Dumped At       : 19:22 23/02/2026 (GMT)
  Total Offsets   : 312
 -------------------------------------------------------------
 =============================================================
*/

#include <cstdint>
#include <string>

namespace Offsets {
    inline std::string ClientVersion = "version-df7528517c6849f7";

    namespace Accessory {
        inline constexpr uintptr_t AccessoryType = 0x120;
    }

    namespace AirProperties {
        inline constexpr uintptr_t AirDensity = 0x18;
        inline constexpr uintptr_t GlobalWind = 0x3c;
    }

    namespace Atmosphere {
        inline constexpr uintptr_t Color = 0xd0;
        inline constexpr uintptr_t Decay = 0xdc;
        inline constexpr uintptr_t Density = 0xe8;
        inline constexpr uintptr_t Glare = 0xec;
        inline constexpr uintptr_t Haze = 0xf0;
        inline constexpr uintptr_t Offset = 0xf4;
    }

    namespace Attachment {
        inline constexpr uintptr_t Position = 0xdc;
    }

    namespace Backpack {
        inline constexpr uintptr_t Player = 0xc8;
    }

    namespace BasePart {
        inline constexpr uintptr_t Color3 = 0x194;
        inline constexpr uintptr_t Primitive = 0x148;
        inline constexpr uintptr_t Shape = 0x1b1;
        inline constexpr uintptr_t Transparency = 0xf0;
    }

    namespace Beam {
        inline constexpr uintptr_t Attachment0 = 0xd8;
        inline constexpr uintptr_t Attachment1 = 0xe0;
        inline constexpr uintptr_t Color = 0x114;
        inline constexpr uintptr_t Enabled = 0x128;
        inline constexpr uintptr_t Width0 = 0x118;
        inline constexpr uintptr_t Width1 = 0x11c;
    }

    namespace BillboardGui {
        inline constexpr uintptr_t Adornee = 0x100;
        inline constexpr uintptr_t Enabled = 0x138;
        inline constexpr uintptr_t MaxDistance = 0x128;
        inline constexpr uintptr_t Size = 0x120;
    }

    namespace BloomEffect {
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t Intensity = 0xd0;
        inline constexpr uintptr_t Size = 0xd4;
        inline constexpr uintptr_t Threshold = 0xd8;
    }

    namespace BlurEffect {
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t Size = 0xd0;
    }

    namespace BodyGyro {
        inline constexpr uintptr_t CFrame = 0xdc;
        inline constexpr uintptr_t MaxTorque = 0x100;
    }

    namespace BodyVelocity {
        inline constexpr uintptr_t MaxForce = 0xec;
        inline constexpr uintptr_t Velocity = 0xd8;
    }

    namespace ByteCode {
        inline constexpr uintptr_t Pointer = 0x10;
        inline constexpr uintptr_t Size = 0x20;
    }

    namespace Camera {
        inline constexpr uintptr_t CFrame = 0xf8;
        inline constexpr uintptr_t CameraSubject = 0xe8;
        inline constexpr uintptr_t CameraType = 0x158;
        inline constexpr uintptr_t FieldOfView = 0x160;
        inline constexpr uintptr_t Position = 0x11c;
        inline constexpr uintptr_t Rotation = 0xf8;
        inline constexpr uintptr_t Viewport = 0x2ac;
        inline constexpr uintptr_t ViewportSize = 0x2e8;
    }

    namespace CharacterMesh {
        inline constexpr uintptr_t BodyPart = 0x160;
    }

    namespace ClickDetector {
        inline constexpr uintptr_t MaxActivationDistance = 0xfc;
    }

    namespace Clothing {
        inline constexpr uintptr_t Color3 = 0x120;
    }

    namespace ColorCorrectionEffect {
        inline constexpr uintptr_t Brightness = 0xdc;
        inline constexpr uintptr_t Contrast = 0xe0;
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t TintColor = 0xd0;
    }

    namespace ColorGradingEffect {
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t TonemapperPreset = 0xd0;
    }

    namespace DataModel {
        inline constexpr uintptr_t CreatorId = 0x188;
        inline constexpr uintptr_t GameId = 0x190;
        inline constexpr uintptr_t JobId = 0x138;
        inline constexpr uintptr_t PlaceVersion = 0x1b0;
        inline constexpr uintptr_t Pointer = 0x7e35858;
        inline constexpr uintptr_t PrimitiveCount = 0x434;
        inline constexpr uintptr_t ServerIP = 0x5e0;
        inline constexpr uintptr_t Workspace = 0x178;
    }

    namespace DepthOfFieldEffect {
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t FarIntensity = 0xd0;
        inline constexpr uintptr_t FocusDistance = 0xd4;
        inline constexpr uintptr_t InFocusRadius = 0xd8;
        inline constexpr uintptr_t NearIntensity = 0xdc;
    }

    namespace Explosion {
        inline constexpr uintptr_t BlastPressure = 0xec;
        inline constexpr uintptr_t BlastRadius = 0xe8;
        inline constexpr uintptr_t DestroyJointRadiusPercent = 0xfc;
        inline constexpr uintptr_t Position = 0xd8;
        inline constexpr uintptr_t Visible = 0x106;
    }

    namespace FakeDataModel {
        inline constexpr uintptr_t Pointer = 0x7e35858;
        inline constexpr uintptr_t RealDataModel = 0x1c0;
    }

    namespace Fire {
        inline constexpr uintptr_t Color = 0xd8;
        inline constexpr uintptr_t Enabled = 0xf8;
        inline constexpr uintptr_t Size = 0xe8;
    }

    namespace ForceField {
        inline constexpr uintptr_t Visible = 0xce;
    }

    namespace GuiBase2D {
        inline constexpr uintptr_t AbsolutePosition = 0x110;
        inline constexpr uintptr_t AbsoluteRotation = 0x188;
        inline constexpr uintptr_t AbsoluteSize = 0x114;
    }

    namespace GuiObject {
        inline constexpr uintptr_t BackgroundColor3 = 0x540;
        inline constexpr uintptr_t BackgroundTransparency = 0x550;
        inline constexpr uintptr_t BorderColor3 = 0x550;
        inline constexpr uintptr_t LayoutOrder = 0x580;
        inline constexpr uintptr_t Position = 0x510;
        inline constexpr uintptr_t Rotation = 0x188;
        inline constexpr uintptr_t ScreenGui_Enabled = 0x4c8;
        inline constexpr uintptr_t Size = 0x530;
        inline constexpr uintptr_t Visible = 0x5ad;
        inline constexpr uintptr_t ZIndex = 0x5a0;
    }

    namespace HeadAccessory {
        inline constexpr uintptr_t Offset = 0xe8;
        inline constexpr uintptr_t Scale = 0xdc;
    }

    namespace Highlight {
        inline constexpr uintptr_t Adornee = 0x108;
        inline constexpr uintptr_t Enabled = 0x136;
        inline constexpr uintptr_t FillColor = 0x11c;
        inline constexpr uintptr_t FillTransparency = 0x128;
        inline constexpr uintptr_t OutlineTransparency = 0x12c;
    }

    namespace Humanoid {
        inline constexpr uintptr_t AutoJumpEnabled = 0x1d8;
        inline constexpr uintptr_t AutoRotate = 0x1d9;
        inline constexpr uintptr_t AutomaticScalingEnabled = 0x1e3;
        inline constexpr uintptr_t BreakJointsOnDeath = 0x1db;
        inline constexpr uintptr_t CameraOffset = 0x140;
        inline constexpr uintptr_t DisplayDistanceType = 0x18c;
        inline constexpr uintptr_t EvaluateStateMachine = 0x1dc;
        inline constexpr uintptr_t FloorMaterial = 0x190;
        inline constexpr uintptr_t Health = 0x194;
        inline constexpr uintptr_t HealthDisplayDistance = 0x198;
        inline constexpr uintptr_t HealthDisplayType = 0x19c;
        inline constexpr uintptr_t HipHeight = 0x1a4;
        inline constexpr uintptr_t HumanoidRootPart = 0x4c0;
        inline constexpr uintptr_t HumanoidState = 0x8d8;
        inline constexpr uintptr_t HumanoidStateID = 0x20;
        inline constexpr uintptr_t IsWalking = 0x956;
        inline constexpr uintptr_t Jump = 0x1dd;
        inline constexpr uintptr_t JumpHeight = 0x1ac;
        inline constexpr uintptr_t JumpPower = 0x1b0;
        inline constexpr uintptr_t MaxHealth = 0x1b4;
        inline constexpr uintptr_t MaxSlopeAngle = 0x1b8;
        inline constexpr uintptr_t MoveDirection = 0x158;
        inline constexpr uintptr_t MoveToPart = 0x130;
        inline constexpr uintptr_t MoveToPoint = 0x17c;
        inline constexpr uintptr_t NameDisplayDistance = 0x1bc;
        inline constexpr uintptr_t NameOcclusion = 0x1c0;
        inline constexpr uintptr_t PlatformStand = 0x1df;
        inline constexpr uintptr_t RequiresNeck = 0x1e0;
        inline constexpr uintptr_t RigType = 0x1c8;
        inline constexpr uintptr_t SeatPart = 0x120;
        inline constexpr uintptr_t Sit = 0x1e0;
        inline constexpr uintptr_t TargetPoint = 0x164;
        inline constexpr uintptr_t UseJumpPower = 0x1e2;
        inline constexpr uintptr_t Walkspeed = 0x1d4;
        inline constexpr uintptr_t WalkspeedCheck = 0x3c0;
    }

    namespace InputObject {
        inline constexpr uintptr_t MousePosition = 0xe0;
    }

    namespace Instance {
        inline constexpr uintptr_t AttributeContainer = 0x40;
        inline constexpr uintptr_t AttributeList = 0x18;
        inline constexpr uintptr_t AttributeToNext = 0x58;
        inline constexpr uintptr_t AttributeToValue = 0x18;
        inline constexpr uintptr_t ChildrenEnd = 0x8;
        inline constexpr uintptr_t ChildrenStart = 0x70;
        inline constexpr uintptr_t ClassDescriptor = 0x18;
        inline constexpr uintptr_t ClassName = 0x8;
        inline constexpr uintptr_t Name = 0xb0;
        inline constexpr uintptr_t Parent = 0x68;
        inline constexpr uintptr_t This = 0x8;
    }

    namespace Lighting {
        inline constexpr uintptr_t Ambient = 0xd8;
        inline constexpr uintptr_t Brightness = 0x118;
        inline constexpr uintptr_t ClockTime = 0x1bc;
        inline constexpr uintptr_t ColorShift_Bottom = 0xf0;
        inline constexpr uintptr_t ColorShift_Top = 0xe4;
        inline constexpr uintptr_t EnvironmentDiffuseScale = 0x124;
        inline constexpr uintptr_t EnvironmentSpecularScale = 0x128;
        inline constexpr uintptr_t ExposureCompensation = 0x12c;
        inline constexpr uintptr_t FogColor = 0xfc;
        inline constexpr uintptr_t FogEnd = 0x134;
        inline constexpr uintptr_t FogStart = 0x138;
        inline constexpr uintptr_t GeographicLatitude = 0x194;
        inline constexpr uintptr_t GlobalShadows = 0x145;
        inline constexpr uintptr_t GradientBottom = 0x194;
        inline constexpr uintptr_t GradientTop = 0x150;
        inline constexpr uintptr_t LightColor = 0x15c;
        inline constexpr uintptr_t LightDirection = 0x168;
        inline constexpr uintptr_t MoonPosition = 0x17c;
        inline constexpr uintptr_t OutdoorAmbient = 0x108;
        inline constexpr uintptr_t Sky = 0x1d8;
        inline constexpr uintptr_t Source = 0x174;
        inline constexpr uintptr_t SunPosition = 0x178;
    }

    namespace LocalScript {
        inline constexpr uintptr_t ByteCode = 0x1a8;
        inline constexpr uintptr_t Hash = 0x1b8;
    }

    namespace MaterialColors {
        inline constexpr uintptr_t Asphalt = 0x30;
        inline constexpr uintptr_t Basalt = 0x27;
        inline constexpr uintptr_t Brick = 0xf;
        inline constexpr uintptr_t Cobblestone = 0x33;
        inline constexpr uintptr_t Concrete = 0xc;
        inline constexpr uintptr_t CrackedLava = 0x2d;
        inline constexpr uintptr_t Glacier = 0x1b;
        inline constexpr uintptr_t Grass = 0x6;
        inline constexpr uintptr_t Ground = 0x2a;
        inline constexpr uintptr_t Ice = 0x36;
        inline constexpr uintptr_t LeafyGrass = 0x39;
        inline constexpr uintptr_t Limestone = 0x3f;
        inline constexpr uintptr_t Mud = 0x24;
        inline constexpr uintptr_t Pavement = 0x42;
        inline constexpr uintptr_t Rock = 0x18;
        inline constexpr uintptr_t Salt = 0x3c;
        inline constexpr uintptr_t Sand = 0x12;
        inline constexpr uintptr_t Sandstone = 0x21;
        inline constexpr uintptr_t Slate = 0x9;
        inline constexpr uintptr_t Snow = 0x1e;
        inline constexpr uintptr_t WoodPlanks = 0x15;
    }

    namespace MeshPart {
        inline constexpr uintptr_t MeshId = 0x318;
        inline constexpr uintptr_t Texture = 0x318;
    }

    namespace Misc {
        inline constexpr uintptr_t Adornee = 0x100;
        inline constexpr uintptr_t StringLength = 0x10;
        inline constexpr uintptr_t Value = 0xc8;
    }

    namespace Model {
        inline constexpr uintptr_t PrimaryPart = 0x278;
        inline constexpr uintptr_t Scale = 0x164;
    }

    namespace ModuleScript {
        inline constexpr uintptr_t ByteCode = 0x150;
        inline constexpr uintptr_t Hash = 0x160;
    }

    namespace MouseService {
        inline constexpr uintptr_t InputObject = 0x100;
        inline constexpr uintptr_t MousePosition = 0xe0;
    }

    namespace ParticleEmitter {
        inline constexpr uintptr_t Color = 0x100;
        inline constexpr uintptr_t Enabled = 0x128;
        inline constexpr uintptr_t Rate = 0x118;
    }

    namespace Player {
        inline constexpr uintptr_t CameraMode = 0x318;
        inline constexpr uintptr_t Country = 0x110;
        inline constexpr uintptr_t DisplayName = 0x130;
        inline constexpr uintptr_t HealthDisplayDistance = 0x338;
        inline constexpr uintptr_t LocalPlayer = 0x130;
        inline constexpr uintptr_t MaxZoomDistance = 0x310;
        inline constexpr uintptr_t MinZoomDistance = 0x314;
        inline constexpr uintptr_t NameDisplayDistance = 0x344;
        inline constexpr uintptr_t Team = 0x290;
        inline constexpr uintptr_t UserId = 0x2b8;
    }

    namespace PlayerConfigurer {
        inline constexpr uintptr_t Pointer = 0x7e12fd8;
    }

    namespace PointLight {
        inline constexpr uintptr_t Brightness = 0xec;
        inline constexpr uintptr_t Color = 0xd8;
        inline constexpr uintptr_t Enabled = 0xf8;
        inline constexpr uintptr_t Range = 0xf0;
    }

    namespace Primitive {
        inline constexpr uintptr_t AssemblyAngularVelocity = 0xfc;
        inline constexpr uintptr_t AssemblyLinearVelocity = 0xf0;
        inline constexpr uintptr_t Flags = 0x1ae;
        inline constexpr uintptr_t Owner = 0x210;
        inline constexpr uintptr_t Position = 0xe4;
        inline constexpr uintptr_t Rotation = 0xc0;
        inline constexpr uintptr_t Size = 0x1b0;
        inline constexpr uintptr_t Validate = 0x6;
    }

    namespace PrimitiveFlags {
        inline constexpr uintptr_t Anchored = 0x2;
        inline constexpr uintptr_t CanCollide = 0x8;
        inline constexpr uintptr_t CanTouch = 0x10;
    }

    namespace ProximityPrompt {
        inline constexpr uintptr_t ActionText = 0xd0;
        inline constexpr uintptr_t Enabled = 0x156;
        inline constexpr uintptr_t GamepadKeyCode = 0x140;
        inline constexpr uintptr_t HoldDuration = 0x140;
        inline constexpr uintptr_t KeyboardKeyCode = 0x144;
        inline constexpr uintptr_t MaxActivationDistance = 0x148;
        inline constexpr uintptr_t ObjectText = 0xf8;
        inline constexpr uintptr_t RequiresLineOfSight = 0x157;
    }

    namespace RenderView {
        inline constexpr uintptr_t DeviceD3D11 = 0x8;
        inline constexpr uintptr_t LightingValid = 0x148;
        inline constexpr uintptr_t SkyValid = 0x2cd;
        inline constexpr uintptr_t VisualEngine = 0x10;
    }

    namespace RunService {
        inline constexpr uintptr_t HeartbeatTask = 0xe8;
    }

    namespace Seat {
        inline constexpr uintptr_t Occupant = 0x220;
    }

    namespace Sky {
        inline constexpr uintptr_t MoonAngularSize = 0x254;
        inline constexpr uintptr_t MoonTextureId = 0xe0;
        inline constexpr uintptr_t SkyboxBk = 0x110;
        inline constexpr uintptr_t SkyboxDn = 0x140;
        inline constexpr uintptr_t SkyboxFt = 0x170;
        inline constexpr uintptr_t SkyboxLf = 0x1a0;
        inline constexpr uintptr_t SkyboxOrientation = 0x248;
        inline constexpr uintptr_t SkyboxRt = 0x1d0;
        inline constexpr uintptr_t SkyboxUp = 0x200;
        inline constexpr uintptr_t StarCount = 0x260;
        inline constexpr uintptr_t SunAngularSize = 0x250;
        inline constexpr uintptr_t SunTextureId = 0x230;
    }

    namespace Smoke {
        inline constexpr uintptr_t Color = 0xd8;
        inline constexpr uintptr_t Enabled = 0xfe;
        inline constexpr uintptr_t Size = 0xe8;
    }

    namespace Sound {
        inline constexpr uintptr_t Looped = 0x14c;
        inline constexpr uintptr_t PlaybackSpeed = 0x130;
        inline constexpr uintptr_t RollOffMaxDistance = 0x134;
        inline constexpr uintptr_t RollOffMinDistance = 0x138;
        inline constexpr uintptr_t SoundGroup = 0x100;
        inline constexpr uintptr_t SoundId = 0xe0;
        inline constexpr uintptr_t Volume = 0x140;
    }

    namespace Sparkles {
        inline constexpr uintptr_t Enabled = 0xfe;
        inline constexpr uintptr_t SparkleColor = 0xd8;
    }

    namespace SpawnLocation {
        inline constexpr uintptr_t AllowTeamChangeOnTouch = 0x40;
        inline constexpr uintptr_t Enabled = 0x1f5;
        inline constexpr uintptr_t ForcefieldDuration = 0x1e8;
        inline constexpr uintptr_t Neutral = 0x1f6;
        inline constexpr uintptr_t TeamColor = 0x1f0;
    }

    namespace SpecialMesh {
        inline constexpr uintptr_t Scale = 0xdc;
    }

    namespace StarterPlayer {
        inline constexpr uintptr_t CharacterJumpPower = 0x118;
    }

    namespace StatsItem {
        inline constexpr uintptr_t Value = 0x1c0;
    }

    namespace SunRaysEffect {
        inline constexpr uintptr_t Enabled = 0xc8;
        inline constexpr uintptr_t Intensity = 0xd0;
        inline constexpr uintptr_t Spread = 0xd4;
    }

    namespace SurfaceGui {
        inline constexpr uintptr_t Adornee = 0x100;
        inline constexpr uintptr_t Enabled = 0x128;
        inline constexpr uintptr_t Face = 0x124;
    }

    namespace TaskScheduler {
        inline constexpr uintptr_t Pointer = 0x7ad4030;
    }

    namespace Team {
        inline constexpr uintptr_t BrickColor = 0xd0;
    }

    namespace Terrain {
        inline constexpr uintptr_t GrassLength = 0x1f0;
        inline constexpr uintptr_t MaterialColors = 0x278;
        inline constexpr uintptr_t WaterColor = 0x1e4;
        inline constexpr uintptr_t WaterReflectance = 0x1fc;
        inline constexpr uintptr_t WaterTransparency = 0x200;
        inline constexpr uintptr_t WaterWaveSize = 0x204;
        inline constexpr uintptr_t WaterWaveSpeed = 0x208;
    }

    namespace Tool {
        inline constexpr uintptr_t CanBeDropped = 0x4a0;
        inline constexpr uintptr_t Enabled = 0x34d;
        inline constexpr uintptr_t Grip = 0x494;
        inline constexpr uintptr_t ManualActivationOnly = 0x2b0;
        inline constexpr uintptr_t RequiresHandle = 0x4a3;
        inline constexpr uintptr_t Tooltip = 0x458;
    }

    namespace VisualEngine {
        inline constexpr uintptr_t Dimensions = 0x720;
        inline constexpr uintptr_t FakeDataModel = 0x700;
        inline constexpr uintptr_t Pointer = 0x79e9468;
        inline constexpr uintptr_t RenderView = 0x800;
        inline constexpr uintptr_t ViewMatrix = 0x120;
    }

    namespace WeldConstraint {
        inline constexpr uintptr_t Enabled = 0xfe;
        inline constexpr uintptr_t Part0 = 0xd8;
        inline constexpr uintptr_t Part1 = 0xe0;
    }

    namespace Workspace {
        inline constexpr uintptr_t CurrentCamera = 0x4a0;
        inline constexpr uintptr_t DistributedGameTime = 0x4c0;
        inline constexpr uintptr_t ReadOnlyGravity = 0xa28;
        inline constexpr uintptr_t World = 0x3d8;
    }

    namespace World {
        inline constexpr uintptr_t AirProperties = 0x1d8;
        inline constexpr uintptr_t Gravity = 0x1d0;
        inline constexpr uintptr_t Primitives = 0x240;
    }

}
