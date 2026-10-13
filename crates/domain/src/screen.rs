//! View-only screen lease and resource rules; native authorization remains binding.
//! Pure bounds and transient state. Adapters own actual native proof and I/O.

pub use crate::modules::ModuleError;

pub const MAX_VIEW_MS: u64 = 300_000;
// Existing native GrantPayload.tenant limit; the canonical view id is its scope.
pub const MAX_VIEW_ID_BYTES: usize = 64;
pub const ENDPOINT_PROOF_MS: u64 = 60_000;
pub const MAX_NATIVE_GRANT_BYTES: usize = 8192;
pub const FIRST_FRAME_TIMEOUT_MS: u64 = 5000;
pub const FRAME_SILENCE_TIMEOUT_MS: u64 = 3000;
pub const FRAME_STALE_MS: u64 = 3000;
pub const MAX_DISPLAYS: usize = 32;
pub const MAX_VIEWS: usize = 1;
pub const RETAINED_FRAMES: usize = 2;
pub const MAX_ENCODED_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 1920 * 1080 * 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenError {
    Module(ModuleError),
    Denied,
    Expired,
    Closed,
    FrameLimit,
}

#[derive(Clone, Copy)]
pub struct ViewLease {
    display: u32,
    max_fps: u32,
    output_height: u32,
    expires_at_ms: u64,
    admitted_at_ms: u64,
}

impl ViewLease {
    /// Called after the owning NDS use case authorizes the actual devices/display.
    /// The requested expiry must not exceed native grant expiry; shorter grants
    /// are rejected rather than silently clamping the lease. It cannot outlive five minutes;
    /// obtaining another lease requires the owning application's reauthorization.
    pub fn new(
        display: u32,
        max_fps: u32,
        output_height: u32,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<Self, ScreenError> {
        let lease = Self::restore(display, max_fps, output_height, now_ms, expires_at_ms)?;
        lease.remaining_ms(now_ms)?;
        Ok(lease)
    }
    /// Shape-only reconstruction from a store/DTO with the ORIGINAL admission
    /// timestamp. Expired records remain representable; no new lifetime is made.
    /// A restored lease/record is metadata, never current permission to use keys.
    pub fn restore(
        display: u32,
        max_fps: u32,
        output_height: u32,
        admitted_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, ScreenError> {
        if !(1..=60).contains(&max_fps) || !(16..=1080).contains(&output_height) {
            return Err(ScreenError::Module(ModuleError::InvalidInput));
        }
        if expires_at_ms <= admitted_at_ms || expires_at_ms - admitted_at_ms > MAX_VIEW_MS {
            return Err(ScreenError::Expired);
        }
        Ok(Self {
            display,
            max_fps,
            output_height,
            expires_at_ms,
            admitted_at_ms,
        })
    }
    pub fn admitted_at_ms(self) -> u64 {
        self.admitted_at_ms
    }
    pub fn expires_at_ms(self) -> u64 {
        self.expires_at_ms
    }
    pub fn display(self) -> u32 {
        self.display
    }
    pub fn max_fps(self) -> u32 {
        self.max_fps
    }
    pub fn output_height(self) -> u32 {
        self.output_height
    }
    pub fn remaining_ms(self, now_ms: u64) -> Result<u64, ScreenError> {
        if now_ms < self.admitted_at_ms {
            return Err(ScreenError::Expired);
        }
        self.expires_at_ms
            .checked_sub(now_ms)
            .filter(|v| *v > 0)
            .ok_or(ScreenError::Expired)
    }
    /// Native contract mapping supplies verified facts, never unverified claims.
    pub fn admit_grant(
        self,
        view: bool,
        input: bool,
        other_services: bool,
        display_allowed: bool,
        grant_expires_ms: u64,
    ) -> Result<(), ScreenError> {
        if !view
            || input
            || other_services
            || !display_allowed
            || grant_expires_ms < self.expires_at_ms
        {
            return Err(ScreenError::Denied);
        }
        Ok(())
    }
}

pub fn frame_layout(width: u32, height: u32, stride: u32, bytes: usize) -> Result<(), ScreenError> {
    let row = width.checked_mul(4).ok_or(ScreenError::FrameLimit)?;
    let total = (stride as usize)
        .checked_mul(height as usize)
        .ok_or(ScreenError::FrameLimit)?;
    if width == 0
        || height == 0
        || width > 1920
        || height > 1080
        || stride < row
        || total != bytes
        || total > MAX_FRAME_BYTES
    {
        return Err(ScreenError::FrameLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_never_widens_native_view_authority() {
        let lease = ViewLease::new(0, 30, 1080, 2000, 1000).unwrap();
        assert_eq!(lease.remaining_ms(2000), Err(ScreenError::Expired));
        assert_eq!(lease.admit_grant(true, false, false, true, 2000), Ok(()));
        assert_eq!(
            lease.admit_grant(true, true, false, true, 2000),
            Err(ScreenError::Denied)
        );
        assert_eq!(
            lease.admit_grant(true, false, true, true, 2000),
            Err(ScreenError::Denied)
        );
        assert_eq!(
            lease.admit_grant(true, false, false, false, 2000),
            Err(ScreenError::Denied)
        );
        assert_eq!(
            lease.admit_grant(true, false, false, true, 1999),
            Err(ScreenError::Denied)
        );
        assert!(ViewLease::new(0, 61, 1080, 2000, 1000).is_err());
        assert!(ViewLease::new(0, 30, 1080, 301001, 1000).is_err());
    }
    #[test]
    fn frame_layout_refuses_size_confusion_before_publication() {
        assert_eq!(frame_layout(1920, 1080, 7680, MAX_FRAME_BYTES), Ok(()));
        for (w, h, s, n) in [
            (0, 1, 4, 4),
            (1921, 1080, 7684, MAX_FRAME_BYTES + 4320),
            (1, 1, 3, 3),
            (1, 2, 4, 4),
            (1, 1, u32::MAX, usize::MAX),
        ] {
            assert_eq!(frame_layout(w, h, s, n), Err(ScreenError::FrameLimit));
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ScreenSupport {
    Supported,
    ServiceDisabled,
    CaptureUnavailable,
    CodecUnsupported,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Display {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

/// A native observation, separate from authorization or visible presentation.
pub struct ScreenCapabilities {
    pub support: ScreenSupport,
    pub displays: Vec<Display>,
}
impl ScreenCapabilities {
    pub fn new(
        service: bool,
        capture: bool,
        h264: bool,
        displays: Vec<Display>,
    ) -> Result<Self, ModuleError> {
        if displays.len() > MAX_DISPLAYS {
            return Err(ModuleError::InvalidResponse);
        }
        let mut ids = std::collections::BTreeSet::new();
        if displays.iter().any(|d| {
            d.width == 0 || d.height == 0 || d.width > 8192 || d.height > 8192 || !ids.insert(d.id)
        }) {
            return Err(ModuleError::InvalidResponse);
        }
        let support = if !service {
            ScreenSupport::ServiceDisabled
        } else if !capture || displays.is_empty() {
            ScreenSupport::CaptureUnavailable
        } else if !h264 {
            ScreenSupport::CodecUnsupported
        } else {
            ScreenSupport::Supported
        };
        Ok(Self { support, displays })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenPhase {
    AwaitingFrame,
    FrameAvailable,
    Stalled,
    Ended,
}

/// Ephemeral read state, never a guarantee of physical display. Renderer
/// lifetime remains I/O; ordinary render lifecycle plus real pixel acceptance
/// establishes presentation. There is no independent receipt coordinator.
pub struct ViewProgress {
    epoch: u64,
    started_ms: u64,
    received: Option<(u64, u64)>,
    ended: bool,
}
impl ViewProgress {
    pub fn new(epoch: u64, now_ms: u64) -> Result<Self, ModuleError> {
        if epoch == 0 {
            return Err(ModuleError::InvalidInput);
        }
        Ok(Self {
            epoch,
            started_ms: now_ms,
            received: None,
            ended: false,
        })
    }
    pub fn received(&mut self, epoch: u64, seq: u64, now_ms: u64) -> Result<(), ModuleError> {
        if self.ended
            || epoch != self.epoch
            || seq == u64::MAX
            || now_ms < self.started_ms
            || self
                .received
                .is_some_and(|(old, time)| seq <= old || now_ms < time)
        {
            return Err(ModuleError::InvalidInput);
        }
        self.received = Some((seq, now_ms));
        Ok(())
    }
    pub fn phase(&self, now_ms: u64) -> ScreenPhase {
        if self.ended {
            return ScreenPhase::Ended;
        }
        match self.received {
            None if now_ms >= self.started_ms
                && now_ms - self.started_ms < FIRST_FRAME_TIMEOUT_MS =>
            {
                ScreenPhase::AwaitingFrame
            }
            Some((_, time)) if now_ms >= time && now_ms - time < FRAME_STALE_MS => {
                ScreenPhase::FrameAvailable
            }
            _ => ScreenPhase::Stalled,
        }
    }
    pub fn end(&mut self) {
        self.ended = true;
        self.received = None;
    }
}
#[cfg(test)]
mod lifetime_tests {
    use super::*;
    #[test]
    fn received_state_is_bounded_by_epoch_freshness_and_terminal_end() {
        let mut state = ViewProgress::new(1, 0).unwrap();
        assert_eq!(state.phase(0), ScreenPhase::AwaitingFrame);
        assert_eq!(state.received(2, 0, 100), Err(ModuleError::InvalidInput));
        state.received(1, 0, 100).unwrap();
        assert_eq!(state.phase(100), ScreenPhase::FrameAvailable);
        assert_eq!(state.phase(3100), ScreenPhase::Stalled);
        state.end();
        assert_eq!(state.received(1, 1, 3101), Err(ModuleError::InvalidInput));
        assert_eq!(state.phase(3101), ScreenPhase::Ended);
    }
}

/// Match the native even-dimension downscale policy without enlarging the
/// renderer's 1920x1080 allocation bound or changing aspect ratio.
pub fn fit_video_height(width: u32, height: u32, requested: u32) -> Result<u32, ModuleError> {
    if width == 0
        || height == 0
        || width > 8192
        || height > 8192
        || !(16..=1080).contains(&requested)
    {
        return Err(ModuleError::InvalidInput);
    }
    let width_bound = (1920u64 * u64::from(height) / u64::from(width)) as u32;
    let fitted = requested.min(height).min(width_bound) & !1;
    let fitted_width = (u64::from(width) * u64::from(fitted) / u64::from(height)) as u32 & !1;
    if fitted < 16 || fitted_width < 2 {
        return Err(ModuleError::InvalidInput);
    }
    Ok(fitted)
}
#[cfg(test)]
mod geometry_tests {
    use super::*;
    #[test]
    fn fit_preserves_wide_and_portrait_layouts_with_even_codec_dimensions() {
        assert_eq!(fit_video_height(5120, 1440, 1080), Ok(540));
        assert_eq!(fit_video_height(1440, 5120, 1080), Ok(1080));
        assert_eq!(fit_video_height(640, 480, 1080), Ok(480));
        assert_eq!(
            fit_video_height(0, 1440, 1080),
            Err(ModuleError::InvalidInput)
        );
    }
}

/// Stored only after the canonical adapter transaction verified NDS device
/// authority AND endpoint-key possession. Constructing this data is not proof.
#[derive(Clone)]
pub struct EndpointBinding {
    pub device: crate::DeviceId,
    pub endpoint: [u8; 32],
    pub revision: u64,
    /// UUID bytes generated once per endpoint instance, retained across retries.
    pub instance_id: [u8; 16],
}

/// Shared proof framing. `origin` is the configured canonical control origin,
/// validated by the URL adapter; nonce/device/expiry must match SignedRequest.
/// This function never verifies Ed25519, authenticates a device or consumes nonce.
pub fn endpoint_signing_bytes(
    origin: &str,
    device: &crate::DeviceId,
    endpoint: &[u8; 32],
    instance_id: &[u8; 16],
    base_revision: u64,
    nonce: &str,
    expires_at_ms: u64,
) -> Result<Vec<u8>, ModuleError> {
    if instance_id.iter().all(|byte| *byte == 0)
        || origin.is_empty()
        || origin.len() > 512
        || !origin.bytes().all(|b| b.is_ascii_graphic())
        || base_revision >= crate::sync::MAX_REVISION
        || expires_at_ms == 0
        || !(16..=128).contains(&nonce.len())
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(ModuleError::InvalidInput);
    }
    let mut bytes = b"NDS-RDS-ENDPOINT-BINDING-V2\0".to_vec();
    for field in [origin.as_bytes(), device.as_str().as_bytes()] {
        bytes.extend_from_slice(&(field.len() as u16).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(endpoint);
    bytes.extend_from_slice(instance_id);
    bytes.extend_from_slice(&base_revision.to_be_bytes());
    bytes.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    bytes.extend_from_slice(nonce.as_bytes());
    bytes.extend_from_slice(&expires_at_ms.to_be_bytes());
    Ok(bytes)
}

/// Finite authorization intent, separate from native permission and frame state.
#[derive(Clone)]
pub struct ViewPermit {
    pub viewer: crate::DeviceId,
    pub host: crate::DeviceId,
    pub viewer_endpoint: [u8; 32],
    pub host_endpoint: [u8; 32],
    pub viewer_revision: u64,
    pub host_revision: u64,
    pub lease: ViewLease,
}
impl ViewPermit {
    /// A native host signer is always this endpoint; never an external/server
    /// issuer supplied by a wire caller. RDS I/O verifies the actual signature.
    pub fn native_issuer(&self) -> [u8; 32] {
        self.host_endpoint
    }
}
/// Passive facts mapped AFTER the native adapter verifies the actual signature.
/// Constructing this value in a unit test is not native authentication.
pub struct NativeGrantFacts<'a> {
    pub issuer: [u8; 32],
    pub subject: [u8; 32],
    pub audience: [u8; 32],
    pub expires_at_ms: u64,
    pub tenant: Option<&'a str>,
    pub policy_revision: Option<u64>,
    pub desktop_view: bool,
    pub desktop_control: bool,
    pub other_services: bool,
    pub display_allowed: bool,
}
impl ViewPermit {
    /// NDS-owned exact match, in addition to the qualified generic lease rule.
    /// The adapter must also check actual crypto/expiry and current local fence.
    fn match_native_grant(&self, native: &NativeGrantFacts<'_>) -> Result<(), ScreenError> {
        if native.issuer != self.host_endpoint
            || native.subject != self.viewer_endpoint
            || native.audience != self.host_endpoint
            || native.expires_at_ms != self.lease.expires_at_ms()
        {
            return Err(ScreenError::Denied);
        }
        self.lease.admit_grant(
            native.desktop_view,
            native.desktop_control,
            native.other_services,
            native.display_allowed,
            native.expires_at_ms,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewState {
    Requested,
    Ready,
    Ended,
}

/// Public projection mapped from generated server DTOs. Contains no server
/// session digest/auth model. Restoring data does not authenticate its source:
/// NdsClient must validate the response and check Accounts LocalUseFence at use.
#[derive(Clone)]
pub struct ViewProjection {
    id: String,
    permit: ViewPermit,
    state: ViewState,
}
impl ViewProjection {
    pub fn restore(id: String, permit: ViewPermit, state: ViewState) -> Result<Self, ModuleError> {
        if !crate::valid_identifier(&id)
            || id.len() > MAX_VIEW_ID_BYTES
            || permit.viewer == permit.host
            || permit.viewer_endpoint == permit.host_endpoint
            || !(1..=crate::sync::MAX_REVISION).contains(&permit.viewer_revision)
            || !(1..=crate::sync::MAX_REVISION).contains(&permit.host_revision)
            || !permit.lease.expires_at_ms().is_multiple_of(1000)
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(Self { id, permit, state })
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Native HostPolicy pins tenant=id() and min_policy_revision=host_revision.
    /// The client matcher requires EXACT revision, not only the native floor.
    /// This is a context check after native crypto and current Accounts fence.
    pub fn match_native_grant(
        &mut self,
        native: &NativeGrantFacts<'_>,
        now_ms: u64,
    ) -> Result<(), ScreenError> {
        if self.state(now_ms) != ViewState::Ready {
            return Err(ScreenError::Closed);
        }
        if native.tenant != Some(self.id.as_str())
            || native.policy_revision != Some(self.permit.host_revision)
        {
            return Err(ScreenError::Denied);
        }
        self.permit.match_native_grant(native)
    }
    pub fn permit(&self) -> &ViewPermit {
        &self.permit
    }
    /// Canonical producer transition; server revalidation is mandatory before
    /// calling it. Ready means an artifact, never visible or authenticated pixels.
    pub fn ready(&mut self, now_ms: u64) -> Result<(), ScreenError> {
        if self.state == ViewState::Ended {
            return Err(ScreenError::Closed);
        }
        if self.permit.lease.remaining_ms(now_ms).is_err() {
            self.end();
            return Err(ScreenError::Expired);
        }
        self.state = ViewState::Ready;
        Ok(())
    }
    pub fn state(&mut self, now_ms: u64) -> ViewState {
        if self.permit.lease.remaining_ms(now_ms).is_err() {
            self.end();
        }
        self.state
    }
    pub fn end(&mut self) {
        self.state = ViewState::Ended;
    }
    pub fn occupies(&self, device: &crate::DeviceId, now_ms: u64) -> bool {
        self.state != ViewState::Ended
            && self.permit.lease.remaining_ms(now_ms).is_ok()
            && (device == &self.permit.viewer || device == &self.permit.host)
    }
}
/// Server-only record adds revocation provenance to the public projection.
/// SQL adapters reconstruct the public data and this digest from retained rows;
/// no fake session is needed to represent Ready/Ended/expired metadata.
pub struct ViewIntent {
    public: ViewProjection,
    viewer_session: crate::identity::ProtectedDigest,
}
impl ViewIntent {
    pub fn new(
        id: String,
        permit: ViewPermit,
        viewer_session: crate::identity::ProtectedDigest,
    ) -> Result<Self, ModuleError> {
        Ok(Self::restore(
            ViewProjection::restore(id, permit, ViewState::Requested)?,
            viewer_session,
        ))
    }
    pub fn restore(
        public: ViewProjection,
        viewer_session: crate::identity::ProtectedDigest,
    ) -> Self {
        Self {
            public,
            viewer_session,
        }
    }
    pub fn public(&self) -> &ViewProjection {
        &self.public
    }
    pub fn viewer_session(&self) -> crate::identity::ProtectedDigest {
        self.viewer_session
    }
    pub fn permit(&self) -> &ViewPermit {
        self.public.permit()
    }
    pub fn ready(&mut self, now_ms: u64) -> Result<(), ScreenError> {
        self.public.ready(now_ms)
    }
    pub fn state(&mut self, now_ms: u64) -> ViewState {
        self.public.state(now_ms)
    }
    pub fn end(&mut self) {
        self.public.end();
    }
    pub fn occupies(&self, device: &crate::DeviceId, now_ms: u64) -> bool {
        self.public.occupies(device, now_ms)
    }
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    #[test]
    fn proof_transcript_binds_exact_fields_with_unambiguous_lengths() {
        let device = crate::DeviceId::new("viewer").unwrap();
        let message = endpoint_signing_bytes(
            "https://control.invalid",
            &device,
            &[3; 32],
            &[9; 16],
            1,
            "screen_nonce_0001",
            60000,
        )
        .unwrap();
        let mut expected = b"NDS-RDS-ENDPOINT-BINDING-V2\0".to_vec();
        for field in [b"https://control.invalid".as_slice(), b"viewer".as_slice()] {
            expected.extend_from_slice(&(field.len() as u16).to_be_bytes());
            expected.extend_from_slice(field);
        }
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&[9; 16]);
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&17u16.to_be_bytes());
        expected.extend_from_slice(b"screen_nonce_0001");
        expected.extend_from_slice(&60000u64.to_be_bytes());
        assert_eq!(message, expected);
        for other in [
            endpoint_signing_bytes(
                "https://other.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                1,
                "screen_nonce_0001",
                60000,
            )
            .unwrap(),
            endpoint_signing_bytes(
                "https://control.invalid",
                &crate::DeviceId::new("host").unwrap(),
                &[3; 32],
                &[9; 16],
                1,
                "screen_nonce_0001",
                60000,
            )
            .unwrap(),
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[4; 32],
                &[9; 16],
                1,
                "screen_nonce_0001",
                60000,
            )
            .unwrap(),
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                2,
                "screen_nonce_0001",
                60000,
            )
            .unwrap(),
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                1,
                "screen_nonce_0002",
                60000,
            )
            .unwrap(),
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                1,
                "screen_nonce_0001",
                60001,
            )
            .unwrap(),
        ] {
            assert_ne!(message, other);
        }
        assert!(message.len() < 2048);
        assert!(
            endpoint_signing_bytes(
                "",
                &device,
                &[3; 32],
                &[9; 16],
                1,
                "screen_nonce_0001",
                60000
            )
            .is_err()
        );
        assert!(
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                crate::sync::MAX_REVISION,
                "screen_nonce_0001",
                60000
            )
            .is_err()
        );
        assert!(
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[9; 16],
                1,
                "bad nonce",
                60000
            )
            .is_err()
        );
    }
    #[test]
    fn instance_is_signed_and_nil_instance_is_rejected() {
        let device = crate::DeviceId::new("viewer").unwrap();
        let first = endpoint_signing_bytes(
            "https://control.invalid",
            &device,
            &[3; 32],
            &[9; 16],
            0,
            "screen_nonce_0001",
            60000,
        )
        .unwrap();
        let other = endpoint_signing_bytes(
            "https://control.invalid",
            &device,
            &[3; 32],
            &[8; 16],
            0,
            "screen_nonce_0001",
            60000,
        )
        .unwrap();
        assert_ne!(first, other);
        assert!(
            endpoint_signing_bytes(
                "https://control.invalid",
                &device,
                &[3; 32],
                &[0; 16],
                0,
                "screen_nonce_0001",
                60000
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod reconstruction_tests {
    use super::*;
    fn public_permit() -> ViewPermit {
        ViewPermit {
            viewer: crate::DeviceId::new("viewer").unwrap(),
            host: crate::DeviceId::new("host").unwrap(),
            viewer_endpoint: [3; 32],
            host_endpoint: [4; 32],
            viewer_revision: 1,
            host_revision: 2,
            lease: ViewLease::restore(0, 30, 1080, 1000, 4000).unwrap(),
        }
    }
    #[test]
    fn public_dto_and_server_rows_restore_ready_ended_and_expired_without_new_authority() {
        // Only public DTO-shaped values are needed here; no server auth/digest.
        let mut ready =
            ViewProjection::restore("view".into(), public_permit(), ViewState::Ready).unwrap();
        assert_eq!(ready.state(2000), ViewState::Ready);
        assert_eq!(ready.permit().lease.admitted_at_ms(), 1000);
        assert_eq!(ready.permit().lease.expires_at_ms(), 4000);
        ready.ready(3000).unwrap();
        assert_eq!(ready.permit().lease.expires_at_ms(), 4000);
        let mut ended =
            ViewProjection::restore("view".into(), public_permit(), ViewState::Ended).unwrap();
        assert_eq!(ended.ready(2000), Err(ScreenError::Closed));
        // Server-only reconstruction adds the actual retained provenance later.
        let mut record = ViewIntent::restore(ended, crate::identity::ProtectedDigest([8; 32]));
        assert_eq!(record.state(2000), ViewState::Ended);
        assert_eq!(record.viewer_session().0, [8; 32]);
        let mut expired =
            ViewProjection::restore("view".into(), public_permit(), ViewState::Ready).unwrap();
        assert_eq!(expired.state(5000), ViewState::Ended);
        assert_eq!(expired.ready(2000), Err(ScreenError::Closed));
        let mut expired_record =
            ViewIntent::restore(expired, crate::identity::ProtectedDigest([8; 32]));
        assert_eq!(expired_record.state(2000), ViewState::Ended);
        assert!(ViewLease::restore(0, 30, 1080, 1000, 301001).is_err());
        assert!(ViewLease::restore(0, 30, 1080, 1000, 1000).is_err());
        assert!(ViewLease::restore(0, 61, 1080, 1000, 4000).is_err());
    }
    #[test]
    fn nds_native_grant_has_exact_identity_expiry_and_scope_while_legacy_rule_is_preserved() {
        let permit = public_permit();
        let mut projection =
            ViewProjection::restore("view".into(), permit.clone(), ViewState::Ready).unwrap();
        let mut facts = NativeGrantFacts {
            issuer: [4; 32],
            subject: [3; 32],
            audience: [4; 32],
            expires_at_ms: 4000,
            tenant: Some("view"),
            policy_revision: Some(2),
            desktop_view: true,
            desktop_control: false,
            other_services: false,
            display_allowed: true,
        };
        assert_eq!(projection.match_native_grant(&facts, 2000), Ok(()));
        facts.issuer = [9; 32];
        assert_eq!(
            projection.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        facts.issuer = [4; 32];
        facts.subject = [9; 32];
        assert_eq!(
            projection.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        facts.subject = [3; 32];
        facts.audience = [9; 32];
        assert_eq!(
            projection.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        facts.audience = [4; 32];
        for expiry in [3999, 4001] {
            facts.expires_at_ms = expiry;
            assert_eq!(
                projection.match_native_grant(&facts, 2000),
                Err(ScreenError::Denied)
            );
        }
        facts.expires_at_ms = 4000;
        facts.desktop_control = true;
        assert!(projection.match_native_grant(&facts, 2000).is_err());
        facts.desktop_control = false;
        facts.other_services = true;
        assert!(projection.match_native_grant(&facts, 2000).is_err());
        facts.other_services = false;
        facts.display_allowed = false;
        assert!(projection.match_native_grant(&facts, 2000).is_err());
        assert_eq!(
            permit.lease.admit_grant(true, false, false, true, 4001),
            Ok(())
        );
        // These are equality/scope tests, not cryptographic verification.
    }
}

#[cfg(test)]
mod intent_binding_tests {
    use super::*;
    fn permit(revision: u64) -> ViewPermit {
        ViewPermit {
            viewer: crate::DeviceId::new("viewer").unwrap(),
            host: crate::DeviceId::new("host").unwrap(),
            viewer_endpoint: [3; 32],
            host_endpoint: [4; 32],
            viewer_revision: 1,
            host_revision: revision,
            lease: ViewLease::restore(0, 30, 1080, 1000, 4000).unwrap(),
        }
    }
    #[test]
    fn old_grant_never_matches_another_intent_or_new_host_instance() {
        let mut first =
            ViewProjection::restore("view_a".into(), permit(2), ViewState::Ready).unwrap();
        let mut second =
            ViewProjection::restore("view_b".into(), permit(2), ViewState::Ready).unwrap();
        let mut facts = NativeGrantFacts {
            issuer: [4; 32],
            subject: [3; 32],
            audience: [4; 32],
            expires_at_ms: 4000,
            tenant: Some("view_a"),
            policy_revision: Some(2),
            desktop_view: true,
            desktop_control: false,
            other_services: false,
            display_allowed: true,
        };
        assert_eq!(first.match_native_grant(&facts, 2000), Ok(()));
        first.end();
        assert_eq!(
            first.match_native_grant(&facts, 2000),
            Err(ScreenError::Closed)
        );
        assert_eq!(
            second.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        facts.tenant = Some("view_b");
        assert_eq!(second.match_native_grant(&facts, 2000), Ok(()));
        for revision in [None, Some(1), Some(3)] {
            facts.policy_revision = revision;
            assert_eq!(
                second.match_native_grant(&facts, 2000),
                Err(ScreenError::Denied)
            );
        }
        facts.policy_revision = Some(2);
        facts.tenant = None;
        assert_eq!(
            second.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        // Fresh host registration retires binding revision even with identical keys.
        let mut restarted =
            ViewProjection::restore("view_b".into(), permit(3), ViewState::Ready).unwrap();
        facts.tenant = Some("view_b");
        assert_eq!(
            restarted.match_native_grant(&facts, 2000),
            Err(ScreenError::Denied)
        );
        facts.policy_revision = Some(3);
        assert_eq!(restarted.match_native_grant(&facts, 2000), Ok(()));
        assert!(ViewProjection::restore("a".repeat(64), permit(2), ViewState::Ready).is_ok());
        assert!(ViewProjection::restore("a".repeat(65), permit(2), ViewState::Ready).is_err());
        // Pure context checks only; actual Agent authz tenant/floor+crypto is a later runtime gate.
    }
}

#[cfg(test)]
mod admission_clock_tests {
    use super::*;
    #[test]
    fn restored_context_fails_closed_before_original_admission_and_cannot_revive() {
        let lease = ViewLease::restore(0, 30, 480, 1000, 4000).unwrap();
        assert_eq!(lease.remaining_ms(1000), Ok(3000));
        assert_eq!(lease.remaining_ms(999), Err(ScreenError::Expired));
        let permit = ViewPermit {
            viewer: crate::DeviceId::new("viewer").unwrap(),
            host: crate::DeviceId::new("host").unwrap(),
            viewer_endpoint: [3; 32],
            host_endpoint: [4; 32],
            viewer_revision: 1,
            host_revision: 2,
            lease,
        };
        let mut restored =
            ViewProjection::restore("view".into(), permit, ViewState::Ready).unwrap();
        assert_eq!(restored.state(999), ViewState::Ended);
        assert_eq!(restored.ready(1000), Err(ScreenError::Closed));
        let mut server = ViewIntent::restore(restored, crate::identity::ProtectedDigest([1; 32]));
        assert_eq!(server.state(1000), ViewState::Ended);
    }
}
