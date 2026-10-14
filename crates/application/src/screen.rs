//! Pure checks over supplied facts. SignedRequest must come from the existing
//! HTTP verifier; Device/Binding/Intent rows must be current canonical rows.
//! Neither these functions nor dummy test inputs authenticate any endpoint.
use crate::{
    lifecycle::ClientLifecycle,
    sync::{SignedRequest, active},
};
use nddev_device_sync_domain::{
    DeviceId, Platform,
    devices::{Device, DeviceStatus},
    identity::AuthenticatedSession,
    screen::{
        ENDPOINT_PROOF_MS, EndpointBinding, MAX_NATIVE_GRANT_BYTES, ScreenError, ViewIntent,
        ViewLease, ViewPermit, ViewProjection, endpoint_signing_bytes,
    },
    sync::MAX_REVISION,
};
use std::future::Future;

pub struct EndpointClaim {
    pub endpoint: [u8; 32],
    /// A new endpoint instance generates this once; lost-ACK retries retain it.
    pub instance_id: [u8; 16],
    pub base_revision: u64,
    pub nonce: String,
    pub expires_at_ms: u64,
}
/// Candidate plus exact proof bytes, NOT a verified binding. The owning
/// transaction must verify a canonical/nonweak Ed25519 key and its signature
/// over these bytes before persisting, and recheck session/device/nonce/revision.
pub fn validate_endpoint_claim(
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    device: &Device,
    current: Option<&EndpointBinding>,
    claim: EndpointClaim,
    configured_origin: &str,
    now_ms: u64,
) -> Result<(EndpointBinding, Vec<u8>), ScreenError> {
    active(auth, signed, now_ms).map_err(|_| ScreenError::Denied)?;
    if !owned_active(auth, device)
        || signed.device != device.id
        || claim.nonce != signed.nonce
        || claim.expires_at_ms != signed.expires_at_ms
        || claim.expires_at_ms > auth.session.expires_at_ms
        || claim.expires_at_ms > now_ms.saturating_add(ENDPOINT_PROOF_MS)
    {
        return Err(ScreenError::Denied);
    }
    if claim.instance_id.iter().all(|byte| *byte == 0)
        || current.is_some_and(|binding| {
            binding.device != device.id
                || binding.revision == 0
                || binding.revision > MAX_REVISION
                || binding.instance_id.iter().all(|byte| *byte == 0)
        })
    {
        return Err(ScreenError::Denied);
    }
    // A retry is identified by the exact instance AND immutable key/base.
    // Every attempt still authenticates fresh NDS context and fresh endpoint PoP.
    let revision = match current {
        Some(binding) if binding.instance_id == claim.instance_id => {
            if binding.endpoint != claim.endpoint
                || binding.revision.checked_sub(1) != Some(claim.base_revision)
            {
                return Err(ScreenError::Denied);
            }
            binding.revision
        }
        _ => {
            let base = current.map_or(0, |binding| binding.revision);
            if base != claim.base_revision || base >= MAX_REVISION {
                return Err(ScreenError::Denied);
            }
            base + 1
        }
    };
    let bytes = endpoint_signing_bytes(
        configured_origin,
        &signed.device,
        &claim.endpoint,
        &claim.instance_id,
        claim.base_revision,
        &claim.nonce,
        claim.expires_at_ms,
    )
    .map_err(ScreenError::Module)?;
    Ok((
        EndpointBinding {
            device: device.id.clone(),
            endpoint: claim.endpoint,
            instance_id: claim.instance_id,
            revision,
        },
        bytes,
    ))
}
fn owned_active(auth: &AuthenticatedSession, device: &Device) -> bool {
    device.owner == auth.session.owner && device.status == DeviceStatus::Active
}

pub struct ViewRequest {
    pub target: DeviceId,
    pub viewer_revision: u64,
    pub host_revision: u64,
    pub display: u32,
    pub max_fps: u32,
    pub output_height: u32,
    pub expires_at_ms: u64,
    pub idempotency_key: String,
}
pub struct ViewRows<'a> {
    pub viewer: &'a Device,
    pub host: &'a Device,
    pub viewer_binding: &'a EndpointBinding,
    pub host_binding: &'a EndpointBinding,
    /// Queried under the same authorization/admission lock. At most two
    /// participant records are needed; no independent client/global registry.
    pub viewer_active: Option<&'a ViewIntent>,
    pub host_active: Option<&'a ViewIntent>,
}
fn current_pair(auth: &AuthenticatedSession, rows: &ViewRows<'_>) -> bool {
    owned_active(auth, rows.viewer)
        && owned_active(auth, rows.host)
        && rows.viewer.id != rows.host.id
        && rows.viewer_binding.device == rows.viewer.id
        && rows.host_binding.device == rows.host.id
        && (1..=MAX_REVISION).contains(&rows.viewer_binding.revision)
        && (1..=MAX_REVISION).contains(&rows.host_binding.revision)
        && rows.viewer_binding.endpoint != rows.host_binding.endpoint
}
/// New request only. Idempotent replay must reauthorize current rows and return
/// the ORIGINAL intent/profile/expiry, never reconstruct or renew this permit.
pub fn authorize_view(
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    rows: ViewRows<'_>,
    request: ViewRequest,
    now_ms: u64,
) -> Result<ViewPermit, ScreenError> {
    active(auth, signed, now_ms).map_err(|_| ScreenError::Denied)?;
    if !current_pair(auth, &rows)
        || signed.device != rows.viewer.id
        || request.target != rows.host.id
        || request.viewer_revision != rows.viewer_binding.revision
        || request.host_revision != rows.host_binding.revision
        || request.expires_at_ms > auth.session.expires_at_ms
        || request.idempotency_key.is_empty()
        || request.idempotency_key.len() > 256
        || !request
            .idempotency_key
            .bytes()
            .all(|b| b.is_ascii_graphic())
    {
        return Err(ScreenError::Denied);
    }
    for (slot, device) in [
        (rows.viewer_active, &rows.viewer.id),
        (rows.host_active, &rows.host.id),
    ] {
        if slot.is_some_and(|intent| intent.occupies(device, now_ms)) {
            return Err(ScreenError::Module(
                nddev_device_sync_domain::modules::ModuleError::Busy,
            ));
        }
    }
    // Check the requested upper bound first; return one explicit accepted
    // whole-second boundary matching native grants. No later silent clamp.
    ViewLease::new(
        request.display,
        request.max_fps,
        request.output_height,
        request.expires_at_ms,
        now_ms,
    )?;
    let lease = ViewLease::new(
        request.display,
        request.max_fps,
        request.output_height,
        request.expires_at_ms / 1000 * 1000,
        now_ms,
    )?;
    Ok(ViewPermit {
        viewer: rows.viewer.id.clone(),
        host: rows.host.id.clone(),
        viewer_endpoint: rows.viewer_binding.endpoint,
        host_endpoint: rows.host_binding.endpoint,
        viewer_revision: request.viewer_revision,
        host_revision: request.host_revision,
        lease,
    })
}
#[derive(Clone, Copy)]
pub enum ViewActor {
    Viewer,
    Host,
}

/// Current authorization for active permission/delivery or idempotent replay. Native
/// authority and signature verification remain mandatory outside the core.
pub fn revalidate_view(
    auth: &AuthenticatedSession,
    signed: &SignedRequest,
    rows: ViewRows<'_>,
    permit: &ViewPermit,
    actor: ViewActor,
    now_ms: u64,
) -> Result<(), ScreenError> {
    active(auth, signed, now_ms).map_err(|_| ScreenError::Denied)?;
    if !current_pair(auth, &rows)
        || (&signed.device
            != match actor {
                ViewActor::Viewer => &permit.viewer,
                ViewActor::Host => &permit.host,
            })
        || permit.viewer != rows.viewer.id
        || permit.host != rows.host.id
        || permit.viewer_revision != rows.viewer_binding.revision
        || permit.host_revision != rows.host_binding.revision
        || permit.viewer_endpoint != rows.viewer_binding.endpoint
        || permit.host_endpoint != rows.host_binding.endpoint
        || permit.lease.expires_at_ms() > auth.session.expires_at_ms
    {
        return Err(ScreenError::Denied);
    }
    permit.lease.remaining_ms(now_ms)?;
    Ok(())
}
/// LOCAL reports only, never a wire/saved-state flag or a proof of OS consent.
/// An X11 authenticated display/source is access, not a system consent dialog.
pub struct HostAccess {
    pub local_device: DeviceId,
    pub local_endpoint: [u8; 32],
    /// Revision returned by the fresh registration of THIS local instance.
    pub local_binding_revision: u64,
    pub local_opt_in: bool,
    pub source_ready: bool,
    pub display: u32,
    pub source_expires_at_ms: u64,
    pub lifecycle: ClientLifecycle,
    pub platform: Platform,
}
/// Client-local guard over actual server-permitted public data and actual local
/// reports. No SQL rows, server digest, AuthenticatedSession or fake SignedRequest.
/// NdsClient must separately check Accounts LocalUseFence immediately before any
/// endpoint key/grant/capture use; this pure predicate cannot authenticate it.
pub fn authorize_host(
    view: &mut ViewProjection,
    local: &HostAccess,
    now_ms: u64,
) -> Result<(), ScreenError> {
    if view.state(now_ms) == nddev_device_sync_domain::screen::ViewState::Ended {
        return Err(ScreenError::Closed);
    }
    let permit = view.permit();
    if local.local_device != permit.host
        || local.local_endpoint != permit.host_endpoint
        || local.local_binding_revision != permit.host_revision
        || !local.local_opt_in
        || !local.source_ready
        || local.display != permit.lease.display()
        || local.source_expires_at_ms < permit.lease.expires_at_ms()
        || !local.lifecycle.permits_work(local.platform)
    {
        return Err(ScreenError::Denied);
    }
    Ok(())
}
/// Size check only; native parsing/signature/scope remains the RDS adapter.
pub fn native_grant_payload(bytes: &[u8]) -> Result<(), ScreenError> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_GRANT_BYTES {
        return Err(ScreenError::Module(
            nddev_device_sync_domain::modules::ModuleError::InvalidInput,
        ));
    }
    Ok(())
}

/// Canonical server control port, not a native grant/registry framework.
/// Every operation uses the existing identity/device authorization transaction:
/// recheck exact live session, enrolled key/device/owner, binding revisions and
/// revocation (including the original viewer session via intent.viewer_session()),
/// consume fresh nonce even before idempotent replay. That server-only session
/// reference is not a wire/presentation field. Binding also
/// verifies the actual endpoint PoP/key, origin/transcript and endpoint uniqueness.
/// A NEW endpoint/host instance registers a fresh proof and advances the
/// existing binding revision even with the same key and a NEW instance UUID.
/// A retry retains exact instance UUID/key/original base while refreshing the
/// signed nonce/expiry and endpoint proof. Consume nonce and verify both proofs
/// before returning the same current row; no revision/intent mutation on replay.
/// Changed key/base with the same id conflicts. A replaced row cannot replay its
/// old original base. No historical id/result registry is needed. Heartbeat/unchanged
/// observations do not call bind. Old live intents retire. Create uses a unique
/// view id <=64 bytes, never reused after End/restart. Native tenant is that id
/// and native policy_revision is the host binding revision; no epoch registry.
/// Create atomically checks participant slots and commits original fingerprint,
/// idempotency key, immutable intent/profile/expiry/result. Replay mismatch is a
/// conflict; expiry/Ended never restarts or renews it. No success before commit.
/// Ready rechecks the current host and both rows before storing opaque <=8KiB
/// native bytes; delivery rechecks viewer and both rows. RDS independently verifies
/// issuer==host endpoint, subject/audience/display/DesktopView-only/scope/expiry.
/// Incoming is bounded to one participant intent. End/revoke shares this lock.
/// End authenticates the owner/participant but does not require a live grant or
/// matching old binding; ending an already ended/expired intent is idempotent.
/// No key, frame, sequence, capture authority or per-frame receipt is durable.
pub trait ScreenStore: Send + Sync {
    /// Read the target's current binding before creating a view. The requester
    /// and target must both be active devices owned by the current session.
    /// A missing binding is unavailable screen capability, not a new identity.
    fn binding(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        target: &DeviceId,
        now_ms: u64,
    ) -> impl Future<Output = Result<Option<EndpointBinding>, ScreenError>> + Send;
    fn bind(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        claim: EndpointClaim,
        signature: [u8; 64],
        now_ms: u64,
    ) -> impl Future<Output = Result<EndpointBinding, ScreenError>> + Send;
    fn create(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        request: ViewRequest,
        original_body: Vec<u8>,
        now_ms: u64,
    ) -> impl Future<Output = Result<ViewIntent, ScreenError>> + Send;
    fn incoming(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        now_ms: u64,
    ) -> impl Future<Output = Result<Option<ViewIntent>, ScreenError>> + Send;
    fn view(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<(ViewIntent, Option<Vec<u8>>), ScreenError>> + Send;
    /// Reject an empty or >MAX_NATIVE_GRANT_BYTES body before retaining it.
    fn ready(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        native_grant: Vec<u8>,
        now_ms: u64,
    ) -> impl Future<Output = Result<ViewIntent, ScreenError>> + Send;
    fn end(
        &self,
        auth: &AuthenticatedSession,
        signed: SignedRequest,
        id: &str,
        now_ms: u64,
    ) -> impl Future<Output = Result<(), ScreenError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::{
        TenantId, UserId,
        devices::{DeviceName, DevicePlatform, PublicDeviceKey},
        identity::{AuthMethod, Owner, ProtectedDigest, Session},
        modules::ModuleError,
        screen::ViewState,
    };
    // Mathematical fixture facts, not a signature/endpoint authentication test.
    struct Case {
        auth: AuthenticatedSession,
        signed: SignedRequest,
        viewer: Device,
        host: Device,
        viewer_binding: EndpointBinding,
        host_binding: EndpointBinding,
    }
    impl Case {
        fn new() -> Self {
            let owner = Owner {
                user_id: UserId::new("owner").unwrap(),
                tenant_id: TenantId::new("tenant").unwrap(),
            };
            let device = |name| Device {
                id: DeviceId::new(name).unwrap(),
                owner: owner.clone(),
                platform: DevicePlatform::Linux,
                name: DeviceName::new("Fixture".into()).unwrap(),
                public_key: PublicDeviceKey([1; 32]),
                status: DeviceStatus::Active,
                created_at_ms: 1000,
            };
            let viewer = device("viewer");
            let host = device("host");
            Self {
                auth: AuthenticatedSession {
                    session: Session::new(owner, AuthMethod::EmailOtp, 1000).unwrap(),
                    binding: ProtectedDigest([1; 32]),
                },
                signed: SignedRequest {
                    device: viewer.id.clone(),
                    nonce: "screen_nonce_0001".into(),
                    expires_at_ms: 60000,
                    fingerprint: [2; 32],
                },
                viewer_binding: EndpointBinding {
                    device: viewer.id.clone(),
                    endpoint: [3; 32],
                    instance_id: [3; 16],
                    revision: 1,
                },
                host_binding: EndpointBinding {
                    device: host.id.clone(),
                    endpoint: [4; 32],
                    instance_id: [4; 16],
                    revision: 2,
                },
                viewer,
                host,
            }
        }
        fn rows(&self) -> ViewRows<'_> {
            ViewRows {
                viewer: &self.viewer,
                host: &self.host,
                viewer_binding: &self.viewer_binding,
                host_binding: &self.host_binding,
                viewer_active: None,
                host_active: None,
            }
        }
        fn request(&self) -> ViewRequest {
            ViewRequest {
                target: self.host.id.clone(),
                viewer_revision: 1,
                host_revision: 2,
                display: 0,
                max_fps: 30,
                output_height: 1080,
                expires_at_ms: 3999,
                idempotency_key: "view_001".into(),
            }
        }
        fn permit(&self) -> Result<ViewPermit, ScreenError> {
            authorize_view(&self.auth, &self.signed, self.rows(), self.request(), 1500)
        }
        fn claim(&self) -> EndpointClaim {
            EndpointClaim {
                endpoint: [3; 32],
                instance_id: [9; 16],
                base_revision: 0,
                nonce: self.signed.nonce.clone(),
                expires_at_ms: self.signed.expires_at_ms,
            }
        }
        fn binding(
            &self,
            claim: EndpointClaim,
            current: Option<&EndpointBinding>,
        ) -> Result<(EndpointBinding, Vec<u8>), ScreenError> {
            validate_endpoint_claim(
                &self.auth,
                &self.signed,
                &self.viewer,
                current,
                claim,
                "https://control.invalid",
                1500,
            )
        }
    }
    #[test]
    fn endpoint_claim_matches_exact_fresh_signed_context_and_revision() {
        let mut c = Case::new();
        let (candidate, bytes) = c.binding(c.claim(), None).unwrap();
        assert_eq!(candidate.revision, 1);
        assert_eq!(candidate.endpoint, [3; 32]);
        assert_eq!(
            bytes,
            endpoint_signing_bytes(
                "https://control.invalid",
                &c.signed.device,
                &[3; 32],
                &[9; 16],
                0,
                &c.signed.nonce,
                60000
            )
            .unwrap()
        );
        let mut claim = c.claim();
        claim.nonce = "different_nonce_01".into();
        assert!(c.binding(claim, None).is_err());
        let mut claim = c.claim();
        claim.expires_at_ms -= 1;
        assert!(c.binding(claim, None).is_err());
        let mut claim = c.claim();
        claim.base_revision = 1;
        assert!(c.binding(claim, None).is_err());
        c.signed.expires_at_ms = 61501;
        assert!(c.binding(c.claim(), None).is_err());
        c.signed.expires_at_ms = 61500;
        assert!(c.binding(c.claim(), None).is_ok());
        c.auth.session.expires_at_ms = 61499;
        assert!(c.binding(c.claim(), None).is_err());
        let mut c = Case::new();
        c.signed.device = c.host.id.clone();
        assert!(c.binding(c.claim(), None).is_err());
        let c = Case::new();
        let mut claim = c.claim();
        claim.base_revision = 1;
        assert_eq!(
            c.binding(claim, Some(&c.viewer_binding))
                .unwrap()
                .0
                .revision,
            2
        );
        let mut claim = c.claim();
        claim.base_revision = 1;
        claim.endpoint = [5; 32];
        assert_eq!(
            c.binding(claim, Some(&c.viewer_binding))
                .unwrap()
                .0
                .revision,
            2
        );
    }
    #[test]
    fn current_owner_active_devices_and_both_binding_revisions_are_required() {
        let c = Case::new();
        assert!(c.permit().is_ok());
        for viewer in [true, false] {
            let mut c = Case::new();
            let device = if viewer { &mut c.viewer } else { &mut c.host };
            device.owner.user_id = UserId::new("other").unwrap();
            assert!(c.permit().is_err());
            let mut c = Case::new();
            let device = if viewer { &mut c.viewer } else { &mut c.host };
            device.status = DeviceStatus::Revoked;
            assert!(c.permit().is_err());
            let mut c = Case::new();
            let binding = if viewer {
                &mut c.viewer_binding
            } else {
                &mut c.host_binding
            };
            binding.revision += 1;
            assert!(c.permit().is_err());
            let mut c = Case::new();
            let binding = if viewer {
                &mut c.viewer_binding
            } else {
                &mut c.host_binding
            };
            binding.device = DeviceId::new("unrelated").unwrap();
            assert!(c.permit().is_err());
        }
        let mut c = Case::new();
        c.signed.device = c.host.id.clone();
        assert!(c.permit().is_err());
        let mut c = Case::new();
        c.host_binding.endpoint = c.viewer_binding.endpoint;
        assert!(c.permit().is_err());
        let mut c = Case::new();
        c.host.id = c.viewer.id.clone();
        assert!(c.permit().is_err());
    }
    #[test]
    fn finite_profile_expiry_and_single_participant_slot_are_enforced() {
        let c = Case::new();
        let permit = c.permit().unwrap();
        assert_eq!(permit.lease.expires_at_ms(), 3000);
        assert_eq!(permit.native_issuer(), c.host_binding.endpoint);
        let mut request = c.request();
        request.expires_at_ms = 301500;
        assert!(authorize_view(&c.auth, &c.signed, c.rows(), request, 1500).is_ok());
        let mut request = c.request();
        request.expires_at_ms = 301501;
        assert!(authorize_view(&c.auth, &c.signed, c.rows(), request, 1500).is_err());
        let mut request = c.request();
        request.expires_at_ms = 1999;
        assert!(authorize_view(&c.auth, &c.signed, c.rows(), request, 1998).is_err());
        let mut request = c.request();
        request.max_fps = 61;
        assert!(authorize_view(&c.auth, &c.signed, c.rows(), request, 1500).is_err());
        let mut intent = ViewIntent::new("view_001".into(), permit, c.auth.binding).unwrap();
        let mut rows = c.rows();
        rows.viewer_active = Some(&intent);
        assert!(matches!(
            authorize_view(&c.auth, &c.signed, rows, c.request(), 1500),
            Err(ScreenError::Module(ModuleError::Busy))
        ));
        intent.ready(1500).unwrap();
        let mut rows = c.rows();
        rows.host_active = Some(&intent);
        assert!(matches!(
            authorize_view(&c.auth, &c.signed, rows, c.request(), 1500),
            Err(ScreenError::Module(ModuleError::Busy))
        ));
        intent.end();
        let mut rows = c.rows();
        rows.host_active = Some(&intent);
        assert!(authorize_view(&c.auth, &c.signed, rows, c.request(), 1500).is_ok());
    }
    #[test]
    fn rotation_revocation_or_shorter_session_invalidates_current_permission() {
        let mut c = Case::new();
        let permit = c.permit().unwrap();
        revalidate_view(
            &c.auth,
            &c.signed,
            c.rows(),
            &permit,
            ViewActor::Viewer,
            1500,
        )
        .unwrap();
        assert!(
            revalidate_view(&c.auth, &c.signed, c.rows(), &permit, ViewActor::Host, 1500).is_err()
        );
        c.host_binding.endpoint = [7; 32];
        assert!(
            revalidate_view(
                &c.auth,
                &c.signed,
                c.rows(),
                &permit,
                ViewActor::Viewer,
                1500
            )
            .is_err()
        );
        let mut c = Case::new();
        let permit = c.permit().unwrap();
        c.viewer.status = DeviceStatus::Revoked;
        assert!(
            revalidate_view(
                &c.auth,
                &c.signed,
                c.rows(),
                &permit,
                ViewActor::Viewer,
                1500
            )
            .is_err()
        );
        let mut c = Case::new();
        let permit = c.permit().unwrap();
        c.auth.session.expires_at_ms = 2999;
        assert!(
            revalidate_view(
                &c.auth,
                &c.signed,
                c.rows(),
                &permit,
                ViewActor::Viewer,
                1500
            )
            .is_err()
        );
        let c = Case::new();
        let permit = c.permit().unwrap();
        assert_eq!(
            revalidate_view(
                &c.auth,
                &c.signed,
                c.rows(),
                &permit,
                ViewActor::Viewer,
                3000
            ),
            Err(ScreenError::Expired)
        );
    }
    #[test]
    fn host_needs_actual_local_guard_matching_endpoint_display_and_lifecycle() {
        let c = Case::new();
        let permit = c.permit().unwrap();
        let mut view = ViewProjection::restore(
            "view".into(),
            permit,
            nddev_device_sync_domain::screen::ViewState::Requested,
        )
        .unwrap();
        let mut local = HostAccess {
            local_device: c.host.id.clone(),
            local_endpoint: c.host_binding.endpoint,
            local_binding_revision: c.host_binding.revision,
            local_opt_in: false,
            source_ready: true,
            display: 0,
            source_expires_at_ms: 3000,
            lifecycle: ClientLifecycle::Resumed,
            platform: Platform::Linux,
        };
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.local_opt_in = true;
        authorize_host(&mut view, &local, 1500).unwrap();
        local.local_endpoint = [8; 32];
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.local_endpoint = c.host_binding.endpoint;
        local.source_ready = false;
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.source_ready = true;
        local.display = 1;
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.display = 0;
        local.source_expires_at_ms = 2999;
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.source_expires_at_ms = 3000;
        local.lifecycle = ClientLifecycle::Inactive;
        authorize_host(&mut view, &local, 1500).unwrap();
        local.platform = Platform::Android;
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.platform = Platform::Linux;
        local.lifecycle = ClientLifecycle::Hidden;
        assert!(authorize_host(&mut view, &local, 1500).is_err());
        local.lifecycle = ClientLifecycle::Resumed;
        view.end();
        assert_eq!(
            authorize_host(&mut view, &local, 1500),
            Err(ScreenError::Closed)
        );
    }
    #[test]
    fn ended_or_observed_expired_intent_never_renews_or_restarts() {
        let c = Case::new();
        let mut intent =
            ViewIntent::new("view".into(), c.permit().unwrap(), c.auth.binding).unwrap();
        assert_eq!(intent.viewer_session(), c.auth.binding);
        intent.ready(1600).unwrap();
        intent.ready(1700).unwrap();
        assert_eq!(intent.permit().lease.expires_at_ms(), 3000);
        assert_eq!(intent.ready(3000), Err(ScreenError::Expired));
        assert_eq!(intent.state(1500), ViewState::Ended);
        assert_eq!(intent.ready(1500), Err(ScreenError::Closed));
        assert!(native_grant_payload(&[1]).is_ok());
        assert!(native_grant_payload(&[]).is_err());
        assert!(native_grant_payload(&vec![0; 8193]).is_err());
    }
    #[test]
    fn lost_ack_retry_with_fresh_nonce_returns_original_binding() {
        let mut c = Case::new();
        let (first, _) = c.binding(c.claim(), None).unwrap();
        c.signed.nonce = "screen_nonce_0002".into();
        c.signed.expires_at_ms = 61000;
        // Same logical registration and base, new legal signed context/PoP.
        let (retry, _) = c.binding(c.claim(), Some(&first)).unwrap();
        assert_eq!(retry.revision, first.revision);
        assert_eq!(retry.endpoint, first.endpoint);
    }
    #[test]
    fn registration_id_distinguishes_retry_restart_and_mismatch() {
        let mut c = Case::new();
        let (first, _) = c.binding(c.claim(), None).unwrap();
        c.signed.nonce = "screen_nonce_0002".into();
        c.signed.expires_at_ms = 61000;
        let (retry, proof) = c.binding(c.claim(), Some(&first)).unwrap();
        assert_eq!(retry.instance_id, first.instance_id);
        assert_eq!(retry.revision, 1);
        // Fresh transcript includes new nonce/expiry and the stable instance id.
        let original = core_proof(&c, &first, "screen_nonce_0001", 60000);
        assert_ne!(proof, original);
        let mut changed = c.claim();
        changed.endpoint = [5; 32];
        assert!(c.binding(changed, Some(&first)).is_err());
        let mut changed = c.claim();
        changed.base_revision = 1;
        assert!(c.binding(changed, Some(&first)).is_err());
        let mut restart = c.claim();
        restart.instance_id = [8; 16];
        assert!(c.binding(restart, Some(&first)).is_err()); // old base is not CAS
        let mut restart = c.claim();
        restart.instance_id = [8; 16];
        restart.base_revision = 1;
        let (next, _) = c.binding(restart, Some(&first)).unwrap();
        assert_eq!(next.endpoint, first.endpoint);
        assert_eq!(next.revision, 2);
        assert_ne!(next.instance_id, first.instance_id);
        assert!(c.binding(c.claim(), Some(&next)).is_err()); // superseded lost ACK
        c.auth.session.expires_at_ms = 1500;
        assert!(c.binding(c.claim(), Some(&first)).is_err()); // replay cannot bypass auth
    }
    fn core_proof(c: &Case, binding: &EndpointBinding, nonce: &str, expiry: u64) -> Vec<u8> {
        endpoint_signing_bytes(
            "https://control.invalid",
            &c.signed.device,
            &binding.endpoint,
            &binding.instance_id,
            0,
            nonce,
            expiry,
        )
        .unwrap()
    }
}

#[cfg(test)]
mod client_projection_tests {
    use super::*;
    use nddev_device_sync_domain::screen::ViewState;
    #[test]
    fn client_local_guard_uses_public_projection_without_server_auth_or_rows() {
        let lease = ViewLease::restore(0, 30, 1080, 1000, 4000).unwrap();
        let permit = ViewPermit {
            viewer: DeviceId::new("viewer").unwrap(),
            host: DeviceId::new("host").unwrap(),
            viewer_endpoint: [3; 32],
            host_endpoint: [4; 32],
            viewer_revision: 1,
            host_revision: 2,
            lease,
        };
        let mut view = ViewProjection::restore("view".into(), permit, ViewState::Ready).unwrap();
        let mut local = HostAccess {
            local_device: DeviceId::new("host").unwrap(),
            local_endpoint: [4; 32],
            local_binding_revision: 2,
            local_opt_in: true,
            source_ready: true,
            display: 0,
            source_expires_at_ms: 4000,
            lifecycle: ClientLifecycle::Resumed,
            platform: Platform::Linux,
        };
        authorize_host(&mut view, &local, 2000).unwrap();
        local.local_binding_revision = 3;
        assert!(authorize_host(&mut view, &local, 2000).is_err());
        local.local_binding_revision = 2;

        local.local_device = DeviceId::new("different").unwrap();
        assert!(authorize_host(&mut view, &local, 2000).is_err());
        local.local_device = DeviceId::new("host").unwrap();
        assert_eq!(
            authorize_host(&mut view, &local, 5000),
            Err(ScreenError::Closed)
        );
        assert_eq!(
            authorize_host(&mut view, &local, 2000),
            Err(ScreenError::Closed)
        );
        // NdsClient must still check current Accounts LocalUseFence before keys;
        // reconstructing a cached projection alone cannot authorize capture.
    }
}
