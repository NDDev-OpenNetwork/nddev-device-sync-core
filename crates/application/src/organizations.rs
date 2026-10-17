//! Company control use cases and ports. Adapters supply current membership under
//! the same transaction as session/device verification, receipt and state writes.
use crate::{
    identity::{EmailAddress, IdentityCrypto, Locale, ProtectedDigest, SecretText},
    sync::{SignedRequest, StoredResult, active},
};
use nddev_device_sync_domain::{
    InvitationId, UserId,
    identity::AuthenticatedSession,
    organizations::{
        Company, CompanyRole, Membership, MembershipChange, OrganizationError,
        commands::{CommandId, DeliveryState},
        invitations::InvitationMetadata,
    },
    sync::MAX_REVISION,
};
use std::future::Future;

pub struct Context {
    pub auth: AuthenticatedSession,
    pub signed: SignedRequest,
    pub now_ms: u64,
}
pub fn authorize(
    context: &Context,
    member: &Membership,
    command: Option<&CommandId>,
    now: u64,
    administrative: bool,
) -> Result<(), OrganizationError> {
    active(&context.auth, &context.signed, now).map_err(|_| OrganizationError::Denied)?;
    let owner = &context.auth.session.owner;
    if administrative {
        member.authorize_administration(owner, &owner.tenant_id)?;
    } else {
        member.authorize_personal(owner, owner)?;
    }
    if let Some(command) = command {
        command.validate(now)?;
    }
    Ok(())
}

pub struct Member {
    pub membership: Membership,
    pub revision: u64,
    pub email: Option<EmailAddress>,
}
impl Member {
    pub fn change(
        &self,
        administrator: &Membership,
        actor: &nddev_device_sync_domain::identity::Owner,
        expected: u64,
        change: MembershipChange,
        active_administrators: usize,
    ) -> Result<(Membership, u64), OrganizationError> {
        if !(1..=MAX_REVISION).contains(&self.revision) {
            return Err(OrganizationError::InvalidState);
        }
        administrator.authorize_administration(actor, &self.membership.owner.tenant_id)?;
        if expected != self.revision {
            return Err(OrganizationError::Conflict);
        }
        let next = self
            .membership
            .change(administrator, actor, change, active_administrators)?;
        let revision = if next == self.membership {
            self.revision
        } else {
            self.revision
                .checked_add(1)
                .filter(|value| *value <= MAX_REVISION)
                .ok_or(OrganizationError::RevisionExhausted)?
        };
        Ok((next, revision))
    }
}
pub struct Overview {
    pub company: Company,
    pub member: Member,
}
pub struct InvitationRecord {
    pub metadata: InvitationMetadata,
    pub email: EmailAddress,
    pub delivery: DeliveryState,
}
pub struct Page<T> {
    pub entries: Vec<T>,
    pub next_cursor: Option<String>,
}

pub struct InvitationRequest {
    pub email: EmailAddress,
    pub role: CompanyRole,
    pub locale: Locale,
}
pub struct PreparedInvitation {
    pub id: InvitationId,
    pub request: InvitationRequest,
    pub recipient_binding: ProtectedDigest,
    pub recipient_subject: ProtectedDigest,
    pub verifier: ProtectedDigest,
    pub token: SecretText,
}
pub struct InvitationMessage {
    pub id: InvitationId,
    pub recipient: EmailAddress,
    pub token: SecretText,
    pub expires_at_ms: u64,
    pub delivery_deadline_ms: u64,
    pub locale: Locale,
}
pub struct CreatedInvitation {
    pub result: StoredResult,
    /// Present only after a new committed creation. Receipt replay never resends.
    pub delivery: Option<InvitationMessage>,
}
pub trait InvitationDelivery: Send + Sync {
    fn available(&self) -> bool;
    fn queue(&self, message: InvitationMessage) -> Result<(), OrganizationError>;
}
pub trait OrganizationStore: Send + Sync {
    fn overview(
        &self,
        context: &Context,
    ) -> impl Future<Output = Result<Overview, OrganizationError>> + Send;
    fn members(
        &self,
        context: &Context,
        after: Option<UserId>,
    ) -> impl Future<Output = Result<Page<Member>, OrganizationError>> + Send;
    fn invitations(
        &self,
        context: &Context,
        after: Option<InvitationId>,
    ) -> impl Future<Output = Result<Page<InvitationRecord>, OrganizationError>> + Send;
    fn create(
        &self,
        context: &Context,
        command: &CommandId,
        invitation: PreparedInvitation,
    ) -> impl Future<Output = Result<CreatedInvitation, OrganizationError>> + Send;
    fn revoke(
        &self,
        context: &Context,
        command: &CommandId,
        invitation: &InvitationId,
    ) -> impl Future<Output = Result<StoredResult, OrganizationError>> + Send;
    fn change(
        &self,
        context: &Context,
        command: &CommandId,
        target: &UserId,
        expected: u64,
        change: MembershipChange,
    ) -> impl Future<Output = Result<StoredResult, OrganizationError>> + Send;
    fn delivery(
        &self,
        id: &InvitationId,
        state: DeliveryState,
    ) -> impl Future<Output = Result<(), OrganizationError>> + Send;
}

pub async fn create_invitation<S: OrganizationStore, C: IdentityCrypto, D: InvitationDelivery>(
    store: &S,
    crypto: &C,
    delivery: &D,
    context: &Context,
    command: &CommandId,
    request: InvitationRequest,
) -> Result<StoredResult, OrganizationError> {
    command.validate(context.now_ms)?;
    let id = InvitationId::new(
        crypto
            .token()
            .map_err(|_| OrganizationError::Unavailable)?
            .into_inner(),
    )
    .map_err(|_| OrganizationError::Unavailable)?;
    let token = crypto.token().map_err(|_| OrganizationError::Unavailable)?;
    let prepared = PreparedInvitation {
        verifier: crypto.protect(
            "company_invitation",
            &[id.as_str().as_bytes(), token.expose().as_bytes()],
        ),
        recipient_binding: crypto.protect("owner_binding", &[request.email.as_str().as_bytes()]),
        recipient_subject: crypto.protect("email_subject", &[request.email.as_str().as_bytes()]),
        id,
        token,
        request,
    };
    // Availability is observed after storage so an existing receipt remains
    // replayable during SMTP downtime. A new resource has an explicit failure
    // state if its bounded queue cannot accept the one-use delivery material.
    let created = store.create(context, command, prepared).await?;
    if let Some(message) = created.delivery {
        let id = message.id.clone();
        if !delivery.available() || delivery.queue(message).is_err() {
            store.delivery(&id, DeliveryState::Failed).await?;
        }
    }
    Ok(created.result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::{TenantId, identity::Owner};
    #[test]
    fn member_revision_fences_changes_and_preserves_last_admin_policy() {
        let owner = Owner {
            user_id: UserId::new("admin").unwrap(),
            tenant_id: TenantId::new("company").unwrap(),
        };
        let member = Member {
            membership: Membership {
                owner: owner.clone(),
                role: CompanyRole::Admin,
                active: true,
            },
            revision: 4,
            email: None,
        };
        assert_eq!(
            member.change(&member.membership, &owner, 3, MembershipChange::Remove, 2),
            Err(OrganizationError::Conflict)
        );
        assert_eq!(
            member.change(&member.membership, &owner, 4, MembershipChange::Remove, 1),
            Err(OrganizationError::LastAdministrator)
        );
        assert_eq!(
            member
                .change(
                    &member.membership,
                    &owner,
                    4,
                    MembershipChange::SetRole(CompanyRole::Admin),
                    1
                )
                .unwrap()
                .1,
            4
        );
        let (next, revision) = member
            .change(&member.membership, &owner, 4, MembershipChange::Remove, 2)
            .unwrap();
        assert!(!next.active);
        assert_eq!(next.owner, owner);
        assert_eq!(revision, 5);
        let exhausted = Member {
            revision: MAX_REVISION,
            ..member
        };
        assert_eq!(
            exhausted.change(
                &exhausted.membership,
                &owner,
                MAX_REVISION,
                MembershipChange::Remove,
                2
            ),
            Err(OrganizationError::RevisionExhausted)
        );
    }
}
