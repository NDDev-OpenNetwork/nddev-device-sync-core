//! An invitation grants membership only after proof of its intended recipient.
//! Token generation, protected verification, delivery and atomic storage are I/O.
use super::{CompanyRole, Membership, OrganizationError};
use crate::{InvitationId, identity::Owner};

pub const INVITATION_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const MAX_PENDING_INVITATIONS: usize = 128;
pub const MEMBER_PAGE_LIMIT: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

/// Storage metadata contains no token, verifier, email address or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationMetadata {
    pub id: InvitationId,
    pub issuer: Owner,
    pub recipient: Owner,
    pub role: CompanyRole,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: InvitationStatus,
}

pub struct Invitation(InvitationMetadata);

impl Invitation {
    pub fn issue(
        id: InvitationId,
        administrator: &Membership,
        actor: &Owner,
        recipient: Owner,
        role: CompanyRole,
        now: u64,
    ) -> Result<Self, OrganizationError> {
        administrator.authorize_administration(actor, &recipient.tenant_id)?;
        if actor == &recipient {
            return Err(OrganizationError::InvalidInput);
        }
        Self::restore(InvitationMetadata {
            id,
            issuer: actor.clone(),
            recipient,
            role,
            issued_at_ms: now,
            expires_at_ms: now
                .checked_add(INVITATION_LIFETIME_MS)
                .ok_or(OrganizationError::InvalidInput)?,
            status: InvitationStatus::Pending,
        })
    }

    pub fn restore(metadata: InvitationMetadata) -> Result<Self, OrganizationError> {
        if metadata.issuer.tenant_id != metadata.recipient.tenant_id
            || metadata.issuer.user_id == metadata.recipient.user_id
            || metadata.expires_at_ms <= metadata.issued_at_ms
            || metadata.expires_at_ms - metadata.issued_at_ms > INVITATION_LIFETIME_MS
        {
            return Err(OrganizationError::InvalidState);
        }
        Ok(Self(metadata))
    }

    pub fn metadata(&self) -> &InvitationMetadata {
        &self.0
    }

    /// The adapter has verified both the protected invitation token and the
    /// intended recipient's authentication proof. Recheck the current issuer
    /// under the same transaction as activation and session creation.
    /// Persist observed expiry even when acceptance is denied.
    pub fn accept(
        &mut self,
        verified_recipient: &Owner,
        current_issuer: &Membership,
        now: u64,
    ) -> Result<Membership, OrganizationError> {
        self.observe_expiry(now)?;
        if self.0.status != InvitationStatus::Pending
            || verified_recipient != &self.0.recipient
            || current_issuer.owner != self.0.issuer
        {
            return Err(OrganizationError::InvitationUnavailable);
        }
        current_issuer
            .authorize_administration(&self.0.issuer, &self.0.recipient.tenant_id)
            .map_err(|_| OrganizationError::InvitationUnavailable)?;
        self.0.status = InvitationStatus::Accepted;
        Ok(Membership {
            owner: self.0.recipient.clone(),
            role: self.0.role,
            active: true,
        })
    }

    /// Revoking an accepted invitation cannot remove an established member.
    /// Membership removal uses the independent last-administrator guard.
    pub fn revoke(
        &mut self,
        administrator: &Membership,
        actor: &Owner,
        now: u64,
    ) -> Result<(), OrganizationError> {
        administrator.authorize_administration(actor, &self.0.recipient.tenant_id)?;
        self.observe_expiry(now)?;
        match self.0.status {
            InvitationStatus::Pending => self.0.status = InvitationStatus::Revoked,
            InvitationStatus::Accepted => return Err(OrganizationError::InvitationUnavailable),
            InvitationStatus::Revoked | InvitationStatus::Expired => {}
        }
        Ok(())
    }

    fn observe_expiry(&mut self, now: u64) -> Result<(), OrganizationError> {
        if now < self.0.issued_at_ms {
            return Err(OrganizationError::InvitationUnavailable);
        }
        if now >= self.0.expires_at_ms && self.0.status == InvitationStatus::Pending {
            self.0.status = InvitationStatus::Expired;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TenantId, UserId};

    fn owner(company: &str, user: &str) -> Owner {
        Owner {
            tenant_id: TenantId::new(company).unwrap(),
            user_id: UserId::new(user).unwrap(),
        }
    }

    fn issuer() -> Membership {
        Membership {
            owner: owner("company", "admin"),
            role: CompanyRole::Admin,
            active: true,
        }
    }

    fn pending() -> Invitation {
        let admin = issuer();
        Invitation::issue(
            InvitationId::new("invitation").unwrap(),
            &admin,
            &admin.owner,
            owner("company", "recipient"),
            CompanyRole::User,
            1000,
        )
        .unwrap()
    }

    #[test]
    fn acceptance_is_bound_to_the_exact_recipient_and_current_issuer() {
        let admin = issuer();
        for stranger in [owner("other", "recipient"), owner("company", "stranger")] {
            let mut value = pending();
            assert_eq!(
                value.accept(&stranger, &admin, 1001),
                Err(OrganizationError::InvitationUnavailable)
            );
            assert_eq!(value.metadata().status, InvitationStatus::Pending);
        }
        let recipient = owner("company", "recipient");
        for wrong in [
            Membership {
                active: false,
                ..admin.clone()
            },
            Membership {
                role: CompanyRole::User,
                ..admin.clone()
            },
            Membership {
                owner: owner("company", "another-admin"),
                ..admin.clone()
            },
        ] {
            assert_eq!(
                pending().accept(&recipient, &wrong, 1001),
                Err(OrganizationError::InvitationUnavailable)
            );
        }
        let mut value = pending();
        let accepted = value.accept(&recipient, &admin, 1001).unwrap();
        assert_eq!(
            accepted,
            Membership {
                owner: recipient.clone(),
                role: CompanyRole::User,
                active: true
            }
        );
        assert_eq!(
            value.accept(&recipient, &admin, 1002),
            Err(OrganizationError::InvitationUnavailable)
        );
        assert_eq!(
            value.revoke(&admin, &admin.owner, 1002),
            Err(OrganizationError::InvitationUnavailable)
        );
        assert_eq!(value.metadata().status, InvitationStatus::Accepted);
    }

    #[test]
    fn expiry_and_revocation_remain_terminal_after_clock_rollback_and_restore() {
        let admin = issuer();
        let recipient = owner("company", "recipient");
        let mut expired = pending();
        assert_eq!(
            expired.accept(&recipient, &admin, 1000 + INVITATION_LIFETIME_MS),
            Err(OrganizationError::InvitationUnavailable)
        );
        let mut restored = Invitation::restore(expired.metadata().clone()).unwrap();
        assert_eq!(
            restored.accept(&recipient, &admin, 1001),
            Err(OrganizationError::InvitationUnavailable)
        );
        assert_eq!(restored.metadata().status, InvitationStatus::Expired);
        let mut revoked = pending();
        revoked.revoke(&admin, &admin.owner, 1001).unwrap();
        revoked.revoke(&admin, &admin.owner, 1002).unwrap();
        assert_eq!(
            revoked.accept(&recipient, &admin, 1000),
            Err(OrganizationError::InvitationUnavailable)
        );
        assert_eq!(revoked.metadata().status, InvitationStatus::Revoked);
    }

    #[test]
    fn issuance_and_restoration_reject_cross_company_or_invalid_authority() {
        let admin = issuer();
        let recipient = owner("company", "recipient");
        assert!(
            Invitation::issue(
                InvitationId::new("id").unwrap(),
                &admin,
                &recipient,
                recipient.clone(),
                CompanyRole::Admin,
                1000
            )
            .is_err()
        );
        assert!(
            Invitation::issue(
                InvitationId::new("id").unwrap(),
                &admin,
                &admin.owner,
                owner("other", "recipient"),
                CompanyRole::Admin,
                1000
            )
            .is_err()
        );
        assert!(
            Invitation::issue(
                InvitationId::new("id").unwrap(),
                &admin,
                &admin.owner,
                recipient,
                CompanyRole::User,
                u64::MAX
            )
            .is_err()
        );
        let original = pending().metadata().clone();
        for invalid in [
            InvitationMetadata {
                recipient: owner("other", "recipient"),
                ..original.clone()
            },
            InvitationMetadata {
                expires_at_ms: 1000,
                ..original.clone()
            },
            InvitationMetadata {
                expires_at_ms: 1001 + INVITATION_LIFETIME_MS,
                ..original
            },
        ] {
            assert!(Invitation::restore(invalid).is_err());
        }
    }
}
