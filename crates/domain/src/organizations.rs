//! Company membership and the narrow administrative RDS exception (ADR 0011).
//!
//! Adapters must load current memberships and revalidate the authenticated actor
//! at the same transaction boundary as the authorized mutation or grant. A UI
//! role, cached membership or supplied tenant ID is not an authority source.
use crate::identity::Owner;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompanyRole {
    Admin,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Membership {
    /// The existing tenant identity is the company identity; user ownership stays
    /// unchanged. No parallel company ID or shared company vault is introduced.
    pub owner: Owner,
    pub role: CompanyRole,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrganizationError {
    #[error("company_access_denied")]
    Denied,
    #[error("company_last_administrator")]
    LastAdministrator,
    #[error("company_membership_state_invalid")]
    InvalidState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipChange {
    SetRole(CompanyRole),
    Remove,
}

impl Membership {
    fn authenticate(&self, actor: &Owner) -> Result<(), OrganizationError> {
        if self.active && &self.owner == actor {
            Ok(())
        } else {
            Err(OrganizationError::Denied)
        }
    }

    /// Vault, GDS and other personal data never inherit administrative access.
    pub fn authorize_personal(
        &self,
        actor: &Owner,
        resource_owner: &Owner,
    ) -> Result<(), OrganizationError> {
        self.authenticate(actor)?;
        if actor == resource_owner {
            Ok(())
        } else {
            Err(OrganizationError::Denied)
        }
    }

    /// Authorizes the ownership boundary only. RDS must additionally enforce
    /// session/device validity, enabled host module, capture consent and lease.
    pub fn authorize_screen(&self, actor: &Owner, target: &Self) -> Result<(), OrganizationError> {
        self.authenticate(actor)?;
        if target.active
            && self.owner.tenant_id == target.owner.tenant_id
            && (self.owner == target.owner || self.role == CompanyRole::Admin)
        {
            Ok(())
        } else {
            Err(OrganizationError::Denied)
        }
    }

    pub fn authorize_administration(
        &self,
        actor: &Owner,
        company: &crate::TenantId,
    ) -> Result<(), OrganizationError> {
        self.authenticate(actor)?;
        if self.role == CompanyRole::Admin && &self.owner.tenant_id == company {
            Ok(())
        } else {
            Err(OrganizationError::Denied)
        }
    }

    /// The authoritative store locks membership changes for the company and
    /// reads `active_administrators` under that lock. A detached count is unsafe.
    /// Removed membership remains retained; invitations own reactivation.
    pub fn change(
        &self,
        administrator: &Self,
        actor: &Owner,
        change: MembershipChange,
        active_administrators: usize,
    ) -> Result<Self, OrganizationError> {
        administrator.authorize_administration(actor, &self.owner.tenant_id)?;
        if active_administrators == 0 {
            return Err(OrganizationError::InvalidState);
        }
        if !self.active {
            return match change {
                MembershipChange::Remove => Ok(self.clone()),
                MembershipChange::SetRole(_) => Err(OrganizationError::Denied),
            };
        }
        if self.role == CompanyRole::Admin
            && active_administrators == 1
            && change != MembershipChange::SetRole(CompanyRole::Admin)
        {
            return Err(OrganizationError::LastAdministrator);
        }
        let mut next = self.clone();
        match change {
            MembershipChange::SetRole(role) => next.role = role,
            MembershipChange::Remove => next.active = false,
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TenantId, UserId};

    fn member(company: &str, user: &str, role: CompanyRole, active: bool) -> Membership {
        Membership {
            owner: Owner {
                tenant_id: TenantId::new(company).unwrap(),
                user_id: UserId::new(user).unwrap(),
            },
            role,
            active,
        }
    }

    #[test]
    fn access_matrix_keeps_personal_data_private_and_rds_inside_the_company() {
        let members = [
            member("a", "admin", CompanyRole::Admin, true),
            member("a", "user", CompanyRole::User, true),
            member("a", "other", CompanyRole::User, true),
            member("b", "external", CompanyRole::Admin, true),
            member("a", "removed", CompanyRole::Admin, false),
        ];
        let screens = [
            [true, true, true, false, false],
            [false, true, false, false, false],
            [false, false, true, false, false],
            [false, false, false, true, false],
            [false, false, false, false, false],
        ];
        for (i, actor) in members.iter().enumerate() {
            for (j, target) in members.iter().enumerate() {
                assert_eq!(
                    actor.authorize_screen(&actor.owner, target).is_ok(),
                    screens[i][j]
                );
                assert_eq!(
                    actor
                        .authorize_personal(&actor.owner, &target.owner)
                        .is_ok(),
                    i == j && i != 4
                );
            }
        }
        let admin = &members[0];
        let user = &members[1];
        assert_eq!(
            admin.authorize_screen(&user.owner, &members[2]),
            Err(OrganizationError::Denied)
        );
        assert_eq!(
            admin.authorize_administration(&user.owner, &admin.owner.tenant_id),
            Err(OrganizationError::Denied)
        );
    }

    #[test]
    fn role_changes_preserve_identity_and_the_last_active_administrator() {
        let admin = member("a", "admin", CompanyRole::Admin, true);
        let user = member("a", "user", CompanyRole::User, true);
        for change in [
            MembershipChange::SetRole(CompanyRole::User),
            MembershipChange::Remove,
        ] {
            assert_eq!(
                admin.change(&admin, &admin.owner, change, 1),
                Err(OrganizationError::LastAdministrator)
            );
            assert!(admin.change(&admin, &admin.owner, change, 2).is_ok());
        }
        let promoted = user
            .change(
                &admin,
                &admin.owner,
                MembershipChange::SetRole(CompanyRole::Admin),
                1,
            )
            .unwrap();
        assert_eq!(promoted.owner, user.owner);
        assert_eq!(promoted.role, CompanyRole::Admin);
        assert_eq!(
            promoted.authorize_personal(&promoted.owner, &admin.owner),
            Err(OrganizationError::Denied)
        );
        let removed = user
            .change(&admin, &admin.owner, MembershipChange::Remove, 1)
            .unwrap();
        assert_eq!(removed.owner, user.owner);
        assert!(!removed.active);
        assert_eq!(
            removed.change(
                &admin,
                &admin.owner,
                MembershipChange::SetRole(CompanyRole::Admin),
                1
            ),
            Err(OrganizationError::Denied)
        );
        assert_eq!(
            removed.change(&admin, &admin.owner, MembershipChange::Remove, 1),
            Ok(removed)
        );
    }

    #[test]
    fn membership_mutations_reject_forged_cross_company_or_removed_authority() {
        let target = member("a", "user", CompanyRole::User, true);
        let admin = member("a", "admin", CompanyRole::Admin, true);
        let other = member("b", "other", CompanyRole::Admin, true);
        let removed = member("a", "removed", CompanyRole::Admin, false);
        for actor in [&target, &other, &removed] {
            assert_eq!(
                target.change(actor, &actor.owner, MembershipChange::Remove, 1),
                Err(OrganizationError::Denied)
            );
        }
        assert_eq!(
            target.change(&admin, &target.owner, MembershipChange::Remove, 1),
            Err(OrganizationError::Denied)
        );
        assert_eq!(
            target.change(&admin, &admin.owner, MembershipChange::Remove, 0),
            Err(OrganizationError::InvalidState)
        );
    }
}
