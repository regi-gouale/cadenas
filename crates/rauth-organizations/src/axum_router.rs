//! Axum router for organizations.
//!
//! Mount as `Router::nest("/api/auth/organizations", rauth_organizations::axum_router::router(auth))`.
//!
//! All endpoints require an authenticated session (cookie or `Authorization: Bearer`).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use rauth_axum::{ApiError, AuthSession};
use rauth_core::{error::Error, Auth};
use serde::Deserialize;
use uuid::Uuid;

use crate::{Membership, Organization, OrganizationId, Role};

pub fn router(auth: Auth) -> Router {
    Router::new()
        .route("/", post(create).get(list))
        .route("/:id", get(get_one).delete(delete_org))
        .route("/:id/members", get(list_members).post(add_member))
        .route(
            "/:id/members/:user_id",
            patch(update_member).delete(remove_member),
        )
        .with_state(auth)
}

#[derive(Deserialize)]
struct CreateBody {
    slug: String,
    name: String,
}

#[derive(Deserialize)]
struct AddMemberBody {
    user_id: Uuid,
    role: Role,
}

#[derive(Deserialize)]
struct UpdateRoleBody {
    role: Role,
}

async fn create(
    State(auth): State<Auth>,
    session: AuthSession,
    Json(body): Json<CreateBody>,
) -> Result<Response, ApiError> {
    if body.slug.trim().is_empty() || body.name.trim().is_empty() {
        return Err(ApiError(Error::bad_request("slug and name are required")));
    }
    let storage = auth.storage();
    let org = storage.create_organization(&body.slug, &body.name).await?;
    storage.add_member(&org.id, &session.user.id, Role::Owner).await?;
    Ok((StatusCode::CREATED, Json(org)).into_response())
}

async fn list(
    State(auth): State<Auth>,
    session: AuthSession,
) -> Result<Response, ApiError> {
    let items = auth
        .storage()
        .list_organizations_for_user(&session.user.id)
        .await?;
    let dto: Vec<_> = items
        .into_iter()
        .map(|(o, r)| serde_json::json!({ "organization": o, "role": r }))
        .collect();
    Ok(Json(dto).into_response())
}

async fn get_one(
    State(auth): State<Auth>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    require_member(&auth, &id, &session).await?;
    let org = auth
        .storage()
        .find_organization_by_id(&id)
        .await?
        .ok_or(Error::UserNotFound)?; // re-using NotFound mapping
    Ok(Json(org).into_response())
}

async fn delete_org(
    State(auth): State<Auth>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    let m = require_member(&auth, &id, &session).await?;
    if m.role != Role::Owner {
        return Err(ApiError(Error::Forbidden));
    }
    auth.storage().delete_organization(&id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn list_members(
    State(auth): State<Auth>,
    session: AuthSession,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    require_member(&auth, &id, &session).await?;
    let members = auth.storage().list_members(&id).await?;
    Ok(Json(members).into_response())
}

async fn add_member(
    State(auth): State<Auth>,
    session: AuthSession,
    Path(id): Path<Uuid>,
    Json(body): Json<AddMemberBody>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    let actor = require_member(&auth, &id, &session).await?;
    require_at_least(actor.role, Role::Admin)?;
    if body.role.rank() > actor.role.rank() {
        return Err(ApiError(Error::Forbidden));
    }
    let target = rauth_core::user::UserId(body.user_id);
    let m: Membership = auth.storage().add_member(&id, &target, body.role).await?;
    Ok((StatusCode::CREATED, Json(m)).into_response())
}

async fn update_member(
    State(auth): State<Auth>,
    session: AuthSession,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateRoleBody>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    let actor = require_member(&auth, &id, &session).await?;
    require_at_least(actor.role, Role::Admin)?;
    let target = rauth_core::user::UserId(user_id);
    if body.role.rank() > actor.role.rank() {
        return Err(ApiError(Error::Forbidden));
    }
    auth.storage().update_member_role(&id, &target, body.role).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn remove_member(
    State(auth): State<Auth>,
    session: AuthSession,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let id = OrganizationId(id);
    let actor = require_member(&auth, &id, &session).await?;
    let target = rauth_core::user::UserId(user_id);
    if target != session.user.id {
        require_at_least(actor.role, Role::Admin)?;
    }
    auth.storage().remove_member(&id, &target).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn require_member(
    auth: &Auth,
    org_id: &OrganizationId,
    session: &AuthSession,
) -> Result<Membership, ApiError> {
    auth.storage()
        .find_membership(org_id, &session.user.id)
        .await?
        .ok_or(ApiError(Error::Forbidden))
}

fn require_at_least(actor: Role, min: Role) -> Result<(), ApiError> {
    if actor.rank() < min.rank() {
        Err(ApiError(Error::Forbidden))
    } else {
        Ok(())
    }
}

// Re-export to keep `Organization` reachable for serde derive consumers.
#[allow(dead_code)]
fn _typecheck_org(o: Organization) -> Organization {
    o
}
