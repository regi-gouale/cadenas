//! Notes CRUD protégé par session — démontre comment consommer `AuthSession`
//! dans une vraie API métier au-dessus de `rauth`.

use axum::{
    extract::{FromRef, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rauth::axum::{ApiError, AuthSession};
use rauth::Auth;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct NotesState {
    pub auth: Auth,
    pub pool: SqlitePool,
}

impl FromRef<NotesState> for Auth {
    fn from_ref(s: &NotesState) -> Auth {
        s.auth.clone()
    }
}

pub async fn migrate(pool: &SqlitePool) -> sqlx::Result<()> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS notes (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            content     TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);"#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub fn router(state: NotesState) -> Router {
    Router::new()
        .route("/", get(list).post(create))
        .route("/:id", axum::routing::delete(delete_note))
        .with_state(state)
}

#[derive(Serialize)]
struct Note {
    id: String,
    content: String,
    created_at: String,
}

#[derive(Deserialize)]
struct CreateBody {
    content: String,
}

async fn list(State(s): State<NotesState>, session: AuthSession) -> Result<Response, ApiError> {
    let _ = s.auth; // session validated against the same Auth, just keep it on the state.
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT id, content, created_at FROM notes
           WHERE user_id = ?1 ORDER BY created_at DESC"#,
    )
    .bind(session.user.id.to_string())
    .fetch_all(&s.pool)
    .await
    .map_err(internal)?;

    let notes: Vec<Note> = rows
        .into_iter()
        .map(|(id, content, created_at)| Note {
            id,
            content,
            created_at,
        })
        .collect();
    Ok(Json(notes).into_response())
}

async fn create(
    State(s): State<NotesState>,
    session: AuthSession,
    Json(body): Json<CreateBody>,
) -> Result<Response, ApiError> {
    if body.content.trim().is_empty() {
        return Err(ApiError(rauth::Error::bad_request("content is required")));
    }
    let id = Uuid::new_v4().to_string();
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| ApiError(rauth::Error::storage(e)))?;
    sqlx::query(
        r#"INSERT INTO notes (id, user_id, content, created_at) VALUES (?1, ?2, ?3, ?4)"#,
    )
    .bind(&id)
    .bind(session.user.id.to_string())
    .bind(body.content.trim())
    .bind(&created_at)
    .execute(&s.pool)
    .await
    .map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(Note {
            id,
            content: body.content,
            created_at,
        }),
    )
        .into_response())
}

async fn delete_note(
    State(s): State<NotesState>,
    session: AuthSession,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let result = sqlx::query(r#"DELETE FROM notes WHERE id = ?1 AND user_id = ?2"#)
        .bind(&id)
        .bind(session.user.id.to_string())
        .execute(&s.pool)
        .await
        .map_err(internal)?;
    if result.rows_affected() == 0 {
        return Err(ApiError(rauth::Error::UserNotFound)); // mapped to 404
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn internal(e: sqlx::Error) -> ApiError {
    ApiError(rauth::Error::storage(e))
}
