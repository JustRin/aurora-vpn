use serde::{Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Msg(String),

    #[error("файловая система: {0}")]
    Io(#[from] std::io::Error),

    #[error("некорректный JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("сетевая ошибка: {0}")]
    Http(#[from] reqwest::Error),
}

impl AppError {
    pub fn msg(text: impl Into<String>) -> Self {
        Self::Msg(text.into())
    }
}

/// Tauri requires command errors to be serializable; a flat string is what the
/// frontend actually renders, so collapse the whole enum into its Display form.
impl Serialize for AppError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::AppError::Msg(format!($($arg)*)))
    };
}
