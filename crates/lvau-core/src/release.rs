use lvau_protocol::envelope::ReleaseMetadata;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Failed to parse or missing envelope")]
    EnvelopeError,
}

pub fn attach_release_metadata(
    in_file: &Path,
    out_file: &Path,
    project_name: Option<String>,
    version: Option<String>,
    git_commit: Option<String>,
    build_timestamp: Option<String>,
) -> Result<(), ReleaseError> {
    let metadata = ReleaseMetadata {
        project_name,
        version,
        git_commit,
        build_timestamp,
    };

    let data = std::fs::read(in_file)?;
    if data.len() < 4 {
        return Err(ReleaseError::EnvelopeError);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(ReleaseError::EnvelopeError);
    }

    let mut envelope: lvau_protocol::envelope::Envelope =
        postcard::from_bytes(&data[4..4 + env_len]).map_err(ReleaseError::Serialization)?;

    envelope.release_metadata = Some(metadata);

    let new_env_bytes = postcard::to_allocvec(&envelope).map_err(ReleaseError::Serialization)?;
    let new_len = new_env_bytes.len() as u32;

    let mut new_data = Vec::with_capacity(4 + new_env_bytes.len() + (data.len() - 4 - env_len));
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[4 + env_len..]);

    std::fs::write(out_file, new_data)?;

    Ok(())
}

pub fn attach_recovery_metadata(
    in_file: &Path,
    out_file: &Path,
    recovery_data: Vec<u8>,
) -> Result<(), ReleaseError> {
    let data = std::fs::read(in_file)?;
    if data.len() < 4 {
        return Err(ReleaseError::EnvelopeError);
    }

    let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + env_len {
        return Err(ReleaseError::EnvelopeError);
    }

    let mut envelope: lvau_protocol::envelope::Envelope =
        postcard::from_bytes(&data[4..4 + env_len]).map_err(ReleaseError::Serialization)?;

    envelope.recovery_metadata = Some(recovery_data);

    let new_env_bytes = postcard::to_allocvec(&envelope).map_err(ReleaseError::Serialization)?;
    let new_len = new_env_bytes.len() as u32;

    let mut new_data = Vec::with_capacity(4 + new_env_bytes.len() + (data.len() - 4 - env_len));
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[4 + env_len..]);

    std::fs::write(out_file, new_data)?;

    Ok(())
}
