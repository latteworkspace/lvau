use lvau_protocol::shard::{ShardEnvelope, SHARD_MAGIC};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fmt;

#[derive(Debug)]
pub enum RedundancyError {
    InvalidShardCount,
    EncodeFailed,
    DecodeFailed,
    NotEnoughShards,
    InvalidMagic,
}

impl fmt::Display for RedundancyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for RedundancyError {}

pub fn split_file(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, RedundancyError> {
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 256 {
        return Err(RedundancyError::InvalidShardCount);
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|_| RedundancyError::InvalidShardCount)?;

    let original_file_size = data.len() as u64;

    // Pad data to be a multiple of data_shards
    let mut padded_data = data.to_vec();
    let padding = data_shards - (padded_data.len() % data_shards);
    if padding != data_shards {
        padded_data.extend(vec![0; padding]);
    }

    let shard_size = padded_data.len() / data_shards;

    // Create the shards
    let mut shards: Vec<Vec<u8>> = padded_data
        .chunks(shard_size)
        .map(|chunk| chunk.to_vec())
        .collect();

    // Extend with parity shards
    for _ in 0..parity_shards {
        shards.push(vec![0; shard_size]);
    }

    // Encode
    rs.encode(&mut shards).map_err(|_| RedundancyError::EncodeFailed)?;

    // Wrap in envelopes and serialize
    let mut encoded_envelopes = Vec::new();
    for (i, shard) in shards.into_iter().enumerate() {
        let envelope = ShardEnvelope {
            magic: SHARD_MAGIC,
            format_version: 1,
            original_file_size,
            data_shards: data_shards as u8,
            parity_shards: parity_shards as u8,
            shard_index: i as u8,
            payload: shard,
        };
        let encoded = postcard::to_allocvec(&envelope).unwrap();
        encoded_envelopes.push(encoded);
    }

    Ok(encoded_envelopes)
}

pub fn recover_file(
    encoded_shards: Vec<Option<Vec<u8>>>,
) -> Result<Vec<u8>, RedundancyError> {
    let mut envelopes = Vec::new();
    
    let mut first_envelope: Option<ShardEnvelope> = None;

    for encoded_opt in encoded_shards {
        match encoded_opt {
            Some(encoded) => {
                let env: ShardEnvelope = postcard::from_bytes(&encoded)
                    .map_err(|_| RedundancyError::DecodeFailed)?;
                
                if env.magic != SHARD_MAGIC {
                    return Err(RedundancyError::InvalidMagic);
                }

                if first_envelope.is_none() {
                    first_envelope = Some(env.clone());
                }

                envelopes.push(Some(env));
            }
            None => {
                envelopes.push(None);
            }
        }
    }

    let template = first_envelope.ok_or(RedundancyError::NotEnoughShards)?;
    let total_shards = (template.data_shards + template.parity_shards) as usize;

    if envelopes.len() != total_shards {
        return Err(RedundancyError::InvalidShardCount);
    }

    let rs = ReedSolomon::new(template.data_shards as usize, template.parity_shards as usize)
        .map_err(|_| RedundancyError::InvalidShardCount)?;

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    let mut present_count = 0;

    for env_opt in envelopes {
        if let Some(env) = env_opt {
            if env.original_file_size != template.original_file_size ||
               env.data_shards != template.data_shards ||
               env.parity_shards != template.parity_shards {
                   return Err(RedundancyError::DecodeFailed); // Mismatched shard parameters
               }
            shards[env.shard_index as usize] = Some(env.payload);
            present_count += 1;
        }
    }

    if present_count < template.data_shards as usize {
        return Err(RedundancyError::NotEnoughShards);
    }

    rs.reconstruct(&mut shards).map_err(|_| RedundancyError::DecodeFailed)?;

    let mut recovered_data = Vec::new();
    for i in 0..template.data_shards as usize {
        if let Some(shard) = &shards[i] {
            recovered_data.extend_from_slice(shard);
        } else {
            return Err(RedundancyError::DecodeFailed);
        }
    }

    recovered_data.truncate(template.original_file_size as usize);

    Ok(recovered_data)
}
