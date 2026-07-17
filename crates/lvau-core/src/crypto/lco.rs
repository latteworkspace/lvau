//! Lvau Custom Obfuscator (LCO)
//!
//! This is an experimental obfuscation layer used in the `Extreme` profile.
//! It is not a cryptographic security boundary. Review the standard AEAD layers
//! and the surrounding implementation when making security decisions.

pub fn apply_lco(data: &mut [u8], key: &[u8; 32], nonce: &[u8]) {
    let mut state = [0u8; 256];

    // Initialize state with key and nonce mixing
    for (i, v) in state.iter_mut().enumerate() {
        *v = i as u8;
    }

    let mut j: u8 = 0;
    for i in 0..256 {
        let key_byte = key[i % 32];
        // Callers currently use a 24-byte nonce, but this helper is public and
        // must not panic if a malformed or future caller supplies an empty one.
        let nonce_byte = nonce.get(i % nonce.len().max(1)).copied().unwrap_or(0);
        // Custom non-linear mixing
        let mix = key_byte
            .wrapping_add(nonce_byte)
            .rotate_left((i % 8) as u32);
        j = j.wrapping_add(state[i]).wrapping_add(mix);
        state.swap(i, j as usize);
    }

    // Generate pseudo-random keystream and XOR with data
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);

        let k = state[i as usize].wrapping_add(state[j as usize]);
        let keystream_byte = state[k as usize];

        // Custom dynamic bitwise rotation based on previous byte (starts at 0)
        let rot = (j % 8) as u32;
        let obfuscated_byte = keystream_byte.rotate_right(rot);

        *byte ^= obfuscated_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::apply_lco;

    #[test]
    fn empty_nonce_does_not_panic_and_remains_reversible() {
        let key = [7_u8; 32];
        let mut data = b"payload".to_vec();
        let original = data.clone();

        apply_lco(&mut data, &key, &[]);
        assert_ne!(data, original);
        apply_lco(&mut data, &key, &[]);

        assert_eq!(data, original);
    }
}
