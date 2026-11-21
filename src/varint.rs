//! Bitcoin CompactSize encoding helpers.
//!
//! [`bitcoin::consensus::Encodable`] returns an error that cannot occur when
//! the sink is a `Vec` or a hash engine. These helpers make the encoding total
//! and keep the panic-free policy of the crate.

use bitcoin::hashes::{HashEngine, sha256};

/// Appends `value` as a CompactSize integer.
pub(crate) fn encode_vec(buffer: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xfc => buffer.push(value as u8),
        0xfd..=0xffff => {
            buffer.push(0xfd);
            buffer.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buffer.push(0xfe);
            buffer.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            buffer.push(0xff);
            buffer.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Writes `value` as a CompactSize integer to a SHA-256 hash engine.
pub(crate) fn encode_engine(engine: &mut sha256::HashEngine, value: u64) {
    match value {
        0..=0xfc => engine.input(&[value as u8]),
        0xfd..=0xffff => {
            engine.input(&[0xfd]);
            engine.input(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            engine.input(&[0xfe]);
            engine.input(&(value as u32).to_le_bytes());
        }
        _ => {
            engine.input(&[0xff]);
            engine.input(&value.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        VarInt,
        consensus::Encodable,
        hashes::{Hash, sha256},
    };

    use super::*;

    #[test]
    fn test_encode_vec_matches_consensus() {
        for value in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut expected = Vec::new();
            VarInt(value)
                .consensus_encode(&mut expected)
                .expect("writing to a Vec cannot fail");

            let mut actual = Vec::new();
            encode_vec(&mut actual, value);
            assert_eq!(actual, expected, "value {value:#x}");
        }
    }

    #[test]
    fn test_encode_engine_matches_consensus() {
        for value in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, u64::MAX] {
            let mut expected_engine = sha256::Hash::engine();
            VarInt(value)
                .consensus_encode(&mut expected_engine)
                .expect("writing to a hash engine cannot fail");

            let mut actual_engine = sha256::Hash::engine();
            encode_engine(&mut actual_engine, value);
            assert_eq!(
                sha256::Hash::from_engine(actual_engine),
                sha256::Hash::from_engine(expected_engine),
                "value {value:#x}"
            );
        }
    }
}
