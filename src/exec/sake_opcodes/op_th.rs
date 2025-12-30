//! OP_TEMPLATEHASH [BIP ?](https://github.com/bitcoin/bips/pull/1974/files#bip-templatehash.md)

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, HashEngine, sha256, sha256t_hash_newtype};

use bitcoin::Opcode;
use bitcoin::opcodes::all::OP_RETURN_206;

use crate::exec::{Exec, ExecError};

pub(crate) const OP_CODE: Opcode = OP_RETURN_206;

sha256t_hash_newtype! {
    /// TemplateHashTag for OP_TEMPLATEHASH
    pub struct TemplateHashTag = hash_str("TemplateHash");

    /// A template hash
    #[hash_newtype(forward)]
    struct TemplateHashHash(_);
}

impl<'a> Exec<'a> {
    pub(crate) fn handle_op_th(&mut self) -> Result<(), ExecError> {
        let template_hash = calculate_template_hash(
            self.sighashcache.transaction(),
            self.input_idx,
            // Annex is always disabled in SAKE emulation
            None,
        );

        self.stack.pushstr(template_hash.as_byte_array());

        Ok(())
    }
}

fn template_hash_tag() -> sha256::Hash {
    let mut engine = sha256::Hash::engine();
    engine.input(b"TemplateHash");
    sha256::Hash::from_engine(engine)
}

fn calculate_template_hash(
    tx: &Transaction,
    input_index: usize,
    annex: Option<&[u8]>,
) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();

    // 1. Add Tagged Hash prefix
    let tag = template_hash_tag();
    engine.input(&tag[..]);
    engine.input(&tag[..]);

    // 2. Transaction Data
    engine.input(&tx.version.0.to_le_bytes());
    engine.input(&tx.lock_time.to_consensus_u32().to_le_bytes());

    // TODO: reuse sha_sequences from SighashCache
    // when/if rust_bitcoin expose that api

    // Copied from rust bitcoin [SighashCache::common_cache_minimal_borrow]
    {
        let mut enc_sequences = sha256::Hash::engine();
        for txin in tx.input.iter() {
            txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
        }
        engine.input(sha256::Hash::from_engine(enc_sequences).as_ref());

        // sha_outputs (Precomputed by BIP341 logic)
        let mut enc = sha256::Hash::engine();
        for txout in tx.output.iter() {
            txout.consensus_encode(&mut enc).unwrap();
        }
        engine.input(sha256::Hash::from_engine(enc).as_ref());
    }

    // 3. Data about this input
    let annex_present: u8 = if annex.is_some() { 1 } else { 0 };
    engine.input(&[annex_present]);
    engine.input(&(input_index as u32).to_le_bytes());

    // 4. Optional Annex
    if let Some(annex_data) = annex {
        let sha_annex = sha256::Hash::hash(annex_data);
        engine.input(&sha_annex[..]);
    }

    sha256::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {}
