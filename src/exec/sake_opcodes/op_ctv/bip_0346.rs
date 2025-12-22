//! bip-0346 reference implementation <https://github.com/bitcoin/bips/blob/debd349e6181d949cbea0691fcc0d67b265b02a8/bip-0346/ref-impl/src/main.rs>

#![allow(
    clippy::unnecessary_cast,
    clippy::collapsible_if,
    clippy::empty_line_after_outer_attr,
    clippy::assign_op_pattern,
    clippy::needless_borrow
)]

use bitcoin::consensus::encode::Encodable;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::{Transaction, TxOut};

pub const TXFS_VERSION: u8 = 1 << 0;
pub const TXFS_LOCKTIME: u8 = 1 << 1;
pub const TXFS_CURRENT_INPUT_IDX: u8 = 1 << 2;
pub const TXFS_CURRENT_INPUT_SPENTSCRIPT: u8 = 1 << 3;
pub const TXFS_CURRENT_INPUT_CONTROL_BLOCK: u8 = 1 << 4;
pub const TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS: u8 = 1 << 5;
pub const TXFS_CURRENT_INPUT_TAPROOT_ANNEX: u8 = 1 << 6;
pub const TXFS_CONTROL: u8 = 1 << 7;

pub const TXFS_INPUTS_PREVOUTS: u8 = 1 << 0;
pub const TXFS_INPUTS_SEQUENCES: u8 = 1 << 1;
pub const TXFS_INPUTS_SCRIPTSIGS: u8 = 1 << 2;
pub const TXFS_INPUTS_PREV_SCRIPTPUBKEYS: u8 = 1 << 3;
pub const TXFS_INPUTS_PREV_VALUES: u8 = 1 << 4;
pub const TXFS_INPUTS_TAPROOT_ANNEXES: u8 = 1 << 5;
pub const TXFS_OUTPUTS_SCRIPTPUBKEYS: u8 = 1 << 6;
pub const TXFS_OUTPUTS_VALUES: u8 = 1 << 7;

pub const TXFS_INPUTS_ALL: u8 = TXFS_INPUTS_PREVOUTS
    | TXFS_INPUTS_SEQUENCES
    | TXFS_INPUTS_SCRIPTSIGS
    | TXFS_INPUTS_PREV_SCRIPTPUBKEYS
    | TXFS_INPUTS_PREV_VALUES
    | TXFS_INPUTS_TAPROOT_ANNEXES;
pub const TXFS_OUTPUTS_ALL: u8 = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES;

pub const TXFS_INOUT_NUMBER: u8 = 1 << 7;
pub const TXFS_INOUT_SELECTION_NONE: u8 = 0x00;
pub const TXFS_INOUT_SELECTION_CURRENT: u8 = 0x40;
pub const TXFS_INOUT_SELECTION_ALL: u8 = 0x3f;
pub const TXFS_INOUT_SELECTION_MODE: u8 = 1 << 6;
pub const TXFS_INOUT_LEADING_SIZE: u8 = 1 << 5;
pub const TXFS_INOUT_INDIVIDUAL_MODE: u8 = 1 << 5;
pub const TXFS_INOUT_SELECTION_MASK: u8 = 0xff ^ (1 << 7) ^ (1 << 6) ^ (1 << 5);

pub const TXFS_SPECIAL_TEMPLATE: [u8; 4] = [
    TXFS_VERSION | TXFS_LOCKTIME | TXFS_CURRENT_INPUT_IDX,
    TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS | TXFS_OUTPUTS_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
    TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL,
];

const SHA256_EMPTY: sha256::Hash = sha256::Hash::const_hash(&[]);

fn read_i7(input: u8) -> i8 {
    let masked = input & 0x7f;
    if (masked & 0x40) == 0 {
        masked as i8
    } else {
        0i8 - ((!(masked - 1)) & 0x7f) as i8
    }
}

fn read_i15(input: u16) -> i16 {
    let masked = input & 0x7fff;
    if (masked & 0x4000) == 0 {
        masked as i16
    } else {
        0i16 - ((!(masked - 1)) & 0x7fff) as i16
    }
}

/// Parse an input or output selection from the TxFieldSelector bytes.
///
/// Returns the selected indices and a flag whether to commit the number of items.
fn parse_inout_selection(
    bytes: &mut impl Iterator<Item = u8>,
    nb_items: usize,
    current_input_idx: u32,
    allow_empty: bool,
) -> Result<(Vec<usize>, bool), &'static str> {
    let first = match bytes.next() {
        Some(b) => b,
        None if !allow_empty => return Ok((vec![], false)),
        None /* if allow_empty */ => return Err("byte missing instead of empty selection"),
    };
    let commit_number = (first & TXFS_INOUT_NUMBER) != 0;
    let selection = first & (0xff ^ TXFS_INOUT_NUMBER);

    let selected = if selection == TXFS_INOUT_SELECTION_NONE {
        vec![]
    } else if selection == TXFS_INOUT_SELECTION_ALL {
        (0..nb_items).collect()
    } else if selection == TXFS_INOUT_SELECTION_CURRENT {
        if current_input_idx as usize >= nb_items {
            // NB can only happen for outputs
            return Err(
                "current input index exceeds number of outputs and current output selected",
            );
        }
        vec![current_input_idx as usize]
    } else if (selection & TXFS_INOUT_SELECTION_MODE) == 0 {
        // leading mode
        let count = if (selection & TXFS_INOUT_LEADING_SIZE) == 0 {
            (selection & TXFS_INOUT_SELECTION_MASK) as usize
        } else {
            let next_byte = bytes
                .next()
                .ok_or("second leading selection byte missing")?;
            (((selection & TXFS_INOUT_SELECTION_MASK) as usize) << 8) + next_byte as usize
        };
        assert_ne!(count, 0, "this should be interpreted as NONE above");
        if count > nb_items {
            return Err("selected number of leading in/outputs out of bounds");
        }
        (0..count).collect()
    } else {
        // individual mode
        let absolute = (selection & TXFS_INOUT_INDIVIDUAL_MODE) == 0;

        let count = (selection & TXFS_INOUT_SELECTION_MASK) as usize;

        let mut selected = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let first = bytes.next().ok_or("expected an index byte")?;
            let single_byte = (first & (1 << 7)) == 0;
            let number = if single_byte {
                first as usize
            } else {
                let next_byte = bytes.next().ok_or("expected another index byte")?;
                (((first & (1 << 7)) as usize) << 8) + next_byte as usize
            };

            let idx = if absolute {
                number
            } else {
                let rel = if single_byte {
                    read_i7(number as u8) as isize
                } else {
                    read_i15(number as u16) as isize
                };

                if rel.is_negative() && rel.abs() > current_input_idx as isize {
                    return Err("relative index out of bounds");
                }
                (current_input_idx as isize + rel) as usize
            };

            if idx > nb_items {
                return Err("selected index out of bounds");
            }
            if let Some(last) = selected.last() {
                if idx <= *last {
                    return Err("selected indices not in increasing order");
                }
            }
            selected.push(idx);
        }
        selected
    };
    Ok((selected, commit_number))
}

fn convert_short_txfs(txfs: u8) -> Result<Vec<u8>, &'static str> {
    let mut base = TXFS_VERSION | TXFS_LOCKTIME | TXFS_CONTROL | TXFS_CURRENT_INPUT_TAPROOT_ANNEX;
    let mut inout_fields = TXFS_OUTPUTS_ALL | TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS;

    let input_selection = match txfs & 0b00000011 {
        0b00000000 => TXFS_INOUT_SELECTION_NONE,
        0b00000001 => TXFS_INOUT_SELECTION_CURRENT,
        0b00000011 => TXFS_INOUT_SELECTION_ALL,
        _ => return Err("0b10 is not a valid input selection"),
    };
    let output_selection = match txfs & 0b00001100 {
        0b00000000 => TXFS_INOUT_SELECTION_NONE,
        0b00000100 => TXFS_INOUT_SELECTION_CURRENT,
        0b00001100 => TXFS_INOUT_SELECTION_ALL,
        _ => return Err("0b10 is not a valid output selection"),
    };

    if txfs & 0b00010000 != 0 {
        inout_fields = inout_fields | TXFS_INPUTS_PREVOUTS;
    }

    if txfs & 0b00100000 != 0 {
        inout_fields = inout_fields | TXFS_INPUTS_PREV_SCRIPTPUBKEYS | TXFS_INPUTS_PREV_VALUES;
    }

    if txfs & 0b01000000 != 0 {
        base = base
            | TXFS_CURRENT_INPUT_CONTROL_BLOCK
            | TXFS_CURRENT_INPUT_SPENTSCRIPT
            | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS;
    }

    if txfs & 0b10000000 != 0 {
        base = base | TXFS_CURRENT_INPUT_IDX;
    }

    Ok(vec![base, inout_fields, input_selection, output_selection])
}

///
///
/// Assumes that TxFieldSelector is valid.
pub fn calculate_txhash(
    txfs: &[u8],
    tx: &Transaction,
    prevouts: &[TxOut],
    current_input_idx: u32,
    current_input_last_codeseparator_pos: Option<u32>,
) -> Result<sha256::Hash, &'static str> {
    assert_eq!(tx.input.len(), prevouts.len());

    let txfs = if txfs.is_empty() {
        TXFS_SPECIAL_TEMPLATE.to_vec()
    } else if txfs.len() == 1 {
        convert_short_txfs(txfs[0])?
    } else {
        txfs.to_vec()
    };
    let txfs = &txfs;

    let mut engine = sha256::Hash::engine();

    if (txfs[0] & TXFS_CONTROL) != 0 {
        engine.input(txfs);
    }

    let mut bytes = txfs.iter().copied().peekable();
    let global = bytes.next().unwrap();

    if (global & TXFS_VERSION) != 0 {
        tx.version.consensus_encode(&mut engine).unwrap();
    }

    if (global & TXFS_LOCKTIME) != 0 {
        tx.lock_time.consensus_encode(&mut engine).unwrap();
    }

    if (global & TXFS_CURRENT_INPUT_IDX) != 0 {
        (current_input_idx as u32)
            .consensus_encode(&mut engine)
            .unwrap();
    }

    let cur = current_input_idx as usize;
    if (global & TXFS_CURRENT_INPUT_SPENTSCRIPT) != 0 {
        let ss = if prevouts[cur].script_pubkey.is_p2sh() {
            tx.input[cur]
                .script_sig
                .redeem_script()
                .map(|s| s.as_bytes())
                .unwrap_or(&[])
        } else if prevouts[cur].script_pubkey.is_p2wsh() {
            tx.input[cur]
                .witness
                .witness_script()
                .map(|s| s.as_bytes())
                .unwrap_or(&[])
        } else if prevouts[cur].script_pubkey.is_p2tr() {
            tx.input[cur]
                .witness
                .tapscript()
                .map(|s| s.as_bytes())
                .unwrap_or(&[])
        } else {
            &[]
        };
        engine.input(&sha256::Hash::hash(&ss)[..]);
    }

    if (global & TXFS_CURRENT_INPUT_CONTROL_BLOCK) != 0 {
        let cb = if prevouts[cur].script_pubkey.is_p2tr() {
            tx.input[cur].witness.taproot_control_block().unwrap_or(&[])
        } else {
            &[]
        };
        engine.input(&sha256::Hash::hash(&cb)[..]);
    }

    if (global & TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS) != 0 {
        let pos = current_input_last_codeseparator_pos.unwrap_or(u32::MAX);
        (pos as u32).consensus_encode(&mut engine).unwrap();
    }

    if (global & TXFS_CURRENT_INPUT_TAPROOT_ANNEX) != 0 {
        if let Some(annex) = tx.input[cur].witness.taproot_annex() {
            engine.input(&sha256::Hash::hash(annex)[..]);
        } else {
            engine.input(&SHA256_EMPTY[..]);
        }
    }

    let inout_fields = match bytes.next() {
        Some(b) => b,
        // Stop early if no inputs or outputs are selected.
        None => return Ok(sha256::Hash::from_engine(engine)),
    };

    // Inputs
    let (input_select, commit_number_inputs) =
        parse_inout_selection(&mut bytes, tx.input.len(), current_input_idx, true)?;

    if commit_number_inputs {
        (tx.input.len() as u32)
            .consensus_encode(&mut engine)
            .unwrap();
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREVOUTS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                tx.input[*i]
                    .previous_output
                    .consensus_encode(&mut engine)
                    .unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_SEQUENCES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                tx.input[*i].sequence.consensus_encode(&mut engine).unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_SCRIPTSIGS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                engine.input(&sha256::Hash::hash(&tx.input[*i].script_sig.as_bytes())[..]);
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREV_SCRIPTPUBKEYS) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                engine.input(&sha256::Hash::hash(&prevouts[*i].script_pubkey.as_bytes())[..]);
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_PREV_VALUES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                prevouts[*i].value.consensus_encode(&mut engine).unwrap();
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    if !input_select.is_empty() && (inout_fields & TXFS_INPUTS_TAPROOT_ANNEXES) != 0 {
        let hash = {
            let mut engine = sha256::Hash::engine();
            for i in &input_select {
                if prevouts[*i].script_pubkey.is_p2tr() {
                    if let Some(annex) = tx.input[*i].witness.taproot_annex() {
                        engine.input(&sha256::Hash::hash(annex)[..]);
                    } else {
                        engine.input(&SHA256_EMPTY[..]);
                    }
                } else {
                    engine.input(&SHA256_EMPTY[..]);
                }
            }
            sha256::Hash::from_engine(engine)
        };
        engine.input(&hash[..]);
    }

    // Outputs
    if bytes.peek().is_none() {
    } else {
        let allow_empty = (inout_fields & TXFS_OUTPUTS_ALL) == 0;
        let (selection, commit_number) =
            parse_inout_selection(&mut bytes, tx.output.len(), current_input_idx, allow_empty)?;

        if commit_number {
            (tx.output.len() as u32)
                .consensus_encode(&mut engine)
                .unwrap();
        }

        if !selection.is_empty() && (inout_fields & TXFS_OUTPUTS_SCRIPTPUBKEYS) != 0 {
            let hash = {
                let mut engine = sha256::Hash::engine();
                for i in &selection {
                    engine.input(&sha256::Hash::hash(&tx.output[*i].script_pubkey.as_bytes())[..]);
                }
                sha256::Hash::from_engine(engine)
            };
            hash.consensus_encode(&mut engine).unwrap();
        }

        if !selection.is_empty() && (inout_fields & TXFS_OUTPUTS_VALUES) != 0 {
            let hash = {
                let mut engine = sha256::Hash::engine();
                for i in &selection {
                    tx.output[*i].value.consensus_encode(&mut engine).unwrap();
                }
                sha256::Hash::from_engine(engine)
            };
            hash.consensus_encode(&mut engine).unwrap();
        }
    }

    if bytes.next().is_some() {
        return Err("unused txfs bytes");
    }
    Ok(sha256::Hash::from_engine(engine))
}
