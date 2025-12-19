use crate::exec::{Exec, ExecError};

impl<'a, 'b> Exec<'a, 'b> {
    fn handle_op_ccv(&mut self) -> Result<(), ExecError> {
        // <data> <index> <pk> <taptree> <mode>
        self.stack.needn(5)?;
        let mode = self.stack.popnum().unwrap();
        let taptree_raw = self.stack.pop().unwrap();
        let pk_raw = self.stack.pop().unwrap();
        let mut index = self.stack.popnum()?;
        let data = self.stack.pop().unwrap();

        // 1. Handle Mode and Basic Validation
        if mode < -1 || mode > 2 {
            return Ok(()); // Undefined mode is OP_SUCCESS
        }

        if index == -1 {
            index = self.input_idx as i64;
        }

        let tx = self.sighashcache.transaction();

        // 2. Resolve Target Script
        let target_script = if mode == -1 {
            // CCV_MODE_CHECK_INPUT
            if index < 0 || index >= tx.input.len() as i64 {
                return Err(ExecError::InvalidStackOperation);
            }
            &self.prevouts[index as usize].script_pubkey
        } else {
            // Check Output Modes
            if index < 0 || index >= tx.output.len() as i64 {
                return Err(ExecError::InvalidStackOperation);
            }
            &tx.output[index as usize].script_pubkey
        };

        // 3. Resolve Naked Key
        let naked_key = if pk_raw.is_empty() {
            // If empty, this is a special case or error depending on BIP interpretation,
            // but usually we expect 32 bytes or -1/0.
            return Err(ExecError::PubKeyType);
        } else if pk_raw == vec![0x81] {
            // minimally encoded -1
            // Use this input's internal key (Requires access to taproot spending data)
            // Assuming your environment provides this or you extract it from the witness
            return Err(ExecError::Internal); // Placeholder: depends on your Taproot data access
        } else if pk_raw == vec![0x00] {
            // 0
            // BIP341 NUMS Key
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
                .parse()
                .unwrap()
        } else if pk_raw.len() == 32 {
            secp256k1::XOnlyPublicKey::from_slice(&pk_raw).map_err(|_| ExecError::PubKeyType)?
        } else {
            return Err(ExecError::PubKeyType);
        };

        // 4. Data Tweaking (The "Contract" part)
        let internal_key = if !data.is_empty() {
            let mut hasher = sha256::Hash::engine();
            hasher.input(&naked_key.serialize());
            hasher.input(&data);
            let hash = sha256::Hash::from_engine(hasher);

            naked_key
                .add_tweak(&self.secp, &hash.to_byte_array().into())
                .map_err(|_| ExecError::Internal)?
                .0
        } else {
            naked_key
        };

        // 5. Taptree Tweaking
        let final_key = if !taptree_raw.is_empty() {
            let root = if taptree_raw == vec![0x81] {
                // -1
                // Replace with current input's taptree root
                self.leaf_hash.into_inner().into() // This is a simplification
            } else if taptree_raw.len() == 32 {
                sha256::Hash::from_slice(&taptree_raw).unwrap()
            } else {
                return Err(ExecError::PubKeyType);
            };

            internal_key
                .add_tweak(&self.secp, &root.to_byte_array().into())
                .map_err(|_| ExecError::Internal)?
                .0
        } else {
            internal_key
        };

        // 6. Verify Script
        let expected_script = Script::new_v1_p2tr(&self.secp, final_key, None);
        if target_script != &expected_script {
            return Err(ExecError::Verify);
        }

        // 7. Amount Checks
        let idx = index as usize;
        match mode {
            0 => {
                // CCV_MODE_CHECK_OUTPUT (Default)
                if self.output_checked_deduct[idx] {
                    return Err(ExecError::Verify);
                }

                self.output_min_amount[idx] += self.residual_input_amount;
                self.residual_input_amount = 0;

                if tx.output[idx].value.to_sat() < self.output_min_amount[idx] {
                    return Err(ExecError::Verify);
                }
                self.output_checked_default[idx] = true;
            }
            2 => {
                // CCV_MODE_CHECK_OUTPUT_DEDUCT_AMOUNT
                let out_val = tx.output[idx].value.to_sat();
                if self.residual_input_amount < out_val {
                    return Err(ExecError::Verify);
                }
                if self.output_checked_default[idx] || self.output_checked_deduct[idx] {
                    return Err(ExecError::Verify);
                }

                self.residual_input_amount -= out_val;
                self.output_checked_deduct[idx] = true;
            }
            _ => {} // Input check or Ignore amount
        }

        Ok(())
    }
}
