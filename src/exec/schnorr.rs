use bitcoin::{TapSighashType, XOnlyPublicKey, secp256k1, sighash::Prevouts};

use crate::{
    Exec,
    exec::{ExecError, VALIDATION_WEIGHT_PER_SIGOP_PASSED},
};

impl<'a, 'b> Exec<'a, 'b> {
    pub(crate) fn check_sig(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        if !sig.is_empty() {
            self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if self.validation_weight < 0 {
                return Err(ExecError::TapscriptValidationWeight);
            }
        }

        if pk.is_empty() {
            Err(ExecError::PubkeyType)
        } else if pk.len() == 32 {
            if !sig.is_empty() {
                self.check_sig_schnorr(sig, pk)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    /// [pk] should be passed as 32-bytes.
    pub(crate) fn check_sig_schnorr(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        assert_eq!(pk.len(), 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ExecError::SchnorrSigSize);
        }

        let pk = XOnlyPublicKey::from_slice(pk).expect("TODO(stevenroose) what to do here?");
        let (sig, hashtype) = if sig.len() == 65 {
            let b = *sig.last().unwrap();
            let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len() - 1])
                .map_err(|_| ExecError::SchnorrSig)?;

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            //TODO(stevenroose) core does not error here
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            let sig = secp256k1::schnorr::Signature::from_slice(sig)
                .map_err(|_| ExecError::SchnorrSig)?;
            (sig, TapSighashType::Default)
        };

        let sighash = self
            .sighashcache
            .taproot_signature_hash(
                self.input_idx,
                &Prevouts::All(self.prevouts),
                None,
                Some((self.leaf_hash, u32::MAX)),
                hashtype,
            )
            .expect("TODO(stevenroose) seems to only happen if prevout index out of bound");

        if self.secp.verify_schnorr(&sig, &sighash.into(), &pk) != Ok(()) {
            return Err(ExecError::SchnorrSig);
        }

        Ok(())
    }
}
