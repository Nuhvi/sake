pub mod op_cat;
pub mod op_csfs;

#[cfg(test)]
mod tests {

    use bitcoin::{ScriptBuf, Transaction, TxOut};

    use crate::{Error, SakeWitnessCarrier, validate};

    pub(crate) fn validate_single_script(
        script: ScriptBuf,
        witness: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        let dummy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut::sake_witness_carrier(&[witness])],
        };
        let prevouts = vec![];

        validate(&dummy_tx, &prevouts, &[(0, script)])
    }
}
