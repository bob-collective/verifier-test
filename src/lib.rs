pub use risc0_groth16::{Fr, Verifier, VerifyingKey};

pub fn verify_full_proof(full_proof: &FullProof) -> Result<(), Error> {
    // note: uses patched risc0 version that exposes new_from_proof which takes a proof
    // rather than a seal
    Verifier::new_from_proof(
        &full_proof.proof,
        &full_proof
            .public_inputs
            .into_iter()
            .map(Fr)
            .collect::<Vec<_>>(),
        &VerifyingKey(full_proof.verifying_key.clone()),
    )
    .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?
    .verify()
    .map_err(|_| anyhow!("VerificationError::InvalidProof"))?;

    // Everything passed
    Ok(())
}

#[test]
fn test_verify() {
    let full_proof = get_params().unwrap();
    verify_full_proof(&full_proof).unwrap();
}

use test_proof::*;
mod test_proof {
    pub use anyhow::{anyhow, Error};
    pub use ark_bn254::Fr;
    pub use ark_bn254::{Bn254, G1Affine, G2Affine};
    pub use ark_groth16::VerifyingKey;
    pub use ark_serialize::CanonicalDeserialize;
    pub use risc0_zkvm::sha::{Digest, Digestible};

    // Deserialize an element over the G1 group from bytes in big-endian format
    pub(crate) fn g1_from_bytes(elem: &[Vec<u8>]) -> Result<G1Affine, Error> {
        if elem.len() != 2 {
            return Err(anyhow!("Malformed G1 field element"));
        }
        let g1_affine: Vec<u8> = elem[0]
            .iter()
            .rev()
            .chain(elem[1].iter().rev())
            .cloned()
            .collect();

        G1Affine::deserialize_uncompressed(&*g1_affine).map_err(|err| anyhow!(err))
    }

    // Deserialize an element over the G2 group from bytes in big-endian format
    pub(crate) fn g2_from_bytes(elem: &[Vec<Vec<u8>>]) -> Result<G2Affine, Error> {
        if elem.len() != 2 || elem[0].len() != 2 || elem[1].len() != 2 {
            return Err(anyhow!("Malformed G2 field element"));
        }
        let g2_affine: Vec<u8> = elem[0][1]
            .iter()
            .rev()
            .chain(elem[0][0].iter().rev())
            .chain(elem[1][1].iter().rev())
            .chain(elem[1][0].iter().rev())
            .cloned()
            .collect();

        G2Affine::deserialize_uncompressed(&*g2_affine).map_err(|err| anyhow!(err))
    }

    pub struct FullProof {
        pub proof: ark_groth16::Proof<Bn254>,
        pub public_inputs: [Fr; 5],
        pub verifying_key: VerifyingKey<Bn254>,
    }

    pub fn get_params() -> Result<FullProof, Error> {
        use risc0_zkvm::{Receipt, VerifierContext};

        let receipt_json = r#"{"inner":{"Groth16":{"seal":[45,246,218,104,51,104,29,192,142,175,6,64,131,16,66,17,123,125,224,149,74,78,224,25,61,239,72,119,243,161,103,172,47,34,174,32,64,169,5,165,49,68,146,179,8,145,46,120,2,93,150,39,216,18,189,86,217,68,51,191,210,73,100,167,32,182,70,228,7,134,118,104,18,172,167,126,186,1,241,52,128,155,252,205,55,144,162,173,60,109,199,211,105,154,87,183,22,31,133,188,169,187,212,154,28,70,18,119,25,14,45,126,22,34,218,50,81,167,48,151,187,166,49,85,30,164,119,17,13,48,111,197,236,96,188,94,146,60,165,245,80,180,62,61,67,60,187,110,238,90,67,96,21,246,144,196,249,190,255,203,46,227,174,97,56,124,243,151,89,195,166,61,129,252,64,120,209,158,254,84,131,44,38,86,236,45,14,246,253,65,217,155,11,38,58,243,122,100,195,208,46,155,156,59,233,140,19,55,93,23,1,98,6,125,116,128,31,155,213,91,184,27,105,146,46,207,204,63,189,77,164,154,105,16,152,171,67,119,221,78,128,178,102,125,157,148,228,10,108,61,206,248,110,210,101,244],"claim":{"Value":{"pre":{"Value":{"pc":2450036,"merkle_root":[1643847833,2089362361,3872213287,1646020003,316582930,996658657,1869743789,3295678572]}},"post":{"Value":{"pc":0,"merkle_root":[0,0,0,0,0,0,0,0]}},"exit_code":{"Halted":0},"input":{"Pruned":[0,0,0,0,0,0,0,0]},"output":{"Value":{"journal":{"Value":[1,0,0,0]},"assumptions":{"Value":[]}}}}},"verifier_parameters":[1763163472,2876521993,3272685530,2018367509,394453731,2734973759,718893618,4111358395]}},"journal":{"bytes":[1,0,0,0]},"metadata":{"verifier_parameters":[1763163472,2876521993,3272685530,2018367509,394453731,2734973759,718893618,4111358395]}}"#;
        let receipt: Receipt = serde_json::from_str(&receipt_json).unwrap();
        let ctx = VerifierContext::default();
        let proof = receipt.inner.groth16().unwrap();
        proof.verify_integrity().unwrap();

        let params = ctx
            .groth16_verifier_parameters
            .as_ref()
            .ok_or(anyhow!("VerificationError::VerifierParametersMissing"))?;

        let (a0, a1) = split_digest(params.control_root)
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let (c0, c1) = split_digest(proof.claim.digest())
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let mut id_bn554: Digest = params.bn254_control_id;
        id_bn554.as_mut_bytes().reverse();
        let id_bn254_fr = fr_from_hex_string(&hex::encode(id_bn554))
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;

        let seal = risc0_groth16::Seal::from_vec(&proof.seal)
            .map_err(|_| anyhow!("VerificationError::ReceiptFormatError"))?;
        let proof = ark_groth16::Proof::<Bn254> {
            a: g1_from_bytes(&seal.a)?,
            b: g2_from_bytes(&seal.b)?,
            c: g1_from_bytes(&seal.c)?,
        };

        // hack: params.verifying_key.0 is private --> just serialize + deserialize
        let serialized_verifying_key = serde_json::to_string(&params.verifying_key).unwrap();
        let deserialized_bytes: Vec<u8> = serde_json::from_str(&serialized_verifying_key).unwrap();
        let deserialized_verifying_key =
            VerifyingKey::<Bn254>::deserialize_uncompressed(deserialized_bytes.as_slice()).unwrap();

        Ok(FullProof {
            proof,
            public_inputs: [a0, a1, c0, c1, id_bn254_fr],
            verifying_key: deserialized_verifying_key,
        })
    }

    /// Splits the digest in half returning a scalar for each halve.
    pub fn split_digest(d: Digest) -> Result<(Fr, Fr), Error> {
        let big_endian: Vec<u8> = d.as_bytes().to_vec().iter().rev().cloned().collect();
        let middle = big_endian.len() / 2;
        let (b, a) = big_endian.split_at(middle);
        Ok((
            fr_from_bytes(&from_u256_hex(&hex::encode(a))?)?,
            fr_from_bytes(&from_u256_hex(&hex::encode(b))?)?,
        ))
    }

    /// Creates an [Fr] from a hex string
    pub fn fr_from_hex_string(val: &str) -> Result<Fr, Error> {
        fr_from_bytes(&from_u256_hex(val)?)
    }

    // Deserialize a scalar field from bytes in big-endian format
    pub(crate) fn fr_from_bytes(scalar: &[u8]) -> Result<Fr, Error> {
        let scalar: Vec<u8> = scalar.iter().rev().cloned().collect();
        ark_bn254::Fr::deserialize_uncompressed(&*scalar)
            // .map(Fr)
            .map_err(|err| anyhow!(err))
    }
    // Convert the U256 value to a byte array in big-endian format
    fn from_u256_hex(value: &str) -> Result<Vec<u8>, Error> {
        Ok(
            to_fixed_array(hex::decode(value).map_err(|_| anyhow!("conversion from u256 failed"))?)
                .to_vec(),
        )
    }

    fn to_fixed_array(input: Vec<u8>) -> [u8; 32] {
        let mut fixed_array = [0u8; 32];
        let start = core::cmp::max(32, input.len()) - core::cmp::min(32, input.len());
        fixed_array[start..].copy_from_slice(&input[input.len().saturating_sub(32)..]);
        fixed_array
    }
}
