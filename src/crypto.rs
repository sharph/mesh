use anyhow::Result;
use base64::prelude::*;
use bincode::{Decode, Encode};
use ed25519_dalek::Signature;
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub type NodeId = [u8; 32];
pub type ShortId = [u8; 12];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicIdentity {
    pub public_key: NodeId,
}

impl PublicIdentity {
    pub fn short_id(&self) -> ShortId {
        self.public_key[0..12]
            .try_into()
            .expect("couldn't convert NodeId into ShortId")
    }
}

impl std::fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base64())
    }
}

#[derive(Clone, Debug)]
pub struct PrivateIdentity {
    private_key: [u8; 32],
    pub public_id: PublicIdentity,
}

impl PublicIdentity {
    pub fn verify(&self, msg: Vec<u8>, signature: &SignatureBytes) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_bytes(signature);
        Ok(verifying_key.verify(msg.as_slice(), &signature).is_ok())
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key)
    }
}

impl PrivateIdentity {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Self {
            private_key: *signing_key.as_bytes(),
            public_id: PublicIdentity {
                public_key: *verifying_key.as_bytes(),
            },
        }
    }

    pub fn sign(&self, msg: Vec<u8>) -> SignatureBytes {
        let mut signing_key: SigningKey = SigningKey::from_bytes(&self.private_key);
        let signature = signing_key.sign(msg.as_slice());
        signature.to_bytes()
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.private_key)
    }
}
