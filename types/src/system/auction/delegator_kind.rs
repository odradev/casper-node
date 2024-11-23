use crate::{
    bytesrepr,
    bytesrepr::{FromBytes, ToBytes, U8_SERIALIZED_LENGTH},
    CLType, CLTyped, PublicKey, URef, URefAddr,
};
use alloc::vec::Vec;
use core::{
    fmt,
    fmt::{Display, Formatter},
};
#[cfg(feature = "datasize")]
use datasize::DataSize;
#[cfg(feature = "json-schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// DelegatorKindTag variants.
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum DelegatorKindTag {
    /// Public key.
    PublicKey = 0,
    /// Purse.
    Purse = 1,
}

/// Auction bid variants.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, PartialOrd, Ord)]
#[cfg_attr(feature = "datasize", derive(DataSize))]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
/// Kinds of delegation bids.
pub enum DelegatorKind {
    /// Delegation from public key.
    PublicKey(PublicKey),
    /// Delegation from purse.
    Purse(URefAddr),
}

impl DelegatorKind {
    /// DelegatorKindTag.
    pub fn tag(&self) -> DelegatorKindTag {
        match self {
            DelegatorKind::PublicKey(_) => DelegatorKindTag::PublicKey,
            DelegatorKind::Purse(_) => DelegatorKindTag::Purse,
        }
    }

    /// Returns true if the kind is a purse.
    pub fn is_purse(&self) -> bool {
        matches!(self, DelegatorKind::Purse(_))
    }
}

impl ToBytes for DelegatorKind {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        let (tag, mut serialized_data) = match self {
            DelegatorKind::PublicKey(public_key) => {
                (DelegatorKindTag::PublicKey, public_key.to_bytes()?)
            }
            DelegatorKind::Purse(uref_addr) => (DelegatorKindTag::Purse, uref_addr.to_bytes()?),
        };
        result.push(tag as u8);
        result.append(&mut serialized_data);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        U8_SERIALIZED_LENGTH
            + match self {
                DelegatorKind::PublicKey(pk) => pk.serialized_length(),
                DelegatorKind::Purse(addr) => addr.serialized_length(),
            }
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        writer.push(self.tag() as u8);
        match self {
            DelegatorKind::PublicKey(pk) => pk.write_bytes(writer)?,
            DelegatorKind::Purse(addr) => addr.write_bytes(writer)?,
        };
        Ok(())
    }
}

impl FromBytes for DelegatorKind {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder): (u8, &[u8]) = FromBytes::from_bytes(bytes)?;
        match tag {
            tag if tag == DelegatorKindTag::PublicKey as u8 => PublicKey::from_bytes(remainder)
                .map(|(pk, remainder)| (DelegatorKind::PublicKey(pk), remainder)),
            tag if tag == DelegatorKindTag::Purse as u8 => URefAddr::from_bytes(remainder)
                .map(|(addr, remainder)| (DelegatorKind::Purse(addr), remainder)),
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

impl Display for DelegatorKind {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            DelegatorKind::PublicKey(pk) => {
                write!(formatter, "{}", pk)
            }
            DelegatorKind::Purse(addr) => {
                write!(formatter, "{}", base16::encode_lower(addr))
            }
        }
    }
}

impl From<PublicKey> for DelegatorKind {
    fn from(value: PublicKey) -> Self {
        DelegatorKind::PublicKey(value)
    }
}

impl From<&PublicKey> for DelegatorKind {
    fn from(value: &PublicKey) -> Self {
        DelegatorKind::PublicKey(value.clone())
    }
}

impl From<URef> for DelegatorKind {
    fn from(value: URef) -> Self {
        DelegatorKind::Purse(value.addr())
    }
}

impl From<URefAddr> for DelegatorKind {
    fn from(value: URefAddr) -> Self {
        DelegatorKind::Purse(value)
    }
}

impl CLTyped for DelegatorKind {
    fn cl_type() -> CLType {
        CLType::Any
    }
}

#[cfg(test)]
mod tests {
    use crate::{bytesrepr, system::auction::delegator_kind::DelegatorKind, PublicKey, SecretKey};

    #[test]
    fn serialization_roundtrip() {
        let delegator_kind = DelegatorKind::PublicKey(PublicKey::from(
            &SecretKey::ed25519_from_bytes([42; SecretKey::ED25519_LENGTH]).unwrap(),
        ));

        bytesrepr::test_serialization_roundtrip(&delegator_kind);

        let delegator_kind = DelegatorKind::Purse([43; 32]);

        bytesrepr::test_serialization_roundtrip(&delegator_kind);
    }
}

#[cfg(test)]
mod prop_tests {
    use proptest::prelude::*;

    use crate::{bytesrepr, gens};

    proptest! {
        #[test]
        fn test_value_bid(kind in gens::delegator_kind_arb()) {
            bytesrepr::test_serialization_roundtrip(&kind);
        }
    }
}
