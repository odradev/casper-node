use alloc::vec::Vec;

#[cfg(feature = "datasize")]
use datasize::DataSize;
#[cfg(feature = "json-schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    bytesrepr::{self, FromBytes, ToBytes, U8_SERIALIZED_LENGTH},
    CLType, CLTyped, EraId, PublicKey, URef, URefAddr, U512,
};

use super::{BidAddr, DelegatorKind, WithdrawPurse};

/// UnbondKindTag variants.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum UnbondKindTag {
    /// Validator bid.
    Validator = 0,
    /// Validator bid.
    DelegatedAccount = 1,
    /// Delegator bid.
    DelegatedPurse = 2,
}

/// Unbond variants.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Ord, PartialOrd)]
#[cfg_attr(feature = "datasize", derive(DataSize))]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
pub enum UnbondKind {
    Validator(PublicKey),
    DelegatedPublicKey(PublicKey),
    DelegatedPurse(URefAddr),
}

impl UnbondKind {
    /// Returns UnbondKindTag.
    pub fn tag(&self) -> UnbondKindTag {
        match self {
            UnbondKind::Validator(_) => UnbondKindTag::Validator,
            UnbondKind::DelegatedPublicKey(_) => UnbondKindTag::DelegatedAccount,
            UnbondKind::DelegatedPurse(_) => UnbondKindTag::DelegatedPurse,
        }
    }

    /// Returns PublicKey, if any.
    pub fn maybe_public_key(&self) -> Option<PublicKey> {
        match self {
            UnbondKind::Validator(pk) | UnbondKind::DelegatedPublicKey(pk) => Some(pk.clone()),
            UnbondKind::DelegatedPurse(_) => None,
        }
    }

    /// Is this a validator unbond?
    pub fn is_validator(&self) -> bool {
        match self {
            UnbondKind::Validator(_) => true,
            UnbondKind::DelegatedPublicKey(_) | UnbondKind::DelegatedPurse(_) => false,
        }
    }

    /// Is this a delegator unbond?
    pub fn is_delegator(&self) -> bool {
        !self.is_validator()
    }

    /// The correct bid addr for this instance.
    pub fn bid_addr(&self, validator_public_key: &PublicKey) -> BidAddr {
        match self {
            UnbondKind::Validator(pk) => BidAddr::UnbondAccount {
                validator: validator_public_key.to_account_hash(),
                unbonder: pk.to_account_hash(),
            },
            UnbondKind::DelegatedPublicKey(pk) => BidAddr::DelegatedAccount {
                delegator: pk.to_account_hash(),
                validator: validator_public_key.to_account_hash(),
            },
            UnbondKind::DelegatedPurse(addr) => BidAddr::DelegatedPurse {
                validator: validator_public_key.to_account_hash(),
                delegator: *addr,
            },
        }
    }
}

impl ToBytes for UnbondKind {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        let (tag, mut serialized_data) = match self {
            UnbondKind::Validator(pk) => (UnbondKindTag::Validator, pk.to_bytes()?),
            UnbondKind::DelegatedPublicKey(pk) => (UnbondKindTag::DelegatedAccount, pk.to_bytes()?),
            UnbondKind::DelegatedPurse(addr) => (UnbondKindTag::DelegatedPurse, addr.to_bytes()?),
        };
        result.push(tag as u8);
        result.append(&mut serialized_data);
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        U8_SERIALIZED_LENGTH
            + match self {
                UnbondKind::Validator(pk) => pk.serialized_length(),
                UnbondKind::DelegatedPublicKey(pk) => pk.serialized_length(),
                UnbondKind::DelegatedPurse(addr) => addr.serialized_length(),
            }
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        writer.push(self.tag() as u8);
        match self {
            UnbondKind::Validator(pk) => pk.write_bytes(writer)?,
            UnbondKind::DelegatedPublicKey(pk) => pk.write_bytes(writer)?,
            UnbondKind::DelegatedPurse(addr) => addr.write_bytes(writer)?,
        };
        Ok(())
    }
}

impl FromBytes for UnbondKind {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder): (u8, &[u8]) = FromBytes::from_bytes(bytes)?;
        match tag {
            tag if tag == UnbondKindTag::Validator as u8 => PublicKey::from_bytes(remainder)
                .map(|(pk, remainder)| (UnbondKind::Validator(pk), remainder)),
            tag if tag == UnbondKindTag::DelegatedAccount as u8 => PublicKey::from_bytes(remainder)
                .map(|(pk, remainder)| (UnbondKind::DelegatedPublicKey(pk), remainder)),
            tag if tag == UnbondKindTag::DelegatedPurse as u8 => URefAddr::from_bytes(remainder)
                .map(|(delegator_bid, remainder)| {
                    (UnbondKind::DelegatedPurse(delegator_bid), remainder)
                }),
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

impl From<DelegatorKind> for UnbondKind {
    fn from(value: DelegatorKind) -> Self {
        match value {
            DelegatorKind::PublicKey(pk) => UnbondKind::DelegatedPublicKey(pk),
            DelegatorKind::Purse(addr) => UnbondKind::DelegatedPurse(addr),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "datasize", derive(DataSize))]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Unbond {
    /// Validators public key.
    validator_public_key: PublicKey,
    /// Unbond kind.
    unbond_kind: UnbondKind,
    /// Unbond amounts per era.
    eras: Vec<UnbondEra>,
}

impl Unbond {
    /// Creates [`Unbond`] instance for an unbonding request.
    pub const fn new(
        validator_public_key: PublicKey,
        unbond_kind: UnbondKind,
        eras: Vec<UnbondEra>,
    ) -> Self {
        Self {
            validator_public_key,
            unbond_kind,
            eras,
        }
    }

    /// Creates [`Unbond`] instance for an unbonding request.
    pub fn new_validator_unbond(validator_public_key: PublicKey, eras: Vec<UnbondEra>) -> Self {
        Self {
            validator_public_key: validator_public_key.clone(),
            unbond_kind: UnbondKind::Validator(validator_public_key),
            eras,
        }
    }

    /// Creates [`Unbond`] instance for an unbonding request.
    pub const fn new_delegated_account_unbond(
        validator_public_key: PublicKey,
        delegator_public_key: PublicKey,
        eras: Vec<UnbondEra>,
    ) -> Self {
        Self {
            validator_public_key,
            unbond_kind: UnbondKind::DelegatedPublicKey(delegator_public_key),
            eras,
        }
    }

    /// Creates [`Unbond`] instance for an unbonding request.
    pub const fn new_delegated_purse_unbond(
        validator_public_key: PublicKey,
        delegator_purse_addr: URefAddr,
        eras: Vec<UnbondEra>,
    ) -> Self {
        Self {
            validator_public_key,
            unbond_kind: UnbondKind::DelegatedPurse(delegator_purse_addr),
            eras,
        }
    }

    /// Checks if given request is made by a validator by checking if public key of unbonder is same
    /// as a key owned by validator.
    pub fn is_validator(&self) -> bool {
        match self.unbond_kind.maybe_public_key() {
            Some(pk) => pk == self.validator_public_key,
            None => false,
        }
    }

    /// Returns public key of validator.
    pub fn validator_public_key(&self) -> &PublicKey {
        &self.validator_public_key
    }

    /// Returns unbond kind.
    pub fn unbond_kind(&self) -> &UnbondKind {
        &self.unbond_kind
    }

    /// Returns eras unbond items.
    pub fn eras(&self) -> &Vec<UnbondEra> {
        &self.eras
    }

    /// Returns eras unbond items.
    pub fn eras_mut(&mut self) -> &mut Vec<UnbondEra> {
        &mut self.eras
    }

    /// Takes eras unbond items.
    pub fn take_eras(mut self) -> Vec<UnbondEra> {
        let eras = self.eras;
        self.eras = vec![];
        eras
    }

    /// Splits instance into eras that are not expired, and eras that are expired (if any).
    pub fn expired(self, era_id: EraId, unbonding_delay: u64) -> (Unbond, Option<Vec<UnbondEra>>) {
        let mut retained = vec![];
        let mut expired = vec![];
        for era in self.eras {
            if era_id >= era.era_of_creation() + unbonding_delay {
                expired.push(era);
            } else {
                retained.push(era)
            }
        }
        let ret = Unbond::new(self.validator_public_key, self.unbond_kind, retained);
        if !expired.is_empty() {
            (ret, Some(expired))
        } else {
            (ret, None)
        }
    }
}

impl ToBytes for Unbond {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(&self.validator_public_key.to_bytes()?);
        result.extend(&self.unbond_kind.to_bytes()?);
        result.extend(&self.eras.to_bytes()?);
        Ok(result)
    }
    fn serialized_length(&self) -> usize {
        self.validator_public_key.serialized_length()
            + self.unbond_kind.serialized_length()
            + self.eras.serialized_length()
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        self.validator_public_key.write_bytes(writer)?;
        self.unbond_kind.write_bytes(writer)?;
        self.eras.write_bytes(writer)?;
        Ok(())
    }
}

impl FromBytes for Unbond {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (validator_public_key, remainder) = FromBytes::from_bytes(bytes)?;
        let (unbond_kind, remainder) = FromBytes::from_bytes(remainder)?;
        let (eras, remainder) = FromBytes::from_bytes(remainder)?;

        Ok((
            Unbond {
                validator_public_key,
                unbond_kind,
                eras,
            },
            remainder,
        ))
    }
}

impl CLTyped for Unbond {
    fn cl_type() -> CLType {
        CLType::Any
    }
}

impl Default for Unbond {
    fn default() -> Self {
        Self {
            unbond_kind: UnbondKind::Validator(PublicKey::System),
            validator_public_key: PublicKey::System,
            eras: vec![],
        }
    }
}

impl From<WithdrawPurse> for Unbond {
    fn from(withdraw_purse: WithdrawPurse) -> Self {
        let unbond_kind =
            if withdraw_purse.validator_public_key == withdraw_purse.unbonder_public_key {
                UnbondKind::Validator(withdraw_purse.validator_public_key.clone())
            } else {
                UnbondKind::DelegatedPublicKey(withdraw_purse.unbonder_public_key.clone())
            };
        Unbond::new(
            withdraw_purse.validator_public_key,
            unbond_kind,
            vec![UnbondEra::new(
                withdraw_purse.bonding_purse,
                withdraw_purse.era_of_creation,
                withdraw_purse.amount,
                None,
            )],
        )
    }
}

/// Unbond amounts per era.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "datasize", derive(DataSize))]
#[cfg_attr(feature = "json-schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UnbondEra {
    /// Bonding Purse
    bonding_purse: URef,
    /// Era in which this unbonding request was created.
    era_of_creation: EraId,
    /// Unbonding Amount.
    amount: U512,
    /// The validator public key to re-delegate to.
    new_validator: Option<PublicKey>,
}

impl UnbondEra {
    /// Creates [`UnbondEra`] instance for an unbonding request.
    pub const fn new(
        bonding_purse: URef,
        era_of_creation: EraId,
        amount: U512,
        new_validator: Option<PublicKey>,
    ) -> Self {
        Self {
            bonding_purse,
            era_of_creation,
            amount,
            new_validator,
        }
    }

    /// Returns bonding purse used to make this unbonding request.
    pub fn bonding_purse(&self) -> &URef {
        &self.bonding_purse
    }

    /// Returns era which was used to create this unbonding request.
    pub fn era_of_creation(&self) -> EraId {
        self.era_of_creation
    }

    /// Returns unbonding amount.
    pub fn amount(&self) -> &U512 {
        &self.amount
    }

    /// Returns the public key for the new validator.
    pub fn new_validator(&self) -> &Option<PublicKey> {
        &self.new_validator
    }

    /// Sets amount to provided value.
    pub fn with_amount(&mut self, amount: U512) {
        self.amount = amount;
    }
}

impl ToBytes for UnbondEra {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        result.extend(&self.bonding_purse.to_bytes()?);
        result.extend(&self.era_of_creation.to_bytes()?);
        result.extend(&self.amount.to_bytes()?);
        result.extend(&self.new_validator.to_bytes()?);
        Ok(result)
    }
    fn serialized_length(&self) -> usize {
        self.bonding_purse.serialized_length()
            + self.era_of_creation.serialized_length()
            + self.amount.serialized_length()
            + self.new_validator.serialized_length()
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        self.bonding_purse.write_bytes(writer)?;
        self.era_of_creation.write_bytes(writer)?;
        self.amount.write_bytes(writer)?;
        self.new_validator.write_bytes(writer)?;
        Ok(())
    }
}

impl FromBytes for UnbondEra {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (bonding_purse, remainder) = FromBytes::from_bytes(bytes)?;
        let (era_of_creation, remainder) = FromBytes::from_bytes(remainder)?;
        let (amount, remainder) = FromBytes::from_bytes(remainder)?;
        let (new_validator, remainder) = Option::<PublicKey>::from_bytes(remainder)?;

        Ok((
            UnbondEra {
                bonding_purse,
                era_of_creation,
                amount,
                new_validator,
            },
            remainder,
        ))
    }
}

impl CLTyped for UnbondEra {
    fn cl_type() -> CLType {
        CLType::Any
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bytesrepr,
        system::auction::{
            unbond::{Unbond, UnbondKind},
            UnbondEra,
        },
        AccessRights, EraId, PublicKey, SecretKey, URef, U512,
    };

    const BONDING_PURSE: URef = URef::new([14; 32], AccessRights::READ_ADD_WRITE);
    const ERA_OF_WITHDRAWAL: EraId = EraId::MAX;

    fn validator_public_key() -> PublicKey {
        let secret_key = SecretKey::ed25519_from_bytes([42; SecretKey::ED25519_LENGTH]).unwrap();
        PublicKey::from(&secret_key)
    }

    fn delegated_account_unbond_kind() -> UnbondKind {
        let secret_key = SecretKey::ed25519_from_bytes([43; SecretKey::ED25519_LENGTH]).unwrap();
        UnbondKind::DelegatedPublicKey(PublicKey::from(&secret_key))
    }

    fn amount() -> U512 {
        U512::max_value() - 1
    }

    #[test]
    fn serialization_roundtrip_for_unbond() {
        let unbond_era = UnbondEra {
            bonding_purse: BONDING_PURSE,
            era_of_creation: ERA_OF_WITHDRAWAL,
            amount: amount(),
            new_validator: None,
        };

        let unbond = Unbond {
            validator_public_key: validator_public_key(),
            unbond_kind: delegated_account_unbond_kind(),
            eras: vec![unbond_era],
        };

        bytesrepr::test_serialization_roundtrip(&unbond);
    }

    #[test]
    fn should_be_validator_condition_for_unbond() {
        let validator_pk = validator_public_key();
        let validator_unbond = Unbond::new(
            validator_pk.clone(),
            UnbondKind::Validator(validator_pk),
            vec![],
        );
        assert!(validator_unbond.is_validator());
    }

    #[test]
    fn should_be_delegator_condition_for_unbond() {
        let delegator_unbond = Unbond::new(
            validator_public_key(),
            delegated_account_unbond_kind(),
            vec![],
        );
        assert!(!delegator_unbond.is_validator());
    }
}
