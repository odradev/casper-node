use core::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use casper_macros::{casper, CasperABI};
use casper_sdk::{collections::Map, host, types::Address};

use crate::{error::Cep18Error, security_badge::SecurityBadge};

#[derive(BorshSerialize, BorshDeserialize, CasperABI, Debug, Clone)]
pub struct CEP18State {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64, // TODO: U256
    pub balances: Map<Address, u64>,
    pub allowances: Map<(Address, Address), u64>,
    pub security_badges: Map<Address, SecurityBadge>,
    pub enable_mint_burn: bool,
}

impl CEP18State {
    pub(crate) fn sec_check(&self, allowed_badge_list: &[SecurityBadge]) -> Result<(), Cep18Error> {
        let caller = host::get_caller();
        let security_badge = self
            .security_badges
            .get(&caller)
            .ok_or(Cep18Error::InsufficientRights)?;
        if !allowed_badge_list.contains(&security_badge) {
            return Err(Cep18Error::InsufficientRights);
        }
        Ok(())
    }

    fn transfer_balance(
        &mut self,
        sender: &Address,
        recipient: &Address,
        amount: u64,
    ) -> Result<(), Cep18Error> {
        if amount == 0 {
            return Ok(());
        }

        let sender_balance = self.balances.get(&sender).unwrap_or_default();

        let new_sender_balance = sender_balance
            .checked_sub(amount)
            .ok_or(Cep18Error::InsufficientBalance)?;

        let recipient_balance = self.balances.get(&recipient).unwrap_or_default();

        let new_recipient_balance = recipient_balance
            .checked_add(amount)
            .ok_or(Cep18Error::Overflow)?;

        self.balances.insert(sender, &new_sender_balance);
        self.balances.insert(recipient, &new_recipient_balance);
        Ok(())
    }
}

impl CEP18State {
    pub(crate) fn new(name: &str, symbol: &str, decimals: u8, total_supply: u64) -> CEP18State {
        CEP18State {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            total_supply,
            balances: Map::new("balances"),
            allowances: Map::new("allowances"),
            security_badges: Map::new("security_badges"),
            enable_mint_burn: false,
        }
    }
}

#[casper(trait_definition)]
pub trait CEP18 {
    #[casper(private)]
    fn state(&self) -> &CEP18State;

    #[casper(private)]
    fn state_mut(&mut self) -> &mut CEP18State;

    fn name(&self) -> &str {
        &self.state().name
    }

    fn symbol(&self) -> &str {
        &self.state().symbol
    }

    fn decimals(&self) -> u8 {
        self.state().decimals
    }

    fn total_supply(&self) -> u64 {
        self.state().total_supply
    }

    fn balance_of(&self, address: Address) -> u64 {
        self.state().balances.get(&address).unwrap_or_default()
    }

    fn allowance(&self, spender: Address, owner: Address) {
        self.state()
            .allowances
            .get(&(spender, owner))
            .unwrap_or_default();
    }

    #[casper(revert_on_error)]
    fn approve(&mut self, spender: Address, amount: u64) -> Result<(), Cep18Error> {
        let owner = host::get_caller();
        if owner == spender {
            return Err(Cep18Error::CannotTargetSelfUser);
        }
        let lookup_key = (owner, spender);
        self.state_mut().allowances.insert(&lookup_key, &amount);
        Ok(())
    }

    #[casper(revert_on_error)]
    fn decrease_allowance(&mut self, spender: Address, amount: u64) -> Result<(), Cep18Error> {
        let owner = host::get_caller();
        if owner == spender {
            return Err(Cep18Error::CannotTargetSelfUser);
        }
        let lookup_key = (owner, spender);
        let allowance = self.state().allowances.get(&lookup_key).unwrap_or_default();
        let allowance = allowance.saturating_sub(amount);
        self.state_mut().allowances.insert(&lookup_key, &allowance);
        Ok(())
    }

    #[casper(revert_on_error)]
    fn increase_allowance(&mut self, spender: Address, amount: u64) -> Result<(), Cep18Error> {
        let owner = host::get_caller();
        if owner == spender {
            return Err(Cep18Error::CannotTargetSelfUser);
        }
        let lookup_key = (owner, spender);
        let allowance = self.state().allowances.get(&lookup_key).unwrap_or_default();
        let allowance = allowance.saturating_add(amount);
        self.state_mut().allowances.insert(&lookup_key, &allowance);
        Ok(())
    }

    #[casper(revert_on_error)]
    fn transfer(&mut self, recipient: Address, amount: u64) -> Result<(), Cep18Error> {
        let sender = host::get_caller();
        if sender == recipient {
            return Err(Cep18Error::CannotTargetSelfUser);
        }
        self.state_mut()
            .transfer_balance(&sender, &recipient, amount)?;
        Ok(())
    }

    #[casper(revert_on_error)]
    fn transfer_from(
        &mut self,
        owner: Address,
        recipient: Address,
        amount: u64,
    ) -> Result<(), Cep18Error> {
        let spender = host::get_caller();
        if owner == recipient {
            return Err(Cep18Error::CannotTargetSelfUser);
        }

        if amount == 0 {
            return Ok(());
        }

        let spender_allowance = self
            .state()
            .allowances
            .get(&(owner, spender))
            .unwrap_or_default();
        let new_spender_allowance = spender_allowance
            .checked_sub(amount)
            .ok_or(Cep18Error::InsufficientAllowance)?;

        self.state_mut()
            .transfer_balance(&owner, &recipient, amount)?;

        self.state_mut()
            .allowances
            .insert(&(owner, spender), &new_spender_allowance);

        Ok(())
    }

    #[casper(revert_on_error)]
    fn mint(&mut self, owner: Address, amount: u64) -> Result<(), Cep18Error> {
        if !self.state().enable_mint_burn {
            return Err(Cep18Error::MintBurnDisabled);
        }

        self.state()
            .sec_check(&[SecurityBadge::Admin, SecurityBadge::Minter])?;

        let balance = self.state().balances.get(&owner).unwrap_or_default();
        let new_balance = balance.checked_add(amount).ok_or(Cep18Error::Overflow)?;
        self.state_mut().balances.insert(&owner, &new_balance);
        self.state_mut().total_supply = self
            .state()
            .total_supply
            .checked_add(amount)
            .ok_or(Cep18Error::Overflow)?;
        Ok(())
    }

    #[casper(revert_on_error)]
    fn burn(&mut self, owner: Address, amount: u64) -> Result<(), Cep18Error> {
        if !self.state().enable_mint_burn {
            return Err(Cep18Error::MintBurnDisabled);
        }

        if owner != host::get_caller() {
            return Err(Cep18Error::InvalidBurnTarget);
        }

        let balance = self.state().balances.get(&owner).unwrap_or_default();
        let new_balance = balance.checked_add(amount).ok_or(Cep18Error::Overflow)?;
        self.state_mut().balances.insert(&owner, &new_balance);
        self.state_mut().total_supply = self
            .state()
            .total_supply
            .checked_sub(amount)
            .ok_or(Cep18Error::Overflow)?;
        Ok(())
    }
}
