#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String, Vec,
};
use types::Message;
use utils::verify_single_process;


pub mod types;
pub mod utils;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
}


#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn version() -> u32 {
        1
    }

    // takes in a vec struct and verifies all the content in it. only uscccessfull if everything is well verified
    pub fn verify_process(env: Env, messages: Vec<Message>, process_name: String) -> bool {
        // loop through and if any false then throw panic otherwise emit event

        for message in messages.iter() {
            let is_valid = verify_single_process(&env, &message);
            if !is_valid {
                panic!("INVALID_SIGNATURE");
            }
        }

        // emit success event
        env.events().publish(
            (symbol_short!("PROCESS"), symbol_short!("VERIFIED")),
            process_name,
        );

        return true;
    }

    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[cfg(test)]
mod test;
