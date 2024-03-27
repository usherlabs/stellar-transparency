use crate::types::{Message, MessageId, RefOption, StringOption};

use crate::utils::verify_single_process;
use crate::{
    utils::{
        byte_to_hex_string_bytes, concatenate_bytes, hash_eth_message, number_to_string_bytes,
        recover_ecdsa_public_key, string_to_bytes,
    },
    Contract,
};
use soroban_sdk::{vec, Bytes, BytesN, Env, String};
extern crate std;

pub fn get_mock_proof(env: &Env) -> Message{ 
    Message{
        message_id: MessageId{ 
            stream_id: String::from_str(env, "0x392bd2cb87f5670f321ad521397d30a00c582b34/mpctlsproofspublic"),
            stream_partition: 0,
            timestamp: 1711476111368,
            sequence_number: 0,
            publisher_id: hex_to_bytes_vec(env,"0x392bd2cb87f5670f321ad521397d30a00c582b34"),
            msg_chain_id: String::from_str(env ,"0ZrVzdLRScL7p19mvIzk")
        },
        prev_msg_ref: RefOption::None,
        message_type: 27,
        content_type: 0,
        encryption_type: 0,
        group_key_id: StringOption::None,
        new_group_key: StringOption::None,
        signature: hex_to_bytes_vec(env, "0xf6c4c8522cd655f7d91069a278ead7e4c7ff7d5889f9042dd373a3fb8fd186eb3998fca8d0e4f3bc8a98adcbdc48056d581e46d1e7aa83861616e177f1efa6041b"),
        serialized_content: String::from_str(env,  "{\"name\":\"alex\"}")
    }
}

pub fn hex_to_bytes_vec(env: &Env, str: &str) -> Bytes {
    let starts_from: usize;
    if str.starts_with("0x") {
        starts_from = 2;
    } else {
        starts_from = 0;
    }

    let vec_bytes = (starts_from..str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&str[i..i + 2], 16).unwrap())
        .collect::<std::vec::Vec<u8>>();

    return Bytes::from_slice(env, &vec_bytes);
}


#[test]
fn test_contract_version() {
    let version = Contract::version();
    assert_eq!(version, 1)
}

#[test]
fn test_string_to_bytes() {
    let env = Env::default();
    let text = "";

    let message = String::from_str(&env, text);
    let output_bytes = string_to_bytes(&env, message.clone());
    std::println!("{:?}",output_bytes);
    assert_eq!(output_bytes, Bytes::from_slice(&env, text.as_bytes()))
}

#[test]
fn test_number_to_string_bytes() {
    let env = Env::default();
    let number = 1219123253;

    let output = number_to_string_bytes(&env, number);

    assert_eq!(
        output,
        Bytes::from_slice(&env, std::format!("{}", number).as_bytes())
    );
}

#[test]
fn test_hash_eth_message() {
    let env = Env::default();
    let text = "hello";
    // this is the expected output in bytes
    let expected_output: BytesN<32> = Bytes::from_slice(
        &env,
        &[
            80, 178, 196, 63, 211, 145, 6, 186, 251, 186, 13, 163, 79, 196, 48, 225, 249, 30, 60,
            150, 234, 42, 206, 226, 188, 52, 17, 159, 146, 179, 119, 80,
        ],
    )
    .try_into()
    .unwrap();

    let message = String::from_str(&env, text);
    let hashed_eth_message = hash_eth_message(&env, string_to_bytes(&env, message));

    assert_eq!(hashed_eth_message, expected_output)
}

#[test]
fn test_concatenate_bytes() {
    let env = Env::default();

    let strings = vec![
        &env,
        string_to_bytes(&env, String::from_str(&env, "hello ")),
        string_to_bytes(&env, String::from_str(&env, "world")),
    ];

    let concatenated = concatenate_bytes(&env, strings);

    assert_eq!(
        concatenated,
        Bytes::from_slice(&env, "hello world".as_bytes())
    );
}

#[test]
fn text_recover_ecdsa_public_keys() {
    let env = Env::default();
    let text = "hello";

    let message = String::from_str(&env, text);
    let expected_pub_key = "0x57c1d4dbfbc9f8cb77709493cc43eaa3cd505432";
    let signature = "0xbb97398a31ab12d204b803dbf07140971f8292ce70178d1b0d4467057a6afe155680d82f06c997fa5b2ede1b965f9d7526dbaf2fb96ca414e4ef84f466b8ef551b";

    let signature_bytes = hex_to_bytes_vec(&env, signature);
    let expected_pub_key_bytes = hex_to_bytes_vec(&env, expected_pub_key);

    let recovered_pub_key: Bytes =
        recover_ecdsa_public_key(&env, string_to_bytes(&env, message), signature_bytes).into();

    assert_eq!(recovered_pub_key, expected_pub_key_bytes);
}

#[test]
fn test_byte_to_hex_string_bytes() {
    let env = Env::default();

    // express this hex in string and byte form
    let string_hex = "0x392bd2cb87f5670f321ad521397d30a00c582b34";
    let hex_bytes = hex_to_bytes_vec(&env,string_hex);

    // express the hex string as ascii encoded characters in bytes
    // ? we are using ascii encoded values rather than the actual hex values
    // ? because we want to represent the hex as a string still, just in bytes.
    let ascii_bytes = string_to_bytes(&env, String::from_str(&env, string_hex));

    // use the developed function to convert from hex_bytes to string_bytes
    // basically convert from byte array to ascii array.
    let derived_ascii_bytes = byte_to_hex_string_bytes(&env, hex_bytes);

    assert_eq!(ascii_bytes, derived_ascii_bytes)
}

#[test]
fn test_verify_process() {
    let env = Env::default();
    let message = get_mock_proof(&env);

    let verified = verify_single_process(&env, &message);
    assert_eq!(verified, true);
}


#[test]
fn test_verify_processes() {
    let env = Env::default();
    let message = get_mock_proof(&env);

    let verified = Contract::verify_process(env.clone(), vec![&env, message.clone(),message.clone()],String::from_str(&env, "text") );
    assert_eq!(verified, true);
}

