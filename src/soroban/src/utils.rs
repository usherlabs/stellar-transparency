use crate::types::Message;
use soroban_sdk::{vec, Bytes, BytesN, Env, String, Vec};

// recover the corresponding ecdsa address used to make this signature
pub fn recover_ecdsa_public_key(env: &Env, message_bytes: Bytes, signature: Bytes) -> BytesN<20> {
    // hash the eth message
    let message_digest = hash_eth_message(env, message_bytes);
    let signature_bytes: BytesN<64> = signature.slice(0..64).try_into().unwrap();
    let recovery_id = signature.last().unwrap() as u32;

    // recover the ECDSA public key
    let pk = env
        .crypto()
        .secp256k1_recover(&message_digest, &signature_bytes, recovery_id - 27);

    let pub_key_bytes: Bytes = pk.into();

    // convert it from 65 bytes to 20 bytes
    // slice of the first byte before hash because it is 0x04 and it just represents an uncompressed signatire
    let pubkey_hash: Bytes = env.crypto().keccak256(&pub_key_bytes.slice(1..)).into();
    let pubkey: BytesN<20> = pubkey_hash.slice(12..).try_into().unwrap();

    return pubkey;
}

// convert a given string to a bytes array of its ascii characters
pub fn string_to_bytes(env: &Env, str1: String) -> Bytes {
    let str_len = str1.len() as usize;

    // how large should this buffer be?
    let mut buffer: [u8; 300000] = [0; 300000];

    str1.copy_into_slice(&mut buffer[..str_len]);
    Bytes::from_slice(&env, &buffer[0..str_len])
}

// represent a number as a series of bytes which stand for the ASCII code for each number
// i.e 012 => [48, 49, 50]
pub fn number_to_string_bytes(env: &Env, number: u64) -> Bytes {
    // Initialize an empty string to hold the result
    // how large should this buffer be?
    let mut buffer: [u8; 100000] = [0; 100000];
    let mut len = 0;

    // Convert the number to a positive value for simplicity
    let mut num = number;

    // if the number we are trying to convert is zero then just provide 48 which is ascii for buffer
    if num == 0 {
        buffer[0] = 48;
        len += 1
    };

    // Convert each digit of the number to a string and prepend it to the result
    while num > 0 {
        let digit = (num % 10) as u8; // Get the last digit

        buffer[len] = digit + 48; //add 48 to the number to get the ascii code
        num /= 10; // Move to the next digit
        len += 1; //increment index
    }

    // it is reversed because we start converting to ASCII bytes from the least significant digit instead of from the front
    // so we need to reverse this array so the items last attended to come back to the front where they are supposed to be
    let reversed_buffer = &mut buffer[0..len];
    reversed_buffer.reverse();

    Bytes::from_slice(&env, reversed_buffer)
}

// hash a given message to be compatible with eth signed message
pub fn hash_eth_message(env: &Env, message_bytes: Bytes) -> BytesN<32> {
    let prefix = String::from_str(&env, "\x19Ethereum Signed Message:\n");

    // Convert strings to bytes
    let prefix_bytes = string_to_bytes(env, prefix);
    let len = message_bytes.len();
    let len_string_bytes = number_to_string_bytes(env, len as u64);

    let eth_message: Bytes = concatenate_bytes(
        env,
        vec![env, prefix_bytes, len_string_bytes, message_bytes],
    );

    let hash: BytesN<32> = env.crypto().keccak256(&eth_message);

    hash
}

// concatenate multiple bytes === abi.encodePacked implementation
pub fn concatenate_bytes(env: &Env, strings: Vec<Bytes>) -> Bytes {
    // create a byte buffer
    let mut concatenated_bytes = Bytes::new(env);

    for byte_group in strings {
        for byte in byte_group {
            concatenated_bytes.insert(concatenated_bytes.len(), byte)
        }
    }

    return concatenated_bytes;
}

// this function converts a group of bytey to its ASCII encoded hexadecimal value
// i.e [78] => [4e] => [52, 101]
// the importance of this is to convert bytes to hex_string
// but since we cannot construct the actual string due to soroban limitations
// we will construct the string as bytes of the ascii encoded values of the hexadecimal representation
//  which is bascially the same as the string representation and can be compared to a provided string prepresentation
pub fn byte_to_hex_string_bytes(env: &Env, bytes: Bytes) -> Bytes {
    let zero_x_in_ascii_bytes = [48, 120];
    let mut hex_string_bytes = Bytes::from_slice(&env, &zero_x_in_ascii_bytes);

    for byte in bytes {
        // basically for a given byte we want to get the first 4 and last 4 bits
        let high_nibble = byte >> 4; // Shift right by 4 bits to get the high nibble
        let low_nibble = byte & 0x0F; // Use a bitmask to get the low nibble

        hex_string_bytes.insert(
            hex_string_bytes.len(),
            convert_nibble_to_string_byte(env, high_nibble),
        );
        hex_string_bytes.insert(
            hex_string_bytes.len(),
            convert_nibble_to_string_byte(env, low_nibble),
        );
    }

    hex_string_bytes
}

// convert from 4 to 52, which is the ascii equivalent of 4
// convert from a(10) to 97 which is the ascii equivalent of a
fn convert_nibble_to_string_byte(env: &Env, nibble: u8) -> u8 {
    if nibble < 10 {
        // if the number is less than 10 then use our already existing function that converts numbers to ascii equivalent
        return number_to_string_bytes(env, nibble as u64).get(0).unwrap();
    }

    // better to use a map than a formula for readability
    // return 87 + nibble;
    match nibble {
        10 => 97,
        11 => 98,
        12 => 99,
        13 => 100,
        14 => 101,
        15 => 102,
        // we should never get here as the max possible value is 15
        _ => panic!("INVALID NIBBLE"),
    }
}

// takes in a streamr message and returns a boolean if it is valid
pub fn verify_single_process(env: &Env, message: &Message) -> bool {
    let payload = message.get_signature_payload(&env);
    let signature = message.get_signature();

    // conver this PK to string bytes
    let recovered_pub_key: Bytes = recover_ecdsa_public_key(&env, payload, signature).into();
    let expected_pub_key = message.message_id.publisher_id.clone();

    return recovered_pub_key == expected_pub_key;
}
