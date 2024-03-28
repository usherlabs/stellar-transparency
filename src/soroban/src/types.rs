use soroban_sdk::{contracttype, vec, Bytes, Env, String};

use crate::utils::{
    byte_to_hex_string_bytes, concatenate_bytes, number_to_string_bytes, string_to_bytes,
};

#[contracttype]
#[derive(Debug, Clone)]

pub enum RefOption {
    Some(PrevMsgRef),
    None,
}

#[contracttype]
#[derive(Debug, Clone)]

pub enum StringOption {
    Some(String),
    None,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct Payload {
    pub stream_id: u64,
    pub stream_partition: u64,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct MessageId {
    pub stream_id: String,
    pub stream_partition: u64,
    pub timestamp: u64,
    pub sequence_number: u64,

    // pass this as bytes (manual conversion since streamr provides it as a hex string)
    pub publisher_id: Bytes,
    pub msg_chain_id: String,
}
#[contracttype]
#[derive(Debug, Clone)]
pub struct PrevMsgRef {
    pub timestamp: u64,
    pub sequence_number: u64,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct Message {
    pub message_id: MessageId,
    pub prev_msg_ref: RefOption,
    pub message_type: u64,
    pub content_type: u64,
    pub encryption_type: u64,
    pub group_key_id: StringOption,
    pub new_group_key: StringOption,
    // pass this as bytes (manual conversion since streamr provides it as a hex string)
    pub signature: Bytes, //pass signature as bytes
    pub serialized_content: String,
}

impl Message {
    // return the piblisher address as ASCII encoded bytes, which is basiically the same as a string
    pub fn get_publisher_address(&self, env: &Env) -> Bytes {
        let publisher = byte_to_hex_string_bytes(env, self.message_id.publisher_id.clone());
        return publisher;
    }

    pub fn get_signature(&self) -> Bytes {
        self.signature.clone()
    }

    pub fn get_signature_payload(&self, env: &Env) -> Bytes {
        let prev = if let RefOption::Some(ref prev_msg_ref) = self.prev_msg_ref{
            concatenate_bytes(
                env,
                vec![
                    env,
                    number_to_string_bytes(env, prev_msg_ref.timestamp as u64),
                    number_to_string_bytes(env, prev_msg_ref.sequence_number as u64),
                ],
            )
        } else {
            Bytes::new(env)
        };

        let new_group_key = if let StringOption::Some(ref new_group_key) = self.new_group_key {
            string_to_bytes(env, new_group_key.clone())
        } else {
            Bytes::new(env)
        };

        let payload = concatenate_bytes(
            env,
            vec![
                env,
                string_to_bytes(env, self.message_id.stream_id.clone()),
                number_to_string_bytes(env, self.message_id.stream_partition as u64),
                number_to_string_bytes(env, self.message_id.timestamp as u64),
                number_to_string_bytes(env, self.message_id.sequence_number as u64),
                self.get_publisher_address(env),
                string_to_bytes(env, self.message_id.msg_chain_id.clone()),
                prev,
                string_to_bytes(env, self.serialized_content.clone()),
                new_group_key,
            ],
        );

        return payload;
    }
}
