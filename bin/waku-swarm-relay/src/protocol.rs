use chrono::Utc;
use prost::Message;

#[derive(Clone, Message)]
pub struct Ping {
    #[prost(uint64, tag = "1")]
    pub timestamp: u64,
}

impl Ping {
    pub fn new() -> Self {
        Ping {
            timestamp: Utc::now().timestamp_millis() as u64,
        }
    }
}

#[derive(Clone, Message)]
pub struct Pong {
    #[prost(uint64, tag = "1")]
    pub timestamp: u64,
    #[prost(bytes, tag = "2")]
    pub address: Vec<u8>,
}

impl Pong {
    pub fn new(address: Vec<u8>, signature: Vec<u8>) -> Self {
        Pong {
            timestamp: Utc::now().timestamp_millis() as u64,
            address,
        }
    }
}

#[derive(Clone, Message)]
pub struct RetrievalRequest {
    #[prost(bytes, tag = "1")]
    pub chunk_address: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct RetrievalDelivery {
    #[prost(bytes, tag = "1")]
    pub data: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub stamp: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct PushSyncDelivery {
    #[prost(bytes, tag = "1")]
    pub data: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub stamp: Vec<u8>,
}

#[derive(Clone, Message)]
pub struct PushSyncReceipt {
    #[prost(bytes, tag = "1")]
    pub chunk_address: Vec<u8>,
    #[prost(bytes, tag = "2")]
    pub signature: Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub nonce: Vec<u8>,
}
