mod arguments;
mod protocol;

use clap::Parser;
use ethers_signers::{LocalWallet, Signer};
use tracing::{debug, error, info};
use waku_bindings::{
    waku_new, waku_set_event_callback, Encoding, Multiaddr, Running,
    WakuContentTopic, WakuLogLevel, WakuMessage, WakuNodeConfig, WakuNodeHandle, WakuPubSubTopic,
};

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use prost::Message;

use crate::protocol::{Ping, Pong};

struct App {
    pub node_handle: WakuNodeHandle<Running>,
}

/// The enrtree address of the production waku2 fleet
pub static ENRTREE: &str =
    "enrtree://AOGECG2SPND25EEFMAJ5WF3KSGJNSGV356DSTL2YVLLZWIV6SAYBM@prod.nodes.status.im";
// set to default-waku for prod
pub static PUBSUB: &str = "dev-waku";

/// Setup a waku node and connect to the waku fleet
pub fn setup_node_handle(_enrtree: String) -> Result<WakuNodeHandle<Running>, WakuHandlingError> {
    let node_config = WakuNodeConfig {
        discv5: Some(true),
        relay_topics: vec![WakuPubSubTopic::new(PUBSUB, Encoding::Proto)],
        log_level: Some(WakuLogLevel::Info),
        ..Default::default()
    };

    let node_handle = waku_new(Some(node_config))
        .map_err(WakuHandlingError::CreateNodeError)?
        .start()
        .map_err(WakuHandlingError::CreateNodeError)?;

    let peer_address: Multiaddr =
        "/ip4/127.0.0.1/tcp/8000/ws/p2p/16Uiu2HAmPNcgHTD1Au6avQSVemez62ApCxVrDVmEvCgCEXkx4J6D"
            .parse()
            .unwrap();

    let peer_id = node_handle
        .add_peer(&peer_address, waku_bindings::ProtocolId::Relay)
        .unwrap();

    node_handle
        .connect_peer_with_id(&peer_id, Some(Duration::from_secs(1)))
        .unwrap();

    info!(
        id = tracing::field::debug(node_handle.peer_id()),
        "Initialized node handle with local peer_id",
    );

    Ok(node_handle)
}

#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub payload: Vec<u8>,
    pub content_topic: WakuContentTopic,
}

#[tokio::main]
async fn main() {
    let args = crate::arguments::Arguments::parse();
    logging::initialize(
        args.logging.log_filter.as_str(),
        args.logging.log_stderr_threshold,
    );

    let wallet = args.private_key.parse::<LocalWallet>().unwrap();

    info!(
        address = tracing::field::debug(wallet.address()),
        "Starting waku-swarm-relay"
    );

    let _parent_span = tracing::info_span!("main").entered();

    // Create an app instance
    let app = Arc::new(App {
        node_handle: setup_node_handle(ENRTREE.to_string()).expect("Unable to parse enrtree"),
    });

    let _ping_topic: WakuContentTopic = "/swarm-waku/1/ping/proto".parse().unwrap();
    let pong_topic: WakuContentTopic = "/swarm-waku/1/pong/proto".parse().unwrap();

    let pubsub_topic = WakuPubSubTopic::new(PUBSUB, Encoding::Proto);

    // use an unbounded channel to send requests to the main loop
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

    // Monitor for incoming requests
    waku_set_event_callback(move |signal| {
        if let waku_bindings::Event::WakuMessage(event) = signal.event() {
            let msg = event.waku_message();
            sender
                .send(ReceivedMessage {
                    payload: msg.payload().to_vec(),
                    content_topic: msg.content_topic().clone(),
                })
                .unwrap();
            debug!("Received message");
            return;
        }
    });

    // Check if there are enough peers. If not, exit the program.
    if app.node_handle.relay_enough_peers(None).is_err() {
        println!("Not enough peers to run the bridge. Exiting.");
        std::process::exit(1);
    }

    // Wait for incoming requests
    while let Some(msg) = receiver.recv().await {
        debug!("Received message: {:?}", msg);

        if msg.content_topic.application_name != "swarm-waku" {
            continue;
        }

        match msg.content_topic.content_topic_name.to_string().as_str() {
            "ping" => {
                debug!(
                    ping = tracing::field::debug(msg.payload.clone()),
                    "Received ping"
                );
                let ping: Ping = match prost::Message::decode(msg.payload.as_slice()) {
                    Ok(ping) => ping,
                    Err(e) => {
                        error!("Failed to decode ping: {}", e);
                        continue;
                    }
                };
                let pong = Pong {
                    timestamp: ping.timestamp,
                    address: wallet.address().as_bytes().to_vec(),
                };
                let mut buf = Vec::new();
                match pong.encode(&mut buf) {
                    Ok(_) => {
                        // create the WakuMessage
                        let waku_message = WakuMessage::new(
                            buf,
                            pong_topic.clone(),
                            1,
                            Utc::now().timestamp_millis() as usize,
                            vec![],
                            true,
                        );
                        let _msg_id = app
                            .node_handle
                            .relay_publish_message(&waku_message, Some(pubsub_topic.clone()), None)
                            .unwrap();
                        debug!("Published pong: {:?}", waku_message);
                    }
                    Err(e) => {
                        error!("Failed to encode pong: {}", e);
                        continue;
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WakuHandlingError {
    #[error("Unable to create waku node: {}", .0)]
    CreateNodeError(String),
}
