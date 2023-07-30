mod arguments;
mod protocol;

use arguments::Arguments;
use clap::Parser;
use ethers_signers::{LocalWallet, Signer};
use reqwest::Client;
use tracing::{debug, error, info};
use waku_bindings::{
    waku_new, waku_set_event_callback, Encoding, Running, WakuContentTopic, WakuLogLevel,
    WakuMessage, WakuNodeConfig, WakuNodeHandle, WakuPubSubTopic,
};

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use prost::Message;

use crate::protocol::{Ping, Pong, RetrievalDelivery, RetrievalRequest};

struct App {
    pub node_handle: WakuNodeHandle<Running>,
}

/// The enrtree address of the production waku2 fleet
pub static ENRTREE: &str =
    "enrtree://AOGECG2SPND25EEFMAJ5WF3KSGJNSGV356DSTL2YVLLZWIV6SAYBM@prod.nodes.status.im";
// set to default-waku for prod
pub static PUBSUB: &str = "default-waku";

/// Setup a waku node and connect to the waku fleet
pub fn setup_node_handle(args: &Arguments) -> Result<WakuNodeHandle<Running>, WakuHandlingError> {
    // Base node configuration
    let node_config = WakuNodeConfig {
        discv5: Some(true),
        relay_topics: vec![WakuPubSubTopic::new(PUBSUB, Encoding::Proto)],
        log_level: Some(WakuLogLevel::Info),
        port: Some(0),
        ..Default::default()
    };

    // Create the node
    let node_handle = waku_new(Some(node_config))
        .map_err(WakuHandlingError::CreateNodeError)?
        .start()
        .map_err(WakuHandlingError::CreateNodeError)?;

    // Iterate through the list of peers and add them to the node
    for peer in &args.peer {
        let peer_id = node_handle
            .add_peer(peer, waku_bindings::ProtocolId::Relay)
            .unwrap();

        node_handle
            .connect_peer_with_id(&peer_id, Some(Duration::from_secs(1)))
            .unwrap();
    }

    info!(
        id = tracing::field::debug(node_handle.peer_id()),
        "Initialized node handle with local peer_id",
    );

    Ok(node_handle)
}

#[tokio::main]
async fn main() {
    // Parse the arguments and initialise logging
    let args = crate::arguments::Arguments::parse();
    logging::initialize(
        args.logging.log_filter.as_str(),
        args.logging.log_stderr_threshold,
    );

    // Create a wallet from the private key used for signing messages
    let wallet = args.private_key.parse::<LocalWallet>().unwrap();

    info!(
        address = tracing::field::debug(wallet.address()),
        "Starting waku-swarm-relay"
    );

    let _parent_span = tracing::info_span!("main").entered();

    // Create an app instance
    let app = Arc::new(App {
        node_handle: setup_node_handle(&args).expect("Failed to setup node handle"),
    });

    let ping_topic: WakuContentTopic = "/swarm-waku/1/ping/proto".parse().unwrap();
    let pong_topic: WakuContentTopic = "/swarm-waku/1/pong/proto".parse().unwrap();
    let retrieval_request_topic: WakuContentTopic =
        "/swarm-waku/1/retrieval-request/proto".parse().unwrap();
    let retrieval_delivery_topic: WakuContentTopic =
        "/swarm-waku/1/retrieval-delivery/proto".parse().unwrap();

    let pubsub_topic = WakuPubSubTopic::new(PUBSUB, Encoding::Proto);

    // Use an unbounded channel for sending requests to the main loop
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

    // Set the waku bindings event callback
    waku_set_event_callback(move |signal| {
        if let waku_bindings::Event::WakuMessage(event) = signal.event() {
            let msg = event.waku_message();
            // TODO: optimize by removing clone
            sender.send(msg.clone()).unwrap();
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

        // Skip any messages whose application name is not "swarm-waku"
        if msg.content_topic().application_name != "swarm-waku" {
            continue;
        }

        match msg.content_topic().content_topic_name.to_string().as_str() {
            "ping" => {
                debug!(
                    ping = tracing::field::debug(msg.payload().clone()),
                    "Received ping"
                );
                let ping: Ping = match prost::Message::decode(msg.payload()) {
                    Ok(ping) => ping,
                    Err(e) => {
                        error!("Failed to decode ping: {}", e);
                        continue;
                    }
                };

                // craft the pong reply
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
                        let msg_id = app
                            .node_handle
                            .relay_publish_message(&waku_message, Some(pubsub_topic.clone()), None)
                            .unwrap();
                        debug!("Published pong: {:?} msg_id: {:?}", waku_message, msg_id);
                    }
                    Err(e) => {
                        error!("Failed to encode pong: {}", e);
                        continue;
                    }
                }
            }
            "retrieval-request" => {
                debug!(
                    retrieval_request = tracing::field::debug(msg.payload().clone()),
                    "Received retrieval request"
                );

                let request = match RetrievalRequest::decode(msg.payload()) {
                    Ok(request) => request,
                    Err(e) => {
                        error!("Failed to decode retrieval request: {}", e);
                        continue;
                    }
                };

                // At this point we have the chunk address which to retrieve

                // Make an asynchronous HTTP request to the remote API URI
                let api_uri = args.bee_api_url.to_owned()
                    + "/chunks/"
                    + &hex::encode(request.chunk_address.as_slice());
                debug!("Fetching data from remote API: {}", api_uri);
                let response = match fetch_from_remote_api(&api_uri).await {
                    Ok(response) => response,
                    Err(e) => {
                        error!("Failed to fetch data from remote API: {}", e);
                        // Handle the error and continue or return an error response to the user
                        continue;
                    }
                };

                // Send the API response to the user
                // craft the retrieval delivery
                let delivery = RetrievalDelivery {
                    data: response,
                    stamp: vec![],
                };
                let mut buf = Vec::new();
                match delivery.encode(&mut buf) {
                    Ok(_) => {
                        // create the WakuMessage
                        let waku_message = WakuMessage::new(
                            buf,
                            retrieval_delivery_topic.clone(),
                            1,
                            Utc::now().timestamp_millis() as usize,
                            vec![],
                            true,
                        );
                        let msg_id = app
                            .node_handle
                            .relay_publish_message(&waku_message, Some(pubsub_topic.clone()), None)
                            .unwrap();
                        debug!(
                            "Published retrieval response: {:?} msg_id: {:?}",
                            waku_message, msg_id
                        );
                    }
                    Err(e) => {
                        error!("Failed to encode retrieval response: {}", e);
                        continue;
                    }
                }
            }
            _ => {}
        }
    }
}

// Asynchronous function to perform the HTTP request using reqwest
async fn fetch_from_remote_api(api_uri: &str) -> Result<Vec<u8>, reqwest::Error> {
    let client = Client::new();
    let response = client.get(api_uri).send().await?.bytes().await?.to_vec();
    Ok(response)
}

#[derive(Debug, thiserror::Error)]
pub enum WakuHandlingError {
    #[error("Unable to create waku node: {}", .0)]
    CreateNodeError(String),
}
