//! Libp2p Swarm, Gossipsub, and Peer Discovery for PSob Indexer.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use libp2p::{
    futures::StreamExt,
    gossipsub, identify, mdns, noise, ping,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, Swarm,
};
use tokio::sync::{mpsc, RwLock};

use super::{P2pConfig, P2pHandle, P2pStatus, SwapIntentMessage};

pub const TOPIC_HEADERS: &str = "/psob/headers/v1";
pub const TOPIC_SIBLINGS: &str = "/psob/siblings/v1";
pub const TOPIC_INTENTS: &str = "/psob/intents/v1";

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

pub async fn start_p2p_swarm(config: P2pConfig) -> anyhow::Result<(P2pHandle, impl std::future::Future<Output = ()>)> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|msg| Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg)) as Box<dyn std::error::Error + Send + Sync>)?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + Send + Sync>)?;

            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            let identify = identify::Behaviour::new(identify::Config::new(
                "/psob/1.0.0".to_string(),
                key.public(),
            ));

            let ping = ping::Behaviour::new(ping::Config::default());

            Ok(AppBehaviour {
                gossipsub,
                mdns,
                identify,
                ping,
            })
        })
        .map_err(|e| anyhow::anyhow!("swarm builder error: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Subscribe to gossip topics
    let topic_headers = gossipsub::IdentTopic::new(TOPIC_HEADERS);
    let topic_siblings = gossipsub::IdentTopic::new(TOPIC_SIBLINGS);
    let topic_intents = gossipsub::IdentTopic::new(TOPIC_INTENTS);

    swarm.behaviour_mut().gossipsub.subscribe(&topic_headers)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic_siblings)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic_intents)?;

    let listen_addr: Multiaddr = format!("/ip4/{}/tcp/{}", config.p2p_bind_addr, config.p2p_port)
        .parse()
        .context("parse multiaddr")?;
    swarm.listen_on(listen_addr)?;

    // Connect to initial bootstrap nodes if configured
    for boot in &config.bootstrap_nodes {
        if let Ok(addr) = boot.parse::<Multiaddr>() {
            let _ = swarm.dial(addr);
        }
    }

    let local_peer_id = *swarm.local_peer_id();
    tracing::info!(peer_id = %local_peer_id, port = config.p2p_port, "initialized libp2p swarm");

    let status = Arc::new(RwLock::new(P2pStatus {
        peer_id: local_peer_id.to_string(),
        listen_addrs: Vec::new(),
        connected_peers_count: 0,
        connected_peers: Vec::new(),
        subscribed_topics: vec![
            TOPIC_HEADERS.to_string(),
            TOPIC_SIBLINGS.to_string(),
            TOPIC_INTENTS.to_string(),
        ],
    }));

    let (tx_intent, rx_intent) = mpsc::channel::<SwapIntentMessage>(100);

    let handle = P2pHandle {
        tx_intent,
        status: Arc::clone(&status),
    };

    let swarm_task = async move {
        run_swarm_loop(swarm, status, rx_intent, topic_intents).await;
    };

    Ok((handle, swarm_task))
}

async fn run_swarm_loop(
    mut swarm: Swarm<AppBehaviour>,
    status: Arc<RwLock<P2pStatus>>,
    mut rx_intent: mpsc::Receiver<SwapIntentMessage>,
    topic_intents: gossipsub::IdentTopic,
) {
    loop {
        tokio::select! {
            // Handle outbound intent message to gossip
            Some(intent) = rx_intent.recv() => {
                if let Ok(payload) = serde_json::to_vec(&intent) {
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic_intents.clone(), payload) {
                        tracing::warn!("failed to gossip swap intent: {e}");
                    } else {
                        tracing::info!(intent_id = %intent.intent_id, "gossiped swap intent to p2p swarm");
                    }
                }
            }
            // Handle inbound swarm events
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(addr = %address, "P2P node listening on address");
                        let mut st = status.write().await;
                        let s = address.to_string();
                        if !st.listen_addrs.contains(&s) {
                            st.listen_addrs.push(s);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            tracing::info!(peer = %peer_id, addr = %multiaddr, "mDNS discovered local peer");
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _) in list {
                            tracing::debug!(peer = %peer_id, "mDNS peer expired");
                        }
                    }
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id: id,
                        message,
                    })) => {
                        let topic = message.topic.as_str();
                        tracing::info!(peer = %peer_id, topic = %topic, msg_id = %id, "received gossipsub message");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let mut st = status.write().await;
                        let p = peer_id.to_string();
                        if !st.connected_peers.contains(&p) {
                            st.connected_peers.push(p);
                            st.connected_peers_count = st.connected_peers.len();
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        let mut st = status.write().await;
                        let p = peer_id.to_string();
                        st.connected_peers.retain(|x| x != &p);
                        st.connected_peers_count = st.connected_peers.len();
                    }
                    _ => {}
                }
            }
        }
    }
}
