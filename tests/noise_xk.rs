use std::convert::TryFrom;
use std::net::{SocketAddr, TcpListener};
use std::str::FromStr;

use inet2_addr::{LocalNode, NodeAddr};
use internet2::session::noise::TransportProtocol;
use internet2::session::Session;
use internet2::{NoiseTranscoder, SendRecvMessage};
use secp256k1::Secp256k1;

#[test]
fn main() {
    let secp = Secp256k1::new();
    let node_rx = LocalNode::new(&secp);
    let node_tx = LocalNode::new(&secp);
    let node =
        NodeAddr::from_str(&format!("{}@127.0.0.1:59876", node_tx.node_id()))
            .unwrap();

    let rx = std::thread::spawn(move || receiver(&node_rx, node));
    let tx = std::thread::spawn(move || sender(&node_tx, node));

    tx.join().unwrap();
    rx.join().unwrap();
}

fn receiver(local_node: &LocalNode, node: NodeAddr) {
    std::thread::sleep(core::time::Duration::from_secs(1));
    let mut session = Session::<
        NoiseTranscoder<{ TransportProtocol::Brontide.message_len_size() }>,
        _,
    >::connect_brontide(
        local_node.private_key(),
        node.id.public_key(),
        node.addr,
    )
    .unwrap();
    let msg = session.recv_raw_message().unwrap();
    assert_eq!(msg, b"Hello world");
    std::thread::sleep(core::time::Duration::from_secs(5));
}

fn sender(local_node: &LocalNode, node: NodeAddr) {
    let listener =
        TcpListener::bind(SocketAddr::try_from(node.addr).unwrap()).unwrap();
    let mut session =
        Session::<
            NoiseTranscoder<{ TransportProtocol::Brontide.message_len_size() }>,
            _,
        >::accept_brontide(local_node.private_key(), &listener)
        .unwrap();
    session.send_raw_message(b"Hello world").unwrap();
    std::thread::sleep(core::time::Duration::from_secs(3));
}
