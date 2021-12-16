use internet2::{Accept, Connect, LocalNode, RemoteNodeAddr};
use secp256k1::Secp256k1;

#[test]
fn main() {
    let secp = Secp256k1::new();
    let node_rx = LocalNode::new(&secp);
    let node_tx = LocalNode::new(&secp);
    let node_addr = "lnp://127.0.0.1:59876".parse().unwrap();
    let node_a = RemoteNodeAddr {
        node_id: node_rx.node_id(),
        remote_addr: node_addr,
    };
    let node_b = node_a.clone();

    let rx = std::thread::spawn(move || receiver(&node_rx, node_a));
    let tx = std::thread::spawn(move || sender(&node_tx, node_b));

    tx.join().unwrap();
    rx.join().unwrap();
}

fn receiver(local_node: &LocalNode, node: RemoteNodeAddr) {
    let mut session = node.accept(local_node).unwrap();
    let msg = session.recv_raw_message().unwrap();
    assert_eq!(msg, b"Hello world");
    //std::thread::sleep(core::time::Duration::from_secs(3));
}

fn sender(local_node: &LocalNode, node: RemoteNodeAddr) {
    //std::thread::sleep(core::time::Duration::from_secs(1));
    let mut session = node.connect(local_node).unwrap();
    session.send_raw_message(b"Hello world").unwrap();
}
