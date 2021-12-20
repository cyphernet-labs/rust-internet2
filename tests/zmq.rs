use internet2::{session, Session, ZmqSocketAddr, ZmqType};

#[test]
fn main() {
    let node_addr1: ZmqSocketAddr = "inproc://zmq-test-1".parse().unwrap();
    let node_addr2 = node_addr1.clone();

    let mut session = session::Raw::with_zmq_unencrypted(
        ZmqType::RouterBind,
        &node_addr1,
        None,
        Some(b"rx"),
    )
    .unwrap();

    let tx = std::thread::spawn(move || {
        let mut session = session::Raw::with_zmq_unencrypted(
            ZmqType::RouterConnect,
            &node_addr2,
            None,
            Some(b"tx"),
        )
        .unwrap();
        session
            .send_routed_message(b"tx", b"tx", b"rx", b"ignored")
            .unwrap();
        let frame = session.recv_routed_message().unwrap();
        assert_eq!(frame.msg, b"hello");
        session.set_identity(&"tx_new").unwrap();
        session
            .send_routed_message(b"tx_new", b"tx_new", b"rx", b"ignored")
            .unwrap();
        let frame = session.recv_routed_message().unwrap();
        assert_eq!(frame.msg, b"world");
    });

    session.recv_routed_message().unwrap();
    session
        .send_routed_message(b"rx", b"rx", b"tx", b"hello")
        .unwrap();
    session.recv_routed_message().unwrap();
    session
        .send_routed_message(b"rx", b"rx", b"tx", b"world")
        .unwrap();

    tx.join().unwrap();
}
