// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! BOLT-1. Manages state of the remote peer and handles direct communications
//! with it. Relies on transport layer (BOLT-8-based) protocol.

use amplify::Bipolar;
use internet2::presentation::{Error, LightningEncode, Unmarshall};
use internet2::session::{
    self, Accept, Connect, LocalNode, PlainTranscoder, Session, Split,
    ToNodeAddr,
};
use internet2::transport::{ftcp, zmqsocket};
use internet2::LIGHTNING_P2P_DEFAULT_PORT;
use lnp::{Messages, LNPWP_UNMARSHALLER};

pub trait RecvMessage {
    fn recv_message(&mut self) -> Result<Messages, Error>;
}

pub trait SendMessage {
    fn send_message(&mut self, message: Messages) -> Result<usize, Error>;
}

pub struct PeerConnection {
    session: Box<dyn Session>,
}

pub struct PeerReceiver {
    //#[cfg(not(feature = "async"))]
    receiver: Box<dyn session::Input + Send>,
    /* #[cfg(feature = "async")]
     * receiver: Box<dyn AsyncRecvFrame>, */
}

pub struct PeerSender {
    //#[cfg(not(feature = "async"))]
    sender: Box<dyn session::Output + Send>,
    /* #[cfg(feature = "async")]
     * sender: Box<dyn AsyncSendFrame>, */
}

impl PeerConnection {
    pub fn with(session: impl Session + 'static) -> Self {
        Self {
            session: Box::new(session),
        }
    }

    pub fn connect(
        remote: impl ToNodeAddr,
        local: &LocalNode,
    ) -> Result<Self, Error> {
        let endpoint = remote
            .to_node_addr(LIGHTNING_P2P_DEFAULT_PORT)
            .ok_or(Error::InvalidEndpoint)?;
        let session = endpoint.connect(local)?;
        Ok(Self { session })
    }

    pub fn accept(
        remote: impl ToNodeAddr,
        local: &LocalNode,
    ) -> Result<Self, Error> {
        let endpoint = remote
            .to_node_addr(LIGHTNING_P2P_DEFAULT_PORT)
            .ok_or(Error::InvalidEndpoint)?;
        let session = endpoint.accept(local)?;
        Ok(Self { session })
    }
}

impl RecvMessage for PeerConnection {
    fn recv_message(&mut self) -> Result<Messages, Error> {
        debug!("Awaiting incoming messages from the remote peer");
        let payload = self.session.recv_raw_message()?;
        trace!("Incoming data from the remote peer: {:?}", payload);
        let message = &*LNPWP_UNMARSHALLER.unmarshall(&payload)?;
        debug!("Message from the remote peer: {}", message);
        Ok(message.clone())
    }
}

impl SendMessage for PeerConnection {
    fn send_message(&mut self, message: Messages) -> Result<usize, Error> {
        debug!("Sending LN message to the remote peer: {}", message);
        let data = &message.lightning_serialize();
        trace!("Lightning-encoded message representation: {:?}", data);
        Ok(self.session.send_raw_message(data)?)
    }
}

impl RecvMessage for PeerReceiver {
    fn recv_message(&mut self) -> Result<Messages, Error> {
        debug!("Awaiting incoming messages from the remote peer");
        let payload = self.receiver.recv_raw_message()?;
        trace!("Incoming data from the remote peer: {:?}", payload);
        let message = &*LNPWP_UNMARSHALLER.unmarshall(&payload)?;
        debug!("Message from the remote peer: {}", message);
        Ok(message.clone())
    }
}

impl SendMessage for PeerSender {
    fn send_message(&mut self, message: Messages) -> Result<usize, Error> {
        debug!("Sending LN message to the remote peer: {}", message);
        let data = &message.lightning_serialize();
        trace!("Lightning-encoded message representation: {:?}", data);
        Ok(self.sender.send_raw_message(data)?)
    }
}

impl Bipolar for PeerConnection {
    type Left = PeerReceiver;
    type Right = PeerSender;

    fn join(_left: Self::Left, _right: Self::Right) -> Self {
        // TODO: Implement
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        let session = self.session.into_any();
        let (input, output) = if let Some(_) = session
            .downcast_ref::<session::Raw<PlainTranscoder, ftcp::Connection>>()
        {
            let session = session
                .downcast::<session::Raw<PlainTranscoder, ftcp::Connection>>()
                .expect(
                    "Must not fail; we just ensured that with downcast_ref",
                );
            (*session).split()
        } else if let Some(_) = session
            .downcast_ref::<session::Raw<PlainTranscoder, zmqsocket::Connection>>()
        {
            let session = session
                .downcast::<session::Raw<PlainTranscoder, ftcp::Connection>>()
                .expect(
                    "Must not fail; we just ensured that with downcast_ref",
                );
            (*session).split()
        } else {
            panic!("Impossible to split this type of Session")
        };
        (
            PeerReceiver { receiver: input },
            PeerSender { sender: output },
        )
    }
}
