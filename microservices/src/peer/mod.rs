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

mod peer_connection;
use crate::node::TryService;
use internet2::presentation::{Error, TypedEnum, Unmarshall, Unmarshaller};
pub use peer_connection::{
    PeerConnection, PeerReceiver, PeerSender, RecvMessage, SendMessage,
};
use std::fmt::{Debug, Display};

/// Trait for types handling specific LNPWP messages.
pub trait Handler<T: TypedEnum> {
    type Error: crate::error::Error + From<Error>;

    /// Function that processes specific peer message
    fn handle(
        &mut self,
        message: <Unmarshaller<T> as Unmarshall>::Data,
    ) -> Result<(), Self::Error>;

    fn handle_err(&mut self, error: Self::Error) -> Result<(), Self::Error>;
}

pub struct Listener<H, T>
where
    T: TypedEnum,
    H: Handler<T>,
    Unmarshaller<T>: Unmarshall,
    <Unmarshaller<T> as Unmarshall>::Data: Display + Debug,
    <Unmarshaller<T> as Unmarshall>::Error: Into<Error>,
{
    receiver: PeerReceiver,
    handler: H,
    unmarshaller: Unmarshaller<T>,
}

impl<H, T> Listener<H, T>
where
    T: TypedEnum,
    H: Handler<T>,
    Unmarshaller<T>: Unmarshall,
    <Unmarshaller<T> as Unmarshall>::Data: Display + Debug,
    <Unmarshaller<T> as Unmarshall>::Error: Into<Error>,
{
    pub fn with(
        receiver: PeerReceiver,
        handler: H,
        unmarshaller: Unmarshaller<T>,
    ) -> Self {
        Self {
            receiver,
            handler,
            unmarshaller,
        }
    }
}

impl<H, T> TryService for Listener<H, T>
where
    T: TypedEnum,
    H: Handler<T>,
    Unmarshaller<T>: Unmarshall,
    <Unmarshaller<T> as Unmarshall>::Data: Display + Debug,
    <Unmarshaller<T> as Unmarshall>::Error: Into<Error>,
{
    type ErrorType = H::Error;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        trace!("Entering event loop of the sender service");
        loop {
            match self.run() {
                Ok(_) => trace!("Peer message processing complete"),
                Err(err) => {
                    trace!("Peer connection generated {}", err);
                    self.handler.handle_err(err)?;
                }
            }
        }
    }
}

impl<H, T> Listener<H, T>
where
    T: TypedEnum,
    H: Handler<T>,
    Unmarshaller<T>: Unmarshall,
    <Unmarshaller<T> as Unmarshall>::Data: Display + Debug,
    <Unmarshaller<T> as Unmarshall>::Error: Into<Error>,
{
    fn run(&mut self) -> Result<(), H::Error> {
        trace!("Awaiting for peer messages...");
        let msg = self.receiver.recv_message(&self.unmarshaller)?;
        debug!("Processing message {}", msg);
        trace!("Message details: {:?}", msg);
        self.handler.handle(msg)
    }
}
