//! Structs useful for the implementation of a mix node.
use super::{poly::Polyfication, Header};

/// The different PolySphinx messages that a mix ndoe should process.
#[derive(Debug, Clone)]
pub enum Command<P: Polyfication, A, H, F> {
    /// The mix node should relay the message.
    ///
    /// See [`Relay`] for more information.
    Relay(Box<Relay<P, A, H>>),
    /// The mix node should deliver the message to the given recipient.
    ///
    /// See [`Destination`] for more information.
    Destination(Box<Destination<P, F>>),
    /// The mix node should multicast the message to multiple nodes.
    ///
    /// See [`Multicast`] for more information.
    Multicast(Multicast<P, A, H>),
}

/// A relay message.
#[derive(Debug, Clone)]
pub struct Relay<P: Polyfication, A, H> {
    /// The identifier of the next hop that the message should be sent to.
    pub next_hop: A,
    /// The prepared next header.
    pub next_header: Header,
    /// The PRE key.
    pub pre_key: P::Token,
    /// Additional data that was relayed to this hop.
    pub extra_data: H,
}

/// A message that has reached its destination.
#[derive(Debug, Clone)]
pub struct Destination<P: Polyfication, F> {
    /// The identifier for the recipient.
    pub recipient: F,
    /// The key to decrypt the message.
    pub decryption_key: P::DecryptionKey,
}

/// A message that should be multicasted.
#[derive(Debug, Clone)]
pub struct Multicast<P: Polyfication, A, H> {
    /// The inner headers and destinations.
    pub subheaders: Vec<Relay<P, A, H>>,
}
