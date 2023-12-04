use std::{fmt::Display, str::FromStr};

use anyhow::Context;
use iroh_net::NodeAddr;
use serde::{Deserialize, Serialize};

/// A token containing everything to get a file from the provider.
///
/// It is a single item which can be easily serialized and deserialized.
///
/// TODO: find a way to move this to iroh-net.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTicket {
    /// The address of the node.
    pub addr: NodeAddr,
}

impl NodeTicket {
    /// Serialize to postcard bytes.
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard::to_stdvec is infallible")
    }

    /// Deserialize from postcard bytes.
    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let ticket: Self = postcard::from_bytes(bytes)?;
        ticket.verify().context("invalid ticket")?;
        Ok(ticket)
    }

    /// Verify this ticket.
    fn verify(&self) -> anyhow::Result<()> {
        // do we need this? a ticket with just a node id still might be useful
        // given some sort of discovery mechanism.
        anyhow::ensure!(!self.addr.info.is_empty(), "no node info");
        Ok(())
    }

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = "node".to_string();
        data_encoding::BASE32_NOPAD.encode_append(&self.to_bytes(), &mut out);
        out.make_ascii_lowercase();
        out
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> anyhow::Result<Self> {
        let Some(base32) = str.strip_prefix("node") else {
            anyhow::bail!("invalid prefix");
        };
        let bytes = data_encoding::BASE32_NOPAD
            .decode(base32.to_ascii_uppercase().as_bytes())
            .context("invalid base32")?;
        Self::from_bytes(&bytes)
    }
}

impl Display for NodeTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

impl FromStr for NodeTicket {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::deserialize(s)
    }
}
