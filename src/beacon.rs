use crate::identifier::Network;
use esploda::bitcoin::address::Address;
use onlyerror::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fmt, str::FromStr};

#[derive(Debug, Error)]
pub enum Error {
    /// Invalid beacon type
    InvalidBeaconType,

    /// Invalid BIP21 address.
    InvalidBip21,

    /// Bitcoin Address Parse error
    AddressParse(#[from] esploda::bitcoin::address::Error),

    /// Identifier Parse Error
    IdentifierParse(#[from] crate::identifier::Error),
}

/// Extension trait for [`Address`]. Allows parsing from [BIP21] URI.
///
/// [BIP21]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
pub trait AddressExt {
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error>
    where
        Self: Sized;
}

impl AddressExt for Address {
    fn from_bip21(uri: &str, network: Network) -> Result<Self, Error> {
        let address = uri.strip_prefix("bitcoin:").ok_or(Error::InvalidBip21)?;
        let address = address
            .split_once('?')
            .map(|(addr, _params)| addr)
            .unwrap_or(address);

        Ok(address
            .parse::<Address<_>>()?
            .require_network(network.try_into()?)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    id: String,
    pub(crate) ty: BeaconType,
    pub(crate) descriptor: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum BeaconType {
    Singleton,
    Cas,
    SparseMerkleTree,
}

impl FromStr for BeaconType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self, Self::Err> {
        match ty {
            "SingletonBeacon" => Ok(Self::Singleton),
            "CASBeacon" => Ok(Self::Cas),
            "SMTBeacon" => Ok(Self::SparseMerkleTree),
            _ => Err(Error::InvalidBeaconType),
        }
    }
}

impl fmt::Display for BeaconType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Singleton => f.write_str("SingletonBeacon"),
            Self::Cas => f.write_str("CASBeacon"),
            Self::SparseMerkleTree => f.write_str("SMTBeacon"),
        }
    }
}

impl Beacon {
    pub(crate) fn new(id: String, ty: BeaconType, descriptor: Address) -> Self {
        Self { id, ty, descriptor }
    }

    pub(crate) fn into_json(self) -> Value {
        json!({
            "id": self.id,
            "type": self.ty.to_string(),
            "serviceEndpoint": format!("bitcoin:{}", self.descriptor),
            // "minimumConfirmationsRequired": self.min_confirmations_required,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_beacon_address_uri() {
        let address =
            Address::from_bip21("foo:mh8h6FXkMzHaW4RKerGT33ZLqx52xL28dU", Network::Regtest);

        assert!(matches!(address, Err(Error::InvalidBip21)));
    }

    #[test]
    fn cas_beacon_string_round_trip() {
        // Spec: did-btcr2/src/beacons.md Table 1 — on-wire string is "CASBeacon".
        assert_eq!("CASBeacon".parse::<BeaconType>().unwrap(), BeaconType::Cas);
        assert_eq!(BeaconType::Cas.to_string(), "CASBeacon");
    }

    #[test]
    fn old_mapbeacon_string_rejected() {
        // The old-spec on-wire string "MapBeacon" must NOT parse — wire-level rename
        assert!("MapBeacon".parse::<BeaconType>().is_err());
    }
}
