//! Structs for handling device.

use age_core::{
    format::{FileKey, FILE_KEY_BYTES},
    primitives::{aead_decrypt, hkdf},
};
use age_plugin::{identity, Callbacks};
use bech32::{ToBase32, Variant};
use std::fmt;
use std::io;

use crate::{
    error::Error,
    format::{RecipientLine, STANZA_KEY_LABEL},
    hid::LedgerHIDDevice,
    k256::{Recipient, TAG_BYTES},
    IDENTITY_PREFIX,
};

const CONFIRM_RECIPIENT_CMD: &[u8; 4] = b"\xE0\x01\x00\x00";
const GET_RECIPIENT_CMD: &[u8; 4] = b"\xE0\x02\x00\x00";
const GET_SHARED_KEY_CMD: &[u8; 4] = b"\xE0\x03\x00\x00";

/// Confirm that the Ledger device is the one associated with the identity
pub(crate) fn confirm_device_recipient(
    device: &LedgerHIDDevice,
    tag: [u8; TAG_BYTES],
) -> Result<crate::k256::Recipient, Error> {
    let mut cmd = CONFIRM_RECIPIENT_CMD.to_vec();
    cmd.extend_from_slice(&[tag.len() as u8]);
    cmd.extend_from_slice(&tag);

    let device_response = device.exchange(&cmd)?;

    if device_response.len() != 67 || &device_response[65..] != b"\x90\x00" {
        return Err(Error::MalformattedMsg);
    }
    crate::k256::Recipient::from_bytes(&device_response[..65]).ok_or(Error::MalformattedMsg)
}

/// Retrieve recipient from Ledger device
pub(crate) fn get_device_recipient(
    device: &LedgerHIDDevice,
) -> Result<crate::k256::Recipient, Error> {
    eprint!("Waiting for Ledger Nano...");
    let device_response = device.exchange(GET_RECIPIENT_CMD)?;
    eprint!("\r                          \r");
    if device_response.len() != 67 || &device_response[65..] != b"\x90\x00" {
        return Err(Error::MalformattedMsg);
    }
    crate::k256::Recipient::from_bytes(&device_response[..65]).ok_or(Error::MalformattedMsg)
}

/// Retrieve shared key from Ledger device
pub(crate) fn get_device_shared_key(
    device: &LedgerHIDDevice,
    ephemeral_key: &[u8],
) -> Result<[u8; 32], Error> {
    assert!(ephemeral_key.len() == 65);
    let mut cmd = GET_SHARED_KEY_CMD.to_vec();
    cmd.extend_from_slice(&[ephemeral_key.len() as u8]);
    cmd.extend_from_slice(ephemeral_key);
    let device_response = device.exchange(&cmd)?;

    if device_response.len() != 34 || &device_response[32..] != b"\x90\x00" {
        return Err(Error::MalformattedMsg);
    }
    Ok(device_response[..32].try_into().unwrap())
}

/// A reference to an age key stored on device.
#[derive(Debug)]
pub struct Stub {
    pub(crate) tag: [u8; TAG_BYTES],
    pub(crate) identity_index: usize,
}

impl fmt::Display for Stub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32::encode(
                IDENTITY_PREFIX,
                self.to_bytes().to_base32(),
                Variant::Bech32,
            )
            .expect("HRP is valid")
            .to_uppercase()
            .as_str(),
        )
    }
}

impl PartialEq for Stub {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub(crate) fn new(recipient: &Recipient) -> Self {
        Stub {
            tag: recipient.tag(),
            identity_index: 0,
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8], identity_index: usize) -> Option<Self> {
        if bytes.len() < TAG_BYTES {
            return None;
        }
        Some(Stub {
            tag: bytes[..TAG_BYTES].try_into().unwrap(),
            identity_index,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TAG_BYTES);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    pub(crate) fn matches(&self, line: &RecipientLine) -> bool {
        self.tag == line.tag
    }

    /// Returns:
    /// - `Ok(Ok(Some(connection)))` if we successfully connected to this device.
    /// - `Ok(Ok(None))` if the user told us to skip this device.
    /// - `Ok(Err(_))` if we encountered an error while trying to connect to the device.
    /// - `Err(_)` on communication errors with the age client.
    pub(crate) fn connect<E>(
        &self,
        _callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<Option<Connection>, identity::Error>> {
        let device = LedgerHIDDevice::new();

        // Read the pubkey from the device and check it still matches.
        let pk =
            match confirm_device_recipient(&device, self.tag) {
                Ok(pk) => pk,
                Err(_) => return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message:
                        "Could not get public key from device or the stub did not match the device"
                            .to_string(),
                })),
            };

        Ok(Ok(Some(Connection {
            device,
            pk,
            tag: self.tag,
        })))
    }
}

pub(crate) struct Connection {
    device: LedgerHIDDevice,
    pk: Recipient,
    tag: [u8; TAG_BYTES],
}

impl Connection {
    pub(crate) fn recipient(&self) -> &Recipient {
        &self.pk
    }

    pub(crate) fn unwrap_file_key(&mut self, line: &RecipientLine) -> Result<FileKey, ()> {
        assert_eq!(self.tag, line.tag);

        // The Nano app for performing scalar multiplication takes the point in its
        // uncompressed SEC-1 encoding.
        let shared_secret =
            get_device_shared_key(&self.device, line.epk_bytes.decompress().as_bytes())
                .map_err(|_| ())?;

        let mut salt = vec![];
        salt.extend_from_slice(line.epk_bytes.as_bytes());
        salt.extend_from_slice(self.pk.to_encoded(true).as_bytes());

        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, &shared_secret);

        // A failure to decrypt is fatal, because we assume that we won't
        // encounter 32-bit collisions on the key tag embedded in the header.
        match aead_decrypt(&enc_key, FILE_KEY_BYTES, &line.encrypted_file_key) {
            Ok(pt) => Ok(TryInto::<[u8; FILE_KEY_BYTES]>::try_into(&pt[..])
                .unwrap()
                .into()),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Stub;

    #[test]
    fn stub_round_trip() {
        let stub = Stub {
            tag: [7; TAG_BYTES],
            identity_index: 0,
        };

        let encoded = stub.to_bytes();
        assert_eq!(Stub::from_bytes(&[], 0), None);
        assert_eq!(Stub::from_bytes(&encoded, 0), Some(stub));
        assert_eq!(Stub::from_bytes(&encoded[..encoded.len() - 1], 0), None);
    }
}
