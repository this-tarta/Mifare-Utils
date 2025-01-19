//! A library for abstracting MIFARE Classic card reading using the `pcsc` crate.
//! Tested on ACR1552U Reader and MIFARE Classic 1K cards
//! ADPU commands follow documentation at: https://www.acs.com.hk/download-manual/13473/REF-ACR1552U-Series-1.05.pdf

use std::ffi::CString;
use pcsc::{Context, Protocols, Scope, Card, Error as PcscError};

/// Represents an error that can occur while interacting with the MIFARE card.
#[derive(Debug)]
pub enum MifareError {
    PcscError(PcscError),
    CardNotPresent,
    AuthenticationFailed,
    ReadError,
    WriteError,
}

impl From<PcscError> for MifareError {
    fn from(err: PcscError) -> Self {
        MifareError::PcscError(err)
    }
}

/// A struct representing a connection to a MIFARE card reader.
pub struct MifareReader {
    context: Context,
}

impl MifareReader {
    /// Creates a new `MifareReader` by initializing the PC/SC context.
    pub fn new() -> Result<Self, MifareError> {
        let context = Context::establish(Scope::User)?;
        Ok(Self { context })
    }

    /// Lists the available readers.
    pub fn list_readers(&self) -> Result<Vec<String>, MifareError> {
        let mut reader_names = vec![0u8; self.context.list_readers_len()?];
        let readers = self.context.list_readers(&mut reader_names)?;
        Ok(readers.map(|s| String::from_utf8_lossy(s.to_bytes()).to_string()).collect())
    }

    /// Connects to a card in the specified reader.
    pub fn connect(&self, reader_name: &str) -> Result<MifareCard, MifareError> {
        let card = self.context.connect(&CString::new(reader_name).expect("CStrin::new"),
                                                pcsc::ShareMode::Shared,
                                                Protocols::all())?;
        Ok(MifareCard { card })
    }
}

/// A struct representing a MIFARE card.
pub struct MifareCard {
    card: Card,
}

#[repr(u8)]
pub enum KeyType {
    KeyA = 0x60,
    KeyB = 0x61
}

impl MifareCard {
    /// Sends an APDU command to the card and retrieves the response.
    pub fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, MifareError> {
        let mut response = [0; 256];
        let response_slice = self.card.transmit(apdu, &mut response)?;
        Ok(response_slice.to_vec())
    }

    pub fn load_key(&self, key: &[u8; 6]) -> Result<(), String> {
        if key.len() != 6 {
            return Err("Key must be exactly 6 bytes.".to_string());
        }

        // Construct the APDU
        let apdu = [
            0xFF,             // CLA
            0x82,             // INS
            0x00,             // P1
            0x00,             // P2: Key Slot (0x00)
            0x06,             // Lc: Length of Key Data
            key[0], key[1], key[2], key[3], key[4], key[5], // Key Data
        ];

        let mut response = [0; 256];
        let response_slice = self
            .card
            .transmit(&apdu, &mut response)
            .map_err(|e| e.to_string())?;

        if response_slice == [0x90, 0x00] {
            Ok(())
        } else {
            Err(format!("Failed to load key: {:?}", response_slice))
        }
    }

    /// Authenticates with a specific block using a buffered key (slot 0)
    pub fn authenticate(&self, block: u8, key_type: KeyType) -> Result<(), MifareError> {
        let apdu = [
            0xFF, 0x86, 0x00, 0x00, 0x05, // APDU header
            0x01, 0x00, block, key_type as u8, 0x00 // block, key type, key buffer number
        ];
        let response = self.send_apdu(&apdu)?;
        if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(MifareError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Allows one to authenticate with a key
    pub fn authenticate_with_key(&self, block: u8, key: &[u8; 6], key_type: KeyType) -> Result<(), MifareError> {
        match self.load_key(key) {
            Ok(_) => (),
            _ => return Err(MifareError::AuthenticationFailed)
        };

        self.authenticate(block, key_type)
    }

    /// Reads data from a specific block.
    pub fn read_block(&self, block: u8) -> Result<Vec<u8>, MifareError> {
        let apdu = [0xFF, 0xB0, 0x08, block, 0x10];
        let response = self.send_apdu(&apdu)?;
        if response.len() < 18 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(MifareError::ReadError);
        }
        Ok(response[..16].to_vec())
    }

    /// Reads data from a sector (including sector trailer)
    pub fn read_sector(&self, sector: u8) -> Result<Vec<u8>, MifareError> {
        let block = sector * 0x10;
        let apdu = [0xFF, 0xB0, 0x08, block, 0x40];
        let response = self.send_apdu(&apdu)?;
        if response.len() < 0x42 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(MifareError::ReadError);
        }
        Ok(response[..0x40].to_vec())
    }

    /// Writes data to a specific block.
    pub fn write_block(&self, block: u8, data: &[u8; 16]) -> Result<(), MifareError> {
        let mut apdu = vec![0xFF, 0xD6, 0x08, block, 0x10];
        apdu.extend_from_slice(data);
        let response = self.send_apdu(&apdu)?;
        if response.len() < 2 || response[response.len() - 2..] != [0x90, 0x00] {
            return Err(MifareError::WriteError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_initialization() {
        let reader = MifareReader::new();
        assert!(reader.is_ok());
    }

    #[test]
    fn test_finds_card_reader() {
        let reader = MifareReader::new();
        assert!(reader.is_ok());
        let readers = reader.expect("no readers").list_readers();
        assert!(readers.is_ok());

        println!("{}", readers.expect("")[0]);
    }

    #[test]
    fn test_read_write_card() {
        let reader = MifareReader::new().expect("can't init readers");
        let readers = reader.list_readers().expect("no readers to list");

        let card = reader.connect(&readers[0]).expect("couldn't connect to card");
        card.load_key(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).expect("couldn't load key");
        card.authenticate(1, KeyType::KeyA).expect("couldn't authenticate");
        let to_write = b"ChristianTarta04";
        card.write_block(1, &to_write).expect("couldn't write block");
        let block = card.read_block(1).expect("couldn't read block");
        assert_eq!(&to_write.to_vec(), &block);
    }
}
