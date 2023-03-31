#![allow(non_snake_case)]

use chacha20poly1305::{
    aead::{stream, KeyInit},
    XChaCha20Poly1305,
};
use std::{
    env,
    fs::{self, metadata, File},
    io::{self, Read, Write},
};

static ENCRYPTED_EXTENSION: &str = ".ulck";
static ENCRYPTED_EXTENSION_LENGTH: usize = ENCRYPTED_EXTENSION.len();

fn runFile(encryptedFilePath: &str, key: &[u8; 32]) -> Result<(), io::Error> {
    if encryptedFilePath == "" {
        return Ok(());
    }

    if !encryptedFilePath.ends_with(ENCRYPTED_EXTENSION) {
        return Ok(());
    }

    let mut encryptedFile = File::open(encryptedFilePath)?;

    println!("Decrypting file: {}", encryptedFilePath);

    let mut nonce = [0u8; 19];
    match encryptedFile.read_exact(&mut nonce) {
        Ok(_) => (),
        Err(_) => return Ok(()),
    };

    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut destinationFilePath = encryptedFilePath.to_string();
    destinationFilePath.truncate(destinationFilePath.len() - ENCRYPTED_EXTENSION_LENGTH);

    let mut destinationFile = File::create(destinationFilePath)?;

    loop {
        let read_count = encryptedFile.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor.decrypt_next(buffer.as_slice());

            match plaintext {
                Ok(plaintext) => {
                    destinationFile.write(&plaintext)?;
                }
                Err(_) => break,
            }
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor.decrypt_last(&buffer[..read_count]);

            match plaintext {
                Ok(plaintext) => {
                    destinationFile.write(&plaintext)?;
                }
                Err(_) => break,
            }

            break;
        }
    }

    println!("Decrypted file: {}", encryptedFilePath);

    Ok(())
}

fn runDirEntry(dirEntryPath: &str, key: &[u8; 32]) {
    let metadata = match metadata(dirEntryPath) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };

    if metadata.is_dir() {
        let dirEntries = match fs::read_dir(dirEntryPath) {
            Ok(paths) => paths,
            Err(_) => return,
        };

        for dirEntry in dirEntries {
            match dirEntry {
                Ok(dirEntry) => match dirEntry.path().to_str() {
                    Some(path) => runDirEntry(&path, &key),
                    None => (),
                },
                Err(_) => (),
            }
        }
    } else {
        match runFile(&dirEntryPath, &key) {
            Ok(_) => (),
            Err(err) => println!("Could not decrypt file: {} File: {}", err, dirEntryPath),
        };
    }
}

fn vecToArray32<T>(v: Vec<T>) -> [T; 32]
where
    T: Copy,
{
    let slice = v.as_slice();
    let array: [T; 32] = match slice.try_into() {
        Ok(ba) => ba,
        Err(_) => panic!("Expected a Vec of length {} but it was {}", 32, v.len()),
    };
    array
}

fn main() {
    let entryPath = env::current_dir().unwrap().to_str().unwrap().to_string();

    let mut keyPath: String = entryPath.clone();
    keyPath.push_str(r#"\unlucke.key"#);

    let keyExists = metadata(&keyPath).is_ok();
    if !keyExists {
        panic!("Key does not exist");
    }

    let mut keyFile = File::open(&keyPath).unwrap();
    let mut keyVec = Vec::new();
    keyFile.read_to_end(&mut keyVec).unwrap();

    let key: [u8; 32] = vecToArray32(keyVec);

    let dirEntries = fs::read_dir(&entryPath).unwrap();
    for dirEntry in dirEntries {
        match dirEntry {
            Ok(dirEntry) => match dirEntry.path().to_str() {
                Some(path) => runDirEntry(&path, &key),
                None => (),
            },
            Err(_) => (),
        }
    }
}
