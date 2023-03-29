#![allow(non_snake_case)]

use chacha20poly1305::{
    aead::{stream, KeyInit, OsRng},
    Key, XChaCha20Poly1305,
};
use rand::RngCore;
use std::{
    env,
    fs::{self, metadata, File},
    io::{self, Read, Write},
    thread,
};

static ENCRYPTED_EXTENSION: &str = ".ulck";

fn runFile(sourceFilePath: &str, key: &[u8; 32]) -> Result<(), io::Error> {
    if sourceFilePath == "" {
        return Ok(());
    }

    if !sourceFilePath.ends_with(ENCRYPTED_EXTENSION) {
        return Ok(());
    }

    let mut sourceFile = File::open(sourceFilePath)?;

    println!("Decrypting file: {}", sourceFilePath);
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
        runFile(&dirEntryPath, &key);
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
    let args: Vec<String> = env::args().collect();
    let entryPath = args.first().unwrap();

    let mut keyPath: String = entryPath.clone();
    keyPath.push_str(r#"\unlucke.key"#);

    let keyExists = metadata(&keyPath).is_ok();
    if !keyExists {
        panic!("Key does not exist");
    }

    let mut keyFile = File::open(&keyPath).unwrap();
    let mut keyVec = Vec::new();
    keyFile.read_to_end(&mut keyVec);

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
