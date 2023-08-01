#![allow(non_snake_case)]

use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};

const ACCESS_KEY: &str = "L2oPpm27XBz9iKqZTirSVeHXg3YrXyWM";

fn main() {
    let listener = TcpListener::bind("0.0.0.0:443").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handleConnection(stream);
            }
            _ => (),
        }
    }
}

fn handleConnection(mut stream: TcpStream) {
    let bufReader = BufReader::new(&mut stream);

    let mut firstChecked = false;

    let data: Vec<String> = bufReader
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| {
            if firstChecked {
                !line.is_empty()
            } else {
                firstChecked = true;
                line == ACCESS_KEY
            }
        })
        .collect();

    println!("Request: {:#?}", data);

    let response = "OK";

    let _ = stream.write_all(response.as_bytes());
}
