// Imports
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use std::fs::File;
use std::io::{Read, Write};

// File Chunk size 
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

// Magic bytes for file format Identification
const MAGIC: &[u8; 8] = b"RUSTENC1";

// 64 hex Key hardcoded for testing and debugging, not usable in production
const HEX_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";


// CLI definition
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Encrypt and Decrypt with 32-byte hex key
    Encrypt {
        input: String,
        output: String,
        //key: String, // 64 hex == 32 byte
    },
    Decrypt {
        input: String,
        output: String,
        //key: String,
    },
}

// Main fn uses AES_GCM in chunked mode, usable with large files
fn main() -> Result<()> {
    // Parse the hex key to bytes
    let key_bytes = parse_key(HEX_KEY)?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {
            encrypt_file(&input, &output, &key_bytes)?;
        }
        Commands::Decrypt { input, output } => {
            decrypt_file(&input, &output, &key_bytes)?;
        }
    }

    Ok(())
}

/// Parse a 64-character hex string into 32-byte key
fn parse_key(hex: &str) -> Result<[u8; 32]> {
    // See if it is 64-hex
    if hex.len() != 64 {
        return Err(anyhow!("Key must be 64 hex characters (32 bytes)"));
    }

    // Transforms it to 32-byte
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16)?;
    }
    Ok(key)
}

// Encryption function
fn encrypt_file(input: &str, output: &str, key: &[u8; 32]) -> Result<()> {
    // Initialize AES-256-GCM cipher with the provided key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create cipher: {:?}", e))?; // map_err converts aes_gcm::Error into anyhow::Error for `?` operator

    // File operations
    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;

    // Generate a random 12-byte base nonce (GCM requires 96-bit nonce)
    let mut base_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut base_nonce);

    // Write file header: |MAGIC|NONCE|
    outfile.write_all(MAGIC)?;
    outfile.write_all(&base_nonce)?;

    // Buffer for reading input in chunks (1 MB each)
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut counter: u32 = 0; // counter used to create unique nonce per chunk

    loop {
        // Read a chunk from the input file
        let bytes_read = infile.read(&mut buffer)?;
        if bytes_read == 0 { break; } // EOF reached

        // Prepare per-chunk nonce
        let mut nonce_bytes = base_nonce;
        nonce_bytes[8..12].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes); // 12-byte nonce for AES-GCM

        // Encrypt the chunk and Returns ciphertext + authentication tag
        let ciphertext = cipher.encrypt(nonce, &buffer[..bytes_read])
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        // Write length of encrypted chunk as u32 (needed for proper decryption)
        outfile.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        // Write encrypted chunk bytes
        outfile.write_all(&ciphertext)?;

        counter += 1; // increment counter for next chunk
    }

    println!("Encryption successful.");
    Ok(())
}

// Decryption function
fn decrypt_file(input: &str, output: &str, key: &[u8; 32]) -> Result<()> {
    // Initialize AES-256-GCM cipher with the same key used in encryption, in this case the hardcoded key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create cipher: {:?}", e))?;

    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;

    // Read and validate the magic header
    let mut magic = [0u8; 8];
    infile.read_exact(&mut magic)?;
    if &magic != MAGIC { return Err(anyhow!("Invalid file format")); }

    // Read the base nonce from the header
    let mut base_nonce = [0u8; 12];
    infile.read_exact(&mut base_nonce)?;

    let mut counter: u32 = 0; // counter used to reconstruct per-chunk nonce

    loop {
        // Read the length of the next encrypted chunk (u32)
        let mut len_buf = [0u8; 4];
        match infile.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => break, // EOF reached
        }

        let chunk_len = u32::from_be_bytes(len_buf) as usize;

        // Read the encrypted chunk bytes
        let mut ciphertext = vec![0u8; chunk_len];
        infile.read_exact(&mut ciphertext)?;

        // Reconstruct per-chunk nonce
        let mut nonce_bytes = base_nonce;
        nonce_bytes[8..12].copy_from_slice(&counter.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt the chunk
        let plaintext = cipher.decrypt(nonce, &*ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {:?}", e))?;

        // Write the decrypted bytes to the output file
        outfile.write_all(&plaintext)?;

        counter += 1;
    }

    println!("Decryption successful.");
    Ok(())
}