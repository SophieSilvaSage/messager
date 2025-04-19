use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{LineEnding, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rand::rngs::OsRng;
use bincode::{Encode, Decode, encode_to_vec, decode_from_slice, config};
use std::fs::File;
use std::io::{Read, Write};

#[derive(Encode, Decode, Debug)]
struct UserData {
    username: String,
    password: String,
    key_length: u32,
    public_key: String,
    private_key: String,
    old_public_key: String,
    old_private_key: String,
}

const USER_BIN_PATH: &str = "user.bin";

fn load_or_create_user() -> UserData {
    let config = config::standard();
    if let Ok(mut file) = File::open(USER_BIN_PATH) {
        let mut data = Vec::new();
        let _ = file.read_to_end(&mut data);
        let (user, _) = decode_from_slice(&data, config).unwrap();
        user
    } else {
        println!("Enter new username:");
        let mut username = String::new();
        std::io::stdin().read_line(&mut username).unwrap();

        println!("Enter new password:");
        let mut password = String::new();
        std::io::stdin().read_line(&mut password).unwrap();

        println!("Enter prefferred key length 2048, 3072 or 4096 reccomended:");
        let mut key_length = String::new();
        std::io::stdin().read_line(&mut key_length).unwrap();
        let key_length: u32 = key_length.trim().parse().unwrap();

        let user = UserData {
            username: username.trim().to_string(),
            password: password.trim().to_string(),
            key_length: key_length,
            public_key: "".to_string(),
            private_key: "".to_string(),
            old_public_key: "".to_string(),
            old_private_key: "".to_string(),
        };
            let data = encode_to_vec(&user, config).unwrap();
            let mut file = File::create(USER_BIN_PATH).unwrap();
            file.write_all(&data).unwrap();
            user
    }
}

fn reload_keys(mut user: UserData) -> UserData {
    let config = config::standard();

    let private_key = RsaPrivateKey::new(&mut OsRng, user.key_length.try_into().unwrap()).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_key = String::from(private_key.to_pkcs1_pem(LineEnding::LF).unwrap().as_str());
    let public_key = String::from(public_key.to_pkcs1_pem(LineEnding::LF).unwrap().as_str());

    user = UserData {
        username: user.username,
        password: user.password,
        key_length: user.key_length,
        public_key: public_key,
        private_key: private_key,
        old_public_key: user.public_key,
        old_private_key: user.private_key,
    };
    let data = encode_to_vec(&user, config).unwrap();
    let mut file = File::create(USER_BIN_PATH).unwrap();
    file.write_all(&data).unwrap();
    user
}
fn main() {
    let user = load_or_create_user();
    println!("User data is {user:#?}");
    let user = reload_keys(user);
    println!("New User data is {user:#?}");
}