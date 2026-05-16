use md5;
use sha1::{Digest, Sha1};
use des::Des;
use des::TdesEde3;
use rc4::Rc4;
use rsa::RsaPrivateKey;
use secp256k1;
use rand::rngs::OsRng;

fn bad_md5(data: &[u8]) -> [u8; 16] {
    md5::compute(data).into()
}

fn bad_sha1(data: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

fn bad_des_use() {
    let _ = Des::new(&[0u8; 8].into());
}

fn bad_3des_use() {
    let _ = TdesEde3::new(&[0u8; 24].into());
}

fn weak_rsa() {
    let mut rng = OsRng;
    let _ = RsaPrivateKey::new(&mut rng, 1024);
}
