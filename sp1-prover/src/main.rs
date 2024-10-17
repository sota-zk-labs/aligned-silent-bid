#![no_main]

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use aligned_sp1_prover::{AuctionData, Bidder, BidderDecryptedData, PVK_PEM};
use rsa::pkcs8::{DecodePrivateKey};
use tiny_keccak::{Hasher, Keccak};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let auction_data = sp1_zkvm::io::read::<AuctionData>();

    let pvk = RsaPrivateKey::from_pkcs8_pem(PVK_PEM).expect("missing private key to encode bidder data");

    let mut winner_addr = &"".to_string();
    let mut winner_data = BidderDecryptedData { amount: 0, timestamp: 0 };
    for bidder in &auction_data.bidders {
        let bidder_data = decrypt_bidder_data(&pvk, bidder);
        if (winner_data.amount < bidder_data.amount) || (winner_data.amount == bidder_data.amount && winner_data.timestamp > bidder_data.timestamp) {
            winner_data = bidder_data;
            winner_addr = &bidder.address;
        }
    }

    sp1_zkvm::io::commit(&calc_auction_hash(&auction_data));
    sp1_zkvm::io::commit(winner_addr);
}

fn u128_to_byte32_ether(x: &u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let x_bytes = x.to_be_bytes();
    bytes[32 - x_bytes.len()..].copy_from_slice(&x_bytes);
    bytes
}

fn calc_auction_hash(auction_data: &AuctionData) -> [u8; 32] {
    let mut input = vec![];
    let mut hasher = Keccak::v256();

    input.extend_from_slice(&u128_to_byte32_ether(&auction_data.id));
    for bidder in &auction_data.bidders {
        let addr = hex::decode(bidder.address.trim_start_matches("0x")).expect("bidder address is not a valid hex string");
        input.extend(&addr);
        input.extend(&bidder.encrypted_data);
    }

    let mut output = [0u8; 32];
    hasher.update(&input);
    hasher.finalize(&mut output);
    output
}

fn decrypt_bidder_data(pvk: &RsaPrivateKey, bidder: &Bidder) -> BidderDecryptedData {
    let data = String::from_utf8(pvk.decrypt(Pkcs1v15Encrypt, &bidder.encrypted_data).expect("failed to decrypt")).unwrap();
    serde_json::from_str::<BidderDecryptedData>(&data).expect("failed to parse decrypted data")
}