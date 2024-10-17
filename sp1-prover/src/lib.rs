use serde::{Deserialize, Serialize};

pub const PVK_PEM: &str = include_str!("../pvk.pem");

#[derive(Deserialize, Serialize)]
pub struct AuctionData {
    pub bidders: Vec<Bidder>,
    pub id: u128,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Bidder {
    pub encrypted_data: Vec<u8>,
    pub address: String,
}

#[derive(Deserialize, Serialize)]
pub struct BidderDecryptedData {
    pub amount: u128,
    pub timestamp: u128,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use std::process::Command;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
    use rsa::rand_core::OsRng;
    use crate::{AuctionData, Bidder, BidderDecryptedData, PVK_PEM};
    use sp1_sdk::{ProverClient, SP1Stdin};

    #[test]
    fn test_sp1_prover() {
        // compile main
        let output = Command::new("cargo").args(["prove", "build"]).output().unwrap();
        println!("{:?}", String::from_utf8_lossy(output.stdout.as_slice()));
        let elf = {
            let mut buffer = Vec::new();
            File::open("./elf/riscv32im-succinct-zkvm-elf").unwrap().read_to_end(&mut buffer).unwrap();
            buffer
        };

        let pvk = RsaPrivateKey::from_pkcs8_pem(PVK_PEM).expect("missing private key to encode bidder data");
        let pbk = pvk.to_public_key();

        let mut stdin = SP1Stdin::new();
        stdin.write(&AuctionData {
            bidders: vec![Bidder {
                encrypted_data: encrypt_bidder_data(&BidderDecryptedData {
                    amount: 2,
                    timestamp: 10,
                }, &pbk),
                address: "0x0123".to_string(),
            }, Bidder {
                encrypted_data: encrypt_bidder_data(&BidderDecryptedData {
                    amount: 1,
                    timestamp: 5,
                }, &pbk),
                address: "0x0456".to_string()
            }],
            id: 0,
        });

        let client = ProverClient::new();
        let (pk, vk) = client.setup(elf.as_slice());

        let Ok(proof) = client.prove(&pk, stdin).run() else {
            println!("Something went wrong!");
            return;
        };

        println!("Proof generated successfully. Verifying proof...");
        client.verify(&proof, &vk).expect("verification failed");
        println!("Proof verified successfully.");

        println!("{:?}", proof.public_values);
        // Todo: validate with data
    }

    fn encrypt_bidder_data(data: &BidderDecryptedData, pbk: &RsaPublicKey) -> Vec<u8> {
        let data = serde_json::to_string(data).expect("failed to serialize bidder data");
        pbk.encrypt(&mut OsRng, Pkcs1v15Encrypt, data.as_bytes()).expect("failed to encrypt bidder data")
    }
}