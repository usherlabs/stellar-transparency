pub mod verifier;

// #[ic_cdk::query]
// fn verify_proof(proof: String, pub_key: String) -> Result<String, String> {
//     // let proof = verifier::verify_proof(proof, pub_key);

//     Ok("proof".to_owned())
// }

#[ic_cdk::query]
fn ping() -> String {
    "pong".to_owned()
}
