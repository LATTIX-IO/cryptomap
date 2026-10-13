// Fixture: exact qualified Rust calls are syntax evidence only.
// Calls in comments, strings and macro token trees are NOT AST call expressions.
fn demo(input: &[u8]) {
    let _ = sha2::Sha256::digest(input);
    let _ = sha2::Sha512::digest(input);
    let _ = ring::digest::digest(&ring::digest::SHA256, input);
    let _ = rustls::ClientConfig::builder();
    let _ = "sha2::Sha256::digest(input); -----BEGIN PRIVATE KEY-----";
    let _ = Sha256::digest(input);
    // sha2::Sha512::digest(input);
    let _ = sha2::Sha256::digest!(input);
    macro_rules! ghost { () => { sha2::Sha256::digest(input) } }
}
