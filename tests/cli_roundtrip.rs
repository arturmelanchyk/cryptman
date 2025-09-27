use assert_cmd::Command;
use assert_fs::TempDir;
use assert_fs::prelude::*;

#[test]
fn encrypt_then_decrypt_hello_world() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let input = temp_dir.child("hello.txt");
    input.write_str("Hello World!")?;

    let encrypted = temp_dir.child("hello.enc");
    let decrypted = temp_dir.child("hello.out");
    let password = "s3cret-password";

    let mut enc_cmd = Command::cargo_bin("cryptman")?;
    enc_cmd
        .env("CRYPTMAN_TEST_PASSWORD", password)
        .arg("enc")
        .arg(input.path())
        .arg(encrypted.path())
        .arg("--passin")
        .arg("env:CRYPTMAN_TEST_PASSWORD")
        .assert()
        .success();

    let mut dec_cmd = Command::cargo_bin("cryptman")?;
    dec_cmd
        .env("CRYPTMAN_TEST_PASSWORD", password)
        .arg("dec")
        .arg(encrypted.path())
        .arg(decrypted.path())
        .arg("--passin")
        .arg("env:CRYPTMAN_TEST_PASSWORD")
        .assert()
        .success();

    decrypted.assert("Hello World!");
    temp_dir.close()?;
    Ok(())
}
