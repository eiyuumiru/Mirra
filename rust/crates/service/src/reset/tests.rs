use super::*;

#[test]
fn attested_keys_are_deleted_until_none_is_left() {
    let mut replies = vec![0, 0, ITEM_NOT_FOUND].into_iter();
    assert_eq!(delete_attested_keys(&mut || Ok(replies.next().unwrap())).unwrap(), 2);
    assert_eq!(delete_attested_keys(&mut || Ok(ITEM_NOT_FOUND)).unwrap(), 0);
}

#[test]
fn keychain_failures_and_runaway_deletes_are_errors() {
    assert!(delete_attested_keys(&mut || Ok(51)).unwrap_err().to_string().contains("exit 51"));
    assert!(delete_attested_keys(&mut || Ok(0)).is_err());
    assert!(delete_attested_keys(&mut || Err(std::io::Error::from(std::io::ErrorKind::NotFound))).is_err());
}

#[test]
fn state_files_are_mirras_private_backups() {
    let [ltk, pairing] = state_files(Path::new("/Users/someone"));
    assert_eq!(ltk, Path::new("/Users/someone/Library/Application Support/Mirra/state/attested-ltk.plist"));
    assert_eq!(pairing, Path::new("/Users/someone/Library/Application Support/Mirra/state/pairing.plist"));
}
