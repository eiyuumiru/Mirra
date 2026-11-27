//! Read the endpoint's platform without requiring developer tools at setup
//! (port of `scripts/macho.py`).
use std::io::Read;
use std::path::Path;

use mirra_core::{Error, Result};
use serde_json::{json, Value};

/// Mach-O file type of the bridge endpoint executable.
pub const EXECUTABLE: u32 = 2;
/// Mach-O file type of the Settings page bundle.
pub const BUNDLE: u32 = 8;

fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Require a thin generic-arm64 device-iOS Mach-O of `filetype`; returns
/// `{'architecture': 'arm64', 'platform': 'ios', 'minimum_os': 'X.Y.Z'}`.
pub fn require_ios_endpoint(path: &Path, filetype: u32) -> Result<Value> {
    let mut stream = std::fs::File::open(path).map_err(|e| Error::with_path(e, path))?;
    let mut header = Vec::new();
    (&mut stream).take(32).read_to_end(&mut header)?;
    if header.len() != 32 {
        return Err(Error::value("The endpoint has an incomplete Mach-O header"));
    }
    let field = |i: usize| u32_at(&header, i * 4);
    let (magic, cpu, subtype, kind, count, length) = (field(0), field(1), field(2), field(3), field(4), field(5));
    if magic != 0xFEEDFACF || cpu != 0x100000C || kind != filetype {
        return Err(Error::value("The endpoint must be a thin arm64 iOS executable"));
    }
    // arm64e uses the same CPU type as arm64. Checking only cputype accepts
    // a binary that cannot run on A11 and earlier bridge devices.
    if subtype != 0 {
        return Err(Error::value("The endpoint must use generic arm64, not arm64e or a restricted CPU subtype"));
    }
    if !(1..=65536).contains(&count) || !(8..=1048576).contains(&length) {
        return Err(Error::value("Invalid endpoint load-command bounds"));
    }
    let length = length as usize;
    let mut commands = Vec::new();
    stream.take(length as u64).read_to_end(&mut commands)?;
    if commands.len() != length {
        return Err(Error::value("The endpoint load commands are truncated"));
    }
    let mut offset = 0usize;
    let mut builds = Vec::new();
    for _ in 0..count {
        if offset + 8 > length {
            return Err(Error::value("The endpoint load command is truncated"));
        }
        let (command, size) = (u32_at(&commands, offset), u32_at(&commands, offset + 4) as usize);
        if size < 8 || size % 8 != 0 || offset + size > length {
            return Err(Error::value("Invalid endpoint load-command size"));
        }
        if command == 0x32 {
            // LC_BUILD_VERSION; device iOS platform = 2.
            if size < 24 {
                return Err(Error::value("Invalid endpoint build-version command"));
            }
            let (platform, minimum, tools) = (u32_at(&commands, offset + 8), u32_at(&commands, offset + 12), u32_at(&commands, offset + 20));
            if size as u64 != 24 + tools as u64 * 8 {
                return Err(Error::value("Invalid endpoint build-tool entries"));
            }
            builds.push((platform, minimum));
        }
        offset += size;
    }
    if offset != length || builds.len() != 1 || builds[0].0 != 2 {
        return Err(Error::value("The endpoint must be built for device iOS"));
    }
    let version = builds[0].1;
    Ok(json!({"architecture": "arm64", "platform": "ios",
        "minimum_os": format!("{}.{}.{}", version >> 16, (version >> 8) & 255, version & 255)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sample {
        platform: u32,
        cpu: u32,
        size: u32,
        count: u32,
        tail: Vec<u8>,
        subtype: u32,
    }

    impl Default for Sample {
        fn default() -> Self {
            Sample { platform: 2, cpu: 0x100000C, size: 24, count: 1, tail: Vec::new(), subtype: 0 }
        }
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn sample(path: &Path, s: Sample) -> Result<Value> {
        let command = words(&[0x32, s.size, s.platform, 15 << 16, 18 << 16, 0]);
        let mut data = words(&[0xFEEDFACF, s.cpu, s.subtype, 2, s.count, (command.len() + s.tail.len()) as u32, 0, 0]);
        data.extend(command);
        data.extend(s.tail);
        std::fs::write(path, data).unwrap();
        require_ios_endpoint(path, EXECUTABLE)
    }

    fn message(result: Result<Value>) -> String {
        match result {
            Err(Error::Value(m)) => m,
            other => panic!("expected ValueError, got {:?}", other),
        }
    }

    #[test]
    fn device_ios_arm64_is_accepted_without_external_tools() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("endpoint");
        assert_eq!(sample(&binary, Sample::default()).unwrap(), json!({"architecture": "arm64", "platform": "ios", "minimum_os": "15.0.0"}));
        assert!(require_ios_endpoint(&binary, BUNDLE).is_err());
    }

    #[test]
    fn macos_simulator_wrong_architecture_and_arm64e_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("endpoint");
        for platform in [1, 7] {
            assert!(message(sample(&binary, Sample { platform, ..Default::default() })).contains("device iOS"));
        }
        assert!(message(sample(&binary, Sample { cpu: 0x1000007, ..Default::default() })).contains("arm64"));
        for subtype in [1, 2, 0x80000002, 0x80000000] {
            assert!(message(sample(&binary, Sample { subtype, ..Default::default() })).contains("generic arm64"));
        }
    }

    #[test]
    fn truncated_header_and_commands_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("endpoint");
        sample(&binary, Sample::default()).unwrap();
        let original = std::fs::read(&binary).unwrap();
        for length in [0, 31, 40, 55] {
            std::fs::write(&binary, &original[..length]).unwrap();
            message(require_ios_endpoint(&binary, EXECUTABLE));
        }
    }

    #[test]
    fn unbounded_misaligned_duplicate_and_trailing_commands_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("endpoint");
        let cases = vec![
            Sample { size: 0, ..Default::default() }, Sample { size: 16, ..Default::default() },
            Sample { size: 25, ..Default::default() }, Sample { size: 1048576, ..Default::default() },
            Sample { count: 0, ..Default::default() }, Sample { count: 2, ..Default::default() },
            Sample { tail: b"ignored".to_vec(), ..Default::default() },
            Sample { count: 2, tail: words(&[0x32, 24, 1, 15 << 16, 0, 0]), ..Default::default() },
        ];
        for case in cases {
            message(sample(&binary, case));
        }
    }
}
