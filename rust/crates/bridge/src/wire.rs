//! Adapt the reviewed attested LTK layout to the host's platform-3 wire
//! format (port of `scripts/wire.py`).
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use mirra_core::{Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// One DER node: `(tag, start, content_start, stop)`.
pub type Node = (u8, usize, usize, usize);

/// `nodes(data, begin, end)`: a lazy iterator over the DER nodes in
/// `data[begin:end]`; an error ends the iteration.
pub fn nodes(data: &[u8], begin: usize, end: Option<usize>) -> Nodes<'_> {
    Nodes { data, position: begin, end: end.unwrap_or(data.len()), failed: false }
}

pub struct Nodes<'a> {
    data: &'a [u8],
    position: usize,
    end: usize,
    failed: bool,
}

impl Iterator for Nodes<'_> {
    type Item = Result<Node>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.position >= self.end {
            return None;
        }
        let result = self.parse();
        self.failed = result.is_err();
        Some(result)
    }
}

impl Nodes<'_> {
    fn parse(&mut self) -> Result<Node> {
        let (data, end) = (self.data, self.end);
        let start = self.position;
        let mut position = self.position;
        if position + 2 > end {
            return Err(Error::Value("Truncated DER header".into()));
        }
        let tag = data[position];
        let mut length = data[position + 1] as usize;
        position += 2;
        if length & 128 != 0 {
            let count = length & 127;
            if !(1..=4).contains(&count) || position + count > end {
                return Err(Error::Value("Invalid DER length".into()));
            }
            length = data[position..position + count].iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
            position += count;
        }
        let stop = position + length;
        if stop > end {
            return Err(Error::Value("DER field exceeds parent".into()));
        }
        self.position = stop;
        Ok((tag, start, position, stop))
    }
}

/// `wrap(tag, data)`: one DER node with a minimal length encoding.
pub fn wrap(tag: u8, data: &[u8]) -> Vec<u8> {
    let size = data.len();
    let mut out = vec![tag];
    if size < 128 {
        out.push(size as u8);
    } else {
        let bytes = (size as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(128 + (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(data);
    out
}

/// `parent, = nodes(...)`: exactly one node.
fn single(data: &[u8]) -> Result<Node> {
    let mut iterator = nodes(data, 0, None);
    let first = match iterator.next() {
        None => return Err(Error::Value("not enough values to unpack (expected 1, got 0)".into())),
        Some(node) => node?,
    };
    match iterator.next() {
        None => Ok(first),
        Some(Err(e)) => Err(e),
        Some(Ok(_)) => Err(Error::Value("too many values to unpack (expected 1)".into())),
    }
}

/// `base64.b64decode(text, validate=True)`.
pub fn b64decode_strict(text: &str) -> Result<Vec<u8>> {
    let body = text.trim_end_matches('=');
    let padding = text.len() - body.len();
    if padding > 2 || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
        return Err(Error::Value("Non-base64 digit found".into()));
    }
    if body.len() % 4 == 1 {
        return Err(Error::Value(format!(
            "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4", body.len())));
    }
    let engine = GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::RequireCanonical));
    engine.decode(text).map_err(|_| Error::Value("Incorrect padding".into()))
}

const SOURCE_TAGS: [u8; 6] = [0x81, 0x85, 0x86, 0x82, 0x83, 0x84];

/// `platform_ltk(encoded, platform)` → `(encoded wire LTK, proof)`.
pub fn platform_ltk(encoded: &str, platform: i64) -> Result<(String, Value)> {
    if platform != 3 {
        return Err(Error::Value("Only the accepted platform-3 profile is supported".into()));
    }
    let raw = b64decode_strict(encoded)?;
    if !(512..=65536).contains(&raw.len()) {
        return Err(Error::Value("Expected an attested signing identity".into()));
    }
    let parent = single(&raw)?;
    if parent.0 != 0x30 {
        return Err(Error::Value("Expected one DER sequence".into()));
    }
    let fields: Vec<Node> = nodes(&raw, parent.2, Some(parent.3)).collect::<Result<_>>()?;
    if fields.iter().map(|f| f.0).collect::<Vec<_>>() != SOURCE_TAGS {
        return Err(Error::Value("Unexpected source LTK layout; do not guess".into()));
    }
    let mut content = raw[parent.2..parent.3].to_vec();
    content.extend(wrap(0x87, &[platform as u8]));
    let modified = wrap(0x30, &content);
    if modified.len() > 65536 {
        return Err(Error::Value("Platform signing identity exceeds the native key limit".into()));
    }
    let updated_parent = single(&modified)?;
    let updated: Vec<Node> = nodes(&modified, updated_parent.2, Some(updated_parent.3)).collect::<Result<_>>()?;
    let preserved = fields.iter().zip(&updated).all(|(a, b)| raw[a.1..a.3] == modified[b.1..b.3]);
    if !preserved || updated.len() != fields.len() + 1 {
        return Err(Error::Value("Existing LTK fields changed".into()));
    }
    let attestation = hex(&Sha256::digest(&raw[fields[1].2..fields[1].3]));
    let proof = json!({
        "wire_platform": platform, "original_bytes": raw.len(), "wire_bytes": modified.len(),
        "original_fields_byte_identical": preserved, "attestation_sha256": attestation,
        "stock_phone_acceptance_verified": false,
    });
    Ok((base64::engine::general_purpose::STANDARD.encode(&modified), proof))
}

pub(crate) fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    fn fixture(size: usize, tags: &[u8]) -> Vec<u8> {
        for payload in size.saturating_sub(80)..size {
            let inner: Vec<u8> = tags.iter().enumerate()
                .flat_map(|(index, tag)| wrap(*tag, &vec![b'x'; if index == 1 { payload } else { 1 }])).collect();
            let raw = wrap(0x30, &inner);
            if raw.len() == size {
                return raw;
            }
        }
        panic!("Cannot construct fixture of size {}", size);
    }

    fn adapt(raw: &[u8], platform: i64) -> Result<(Vec<u8>, Value)> {
        let (encoded, proof) = platform_ltk(&B64.encode(raw), platform)?;
        Ok((B64.decode(encoded).unwrap(), proof))
    }

    #[test]
    fn maximum_output_is_checked_after_platform_tag_is_appended() {
        let (modified, proof) = adapt(&fixture(65533, &SOURCE_TAGS), 3).unwrap();
        assert_eq!(modified.len(), 65536);
        assert_eq!(proof["wire_bytes"], 65536);
        for size in [65534, 65535, 65536] {
            let error = adapt(&fixture(size, &SOURCE_TAGS), 3).unwrap_err();
            assert!(error.to_string().contains("native key limit"), "{}", error);
        }
    }

    #[test]
    fn existing_fields_are_preserved_at_der_length_boundaries() {
        for size in [512, 513, 700, 1024, 65532, 65533] {
            let original = fixture(size, &SOURCE_TAGS);
            let (modified, proof) = adapt(&original, 3).unwrap();
            let parent = single(&original).unwrap();
            let updated = single(&modified).unwrap();
            let mut expected = original[parent.2..parent.3].to_vec();
            expected.extend_from_slice(b"\x87\x01\x03");
            assert_eq!(modified[updated.2..updated.3], expected[..]);
            assert_eq!(proof["original_fields_byte_identical"], true);
            assert_eq!(proof["stock_phone_acceptance_verified"], false);
            assert_eq!(proof["original_bytes"], size);
            let keys: Vec<&String> = proof.as_object().unwrap().keys().collect();
            assert_eq!(keys, ["wire_platform", "original_bytes", "wire_bytes", "original_fields_byte_identical",
                "attestation_sha256", "stock_phone_acceptance_verified"]);
        }
    }

    #[test]
    fn invalid_sizes_platforms_and_unreviewed_layouts_are_refused() {
        for size in [511, 65537] {
            assert!(adapt(&fixture(size, &SOURCE_TAGS), 3).is_err());
        }
        for platform in [0, 1, 2, 4] {
            assert!(adapt(&fixture(700, &SOURCE_TAGS), platform).is_err());
        }
        let mut reversed = SOURCE_TAGS.to_vec();
        reversed.reverse();
        let mut extra = SOURCE_TAGS.to_vec();
        extra.push(0x87);
        let mut swapped = vec![0x81];
        swapped.extend_from_slice(&SOURCE_TAGS[1..5]);
        swapped.push(0x85);
        for tags in [reversed, SOURCE_TAGS[..5].to_vec(), extra, swapped] {
            let error = adapt(&fixture(700, &tags), 3).unwrap_err();
            assert_eq!(error.to_string(), "Unexpected source LTK layout; do not guess");
        }
    }

    #[test]
    fn malformed_der_and_base64_cannot_publish_a_wire_key() {
        let raw = fixture(700, &SOURCE_TAGS);
        let mut appended = raw.clone();
        appended.extend_from_slice(b"\x30\x00");
        let mut indefinite = b"\x30\x80".to_vec();
        indefinite.extend_from_slice(&raw[2..]);
        let mut long = b"\x30\x85\x00\x00\x00\x02\x00".to_vec();
        long.extend_from_slice(&raw[7..]);
        for malformed in [raw[..raw.len() - 1].to_vec(), appended, indefinite, long] {
            assert!(adapt(&malformed, 3).is_err());
        }
        assert_eq!(platform_ltk("!!!!", 3).unwrap_err().to_string(), "Non-base64 digit found");
        assert_eq!(b64decode_strict("QQ").unwrap_err().to_string(), "Incorrect padding");
        assert_eq!(b64decode_strict("QR==").unwrap(), b"A");
        assert_eq!(wrap(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);
    }
}
