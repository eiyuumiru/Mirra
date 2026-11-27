//! USB discovery and connection primitives, independent of a particular model
//! (port of `scripts/usbmux.py`).
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use mirra_core::{Error, Result};
use serde_json::{json, Map, Value};

use crate::plist;
use crate::pyutil::{py_str, socket_error};

pub const SOCKET_PATH: &str = "/var/run/usbmuxd";
pub const LOCKDOWN_PORT: u16 = 62078;
const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_PAYLOAD: usize = 1048576;

#[cfg(test)]
thread_local! {
    /// Tests point the default socket at a fake usbmuxd.
    pub(crate) static SOCKET_OVERRIDE: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn default_socket() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(path) = SOCKET_OVERRIDE.with(|p| p.borrow().clone()) {
        return path;
    }
    std::path::PathBuf::from(SOCKET_PATH)
}

/// `recvn(sock, length)`
pub fn recvn(sock: &mut impl Read, length: usize) -> Result<Vec<u8>> {
    let mut result = vec![0u8; length];
    let mut filled = 0;
    while filled < length {
        match sock.read(&mut result[filled..]) {
            Ok(0) => return Err(Error::Connection("Device connection closed".into())),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(socket_error(e)),
        }
    }
    Ok(result)
}

/// `request(message)`: one usbmuxd exchange; returns the socket (which a
/// `Connect` turns into the device stream) and the decoded reply.
pub fn request(message: &Map<String, Value>) -> Result<(UnixStream, Value)> {
    request_at(&default_socket(), message)
}

/// [`request`] against a specific usbmuxd socket path.
pub fn request_at(socket_path: &Path, message: &Map<String, Value>) -> Result<(UnixStream, Value)> {
    let mut sock = UnixStream::connect(socket_path).map_err(socket_error)?;
    sock.set_read_timeout(Some(TIMEOUT)).map_err(Error::Os)?;
    sock.set_write_timeout(Some(TIMEOUT)).map_err(Error::Os)?;
    let mut full = Map::new();
    full.insert("ClientVersionString".into(), json!("Mirra"));
    full.insert("ProgName".into(), json!("Mirra"));
    full.insert("kLibUSBMuxVersion".into(), json!(3));
    for (k, v) in message {
        full.insert(k.clone(), v.clone());
    }
    let payload = plist::dumps(&Value::Object(full))?;
    let mut packet = Vec::with_capacity(16 + payload.len());
    for field in [(16 + payload.len()) as u32, 1, 8, 1] {
        packet.extend_from_slice(&field.to_le_bytes());
    }
    packet.extend_from_slice(&payload);
    sock.write_all(&packet).map_err(socket_error)?;
    let header = recvn(&mut sock, 16)?;
    let field = |i: usize| u32::from_le_bytes(header[i * 4..i * 4 + 4].try_into().unwrap());
    let (length, version, kind, tag) = (field(0) as usize, field(1), field(2), field(3));
    if version != 1 || kind != 8 || tag != 1 || !(16..=MAX_PAYLOAD).contains(&length) {
        return Err(Error::Connection("Unexpected usbmuxd reply".into()));
    }
    let body = recvn(&mut sock, length - 16)?;
    let reply = plist::loads(&body)?;
    Ok((sock, reply))
}

/// `connect(device_id, port)`: a stream to `port` on the device.
pub fn connect(device_id: &Value, port: u16) -> Result<UnixStream> {
    connect_at(&default_socket(), device_id, port)
}

pub fn connect_at(socket_path: &Path, device_id: &Value, port: u16) -> Result<UnixStream> {
    let mut message = Map::new();
    message.insert("MessageType".into(), json!("Connect"));
    message.insert("DeviceID".into(), device_id.clone());
    message.insert("PortNumber".into(), json!(port.to_be()));
    let (sock, reply) = request_at(socket_path, &message)?;
    let number = reply.get("Number");
    if !matches!(number, Some(Value::Number(n)) if n.as_f64() == Some(0.0)) {
        return Err(Error::Connection(format!("usbmuxd refused device port {}: {}", port, py_str(number))));
    }
    Ok(sock)
}

/// `product_type(device_id)`: the lockdown `ProductType` value (any type).
pub fn product_type(device_id: &Value) -> Result<Value> {
    product_type_at(&default_socket(), device_id)
}

pub fn product_type_at(socket_path: &Path, device_id: &Value) -> Result<Value> {
    let mut sock = connect_at(socket_path, device_id, LOCKDOWN_PORT)?;
    let payload = plist::dumps(&json!({"Label": "Mirra", "Request": "GetValue", "Key": "ProductType"}))?;
    let mut packet = (payload.len() as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&payload);
    sock.write_all(&packet).map_err(socket_error)?;
    let length = u32::from_be_bytes(recvn(&mut sock, 4)?.try_into().unwrap()) as usize;
    if !(1..=MAX_PAYLOAD).contains(&length) {
        return Err(Error::Connection("Unexpected lockdown reply".into()));
    }
    let reply = plist::loads(&recvn(&mut sock, length)?)?;
    Ok(reply.get("Value").cloned().unwrap_or(Value::Null))
}

fn connection_type(device: &Value) -> Option<&Value> {
    device.get("Properties").and_then(|p| p.get("ConnectionType"))
}

/// `list_devices()`: attached USB devices (network pairings excluded).
pub fn list_devices() -> Result<Vec<Value>> {
    list_devices_at(&default_socket())
}

pub fn list_devices_at(socket_path: &Path) -> Result<Vec<Value>> {
    let mut message = Map::new();
    message.insert("MessageType".into(), json!("ListDevices"));
    let (sock, reply) = request_at(socket_path, &message)?;
    drop(sock);
    let devices = match reply.get("DeviceList") {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    Ok(devices.into_iter().filter(|d| connection_type(d) == Some(&json!("USB"))).collect())
}

/// Reads a device's product type by `DeviceID` (see [`product_type`]).
pub type ProductReader<'a> = &'a dyn Fn(&Value) -> Result<Value>;

/// `select_device(devices, product=, serial=, product_reader=)`: reject
/// missing or ambiguous devices; identifiers are AND filters.
pub fn select_device(devices: &[Value], product: &str, serial: &str, product_reader: Option<ProductReader>) -> Result<Value> {
    if product.is_empty() && serial.is_empty() {
        return Err(Error::Value("Select a backend serial or product_type".into()));
    }
    let default_reader = |id: &Value| product_type(id);
    let reader: ProductReader = product_reader.unwrap_or(&default_reader);
    let mut matches = Vec::new();
    for device in devices {
        let properties = device.get("Properties");
        if properties.and_then(|p| p.get("ConnectionType")) != Some(&json!("USB")) {
            continue;
        }
        if !serial.is_empty() && properties.and_then(|p| p.get("SerialNumber")) != Some(&json!(serial)) {
            continue;
        }
        if !product.is_empty() {
            let id = device.get("DeviceID").cloned().unwrap_or(Value::Null);
            match reader(&id) {
                Ok(value) if value == json!(product) => {}
                Ok(_) => continue,
                Err(e) if e.is_os_error() || matches!(e, Error::Value(_) | Error::Config(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        matches.push(device.clone());
    }
    if matches.len() != 1 {
        return Err(Error::Connection(format!(
            "Expected one matching USB backend; found {}. Check config/local.json and connected devices", matches.len())));
    }
    Ok(matches.remove(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn device(id: i64, serial: &str, transport: &str) -> Value {
        json!({"DeviceID": id, "Properties": {"SerialNumber": serial, "ConnectionType": transport}})
    }

    #[test]
    fn replug_uses_new_identifier() {
        let first = select_device(&[device(4, "BACKEND", "USB")], "", "BACKEND", None).unwrap();
        let next = select_device(&[device(17, "BACKEND", "USB")], "", "BACKEND", None).unwrap();
        assert_eq!(first["DeviceID"], 4);
        assert_eq!(next["DeviceID"], 17);
    }

    #[test]
    fn same_model_is_ambiguous_without_serial() {
        let devices = [device(1, "FIRST", "USB"), device(2, "SECOND", "USB")];
        let reader = |_: &Value| Ok(json!("iPhone11,2"));
        let error = select_device(&devices, "iPhone11,2", "", Some(&reader)).unwrap_err();
        assert_eq!(error.type_name(), "ConnectionError");
        assert_eq!(error.to_string(), "Expected one matching USB backend; found 2. Check config/local.json and connected devices");
        assert_eq!(select_device(&devices, "", "SECOND", None).unwrap()["DeviceID"], 2);
    }

    #[test]
    fn serial_does_not_override_wrong_model() {
        let reader = |_: &Value| Ok(json!("iPhone14,5"));
        assert!(select_device(&[device(1, "BACKEND", "USB")], "iPhone11,2", "BACKEND", Some(&reader)).is_err());
    }

    #[test]
    fn network_and_unreadable_devices_are_excluded() {
        assert!(select_device(&[device(1, "BACKEND", "Network")], "", "BACKEND", None).is_err());
        let unavailable = |_: &Value| Err(Error::Connection("disconnected".into()));
        assert!(select_device(&[device(1, "BACKEND", "USB")], "iPhone11,2", "", Some(&unavailable)).is_err());
        let error = select_device(&[device(1, "BACKEND", "USB")], "", "", None).unwrap_err();
        assert_eq!(error.to_string(), "Select a backend serial or product_type");
        let broken = |_: &Value| Err(Error::Runtime("unexpected".into()));
        assert_eq!(select_device(&[device(1, "BACKEND", "USB")], "iPhone11,2", "", Some(&broken)).unwrap_err().type_name(),
            "RuntimeError");
    }

    /// A fake usbmuxd: replies to each message with `reply(request)`; on a
    /// successful Connect to the lockdown port, it answers GetValue.
    pub(crate) fn fake_usbmuxd(reply: impl Fn(&Value) -> Value + Send + Sync + 'static, connections: usize)
        -> (tempfile::TempDir, std::path::PathBuf, std::thread::JoinHandle<Vec<Value>>) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("usbmuxd");
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..connections {
                let (mut stream, _) = listener.accept().unwrap();
                let header = recvn(&mut stream, 16).unwrap();
                let length = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
                assert_eq!(&header[4..], &[1, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0]);
                let message = plist::loads(&recvn(&mut stream, length - 16).unwrap()).unwrap();
                let answer = plist::dumps(&reply(&message)).unwrap();
                let mut packet = Vec::new();
                for field in [(16 + answer.len()) as u32, 1, 8, 1] {
                    packet.extend_from_slice(&field.to_le_bytes());
                }
                packet.extend_from_slice(&answer);
                stream.write_all(&packet).unwrap();
                if message["MessageType"] == "Connect" && message["PortNumber"] == LOCKDOWN_PORT.to_be() {
                    let size = u32::from_be_bytes(recvn(&mut stream, 4).unwrap().try_into().unwrap()) as usize;
                    let query = plist::loads(&recvn(&mut stream, size).unwrap()).unwrap();
                    assert_eq!(query, json!({"Label": "Mirra", "Request": "GetValue", "Key": "ProductType"}));
                    let value = plist::dumps(&json!({"Key": "ProductType", "Value": "iPhone10,5"})).unwrap();
                    stream.write_all(&(value.len() as u32).to_be_bytes()).unwrap();
                    stream.write_all(&value).unwrap();
                }
                seen.push(message);
            }
            seen
        });
        (temp, path, handle)
    }

    #[test]
    fn talks_the_usbmuxd_protocol() {
        let (_temp, path, server) = fake_usbmuxd(|message| match message["MessageType"].as_str() {
            Some("ListDevices") => json!({"DeviceList": [device(5, "S1", "USB"), device(6, "S2", "Network"),
                json!({"DeviceID": 7, "Properties": {"SerialNumber": "S3"}})]}),
            Some("Connect") if message["PortNumber"] == 1u16.to_be() => json!({"MessageType": "Result", "Number": 3}),
            _ => json!({"MessageType": "Result", "Number": 0}),
        }, 4);
        let devices = list_devices_at(&path).unwrap();
        assert_eq!(devices, vec![device(5, "S1", "USB")]);
        assert_eq!(product_type_at(&path, &json!(5)).unwrap(), "iPhone10,5");
        let refused = connect_at(&path, &json!(5), 1).unwrap_err();
        assert_eq!(refused.to_string(), "usbmuxd refused device port 1: 3");
        assert_eq!(refused.type_name(), "ConnectionError");
        connect_at(&path, &json!(5), 47820).unwrap();
        let seen = server.join().unwrap();
        assert_eq!(seen[0], json!({"ClientVersionString": "Mirra", "MessageType": "ListDevices", "ProgName": "Mirra",
            "kLibUSBMuxVersion": 3}));
        assert_eq!(seen[3]["PortNumber"], 52410);
        assert_eq!(seen[3]["DeviceID"], 5);
    }

    #[test]
    fn bad_replies_and_missing_daemon_are_connection_failures() {
        let temp = tempfile::tempdir().unwrap();
        let missing = list_devices_at(&temp.path().join("absent")).unwrap_err();
        assert_eq!(missing.to_string(), "[Errno 2] No such file or directory");
        let path = temp.path().join("bad");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let header = recvn(&mut stream, 16).unwrap();
            let length = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
            recvn(&mut stream, length - 16).unwrap();
            stream.write_all(&[20, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 2, 0, 0, 0]).unwrap();
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        assert_eq!(list_devices_at(&path).unwrap_err().to_string(), "Unexpected usbmuxd reply");
        let closed = list_devices_at(&path).unwrap_err();
        assert!(closed.is_os_error(), "{}", closed);
        server.join().unwrap();
    }
}
