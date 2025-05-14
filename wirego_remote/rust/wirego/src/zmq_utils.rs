use zeromq::{Socket, SocketRecv, SocketSend};

use crate::error::WiregoError;

pub(crate) async fn bind_zmq_socket(zmq_endpoint: &str) -> Result<zeromq::RepSocket, WiregoError> {
    if zmq_endpoint.is_empty() {
        return Err(WiregoError::SocketInvalidEndpoint(
            "Empty endpoint".to_string(),
        ));
    }

    if !zmq_endpoint.starts_with("tcp://") && !zmq_endpoint.starts_with("ipc://") {
        return Err(WiregoError::SocketTypeNotSupported(
            "Invalid endpoint, must start with tcp:// or ipc://".to_string(),
        ));
    }

    let mut zmq_socket = zeromq::RepSocket::new();
    match zmq_socket.bind(zmq_endpoint).await {
        Ok(_) => {
            println!("Wirego bridge is ready to receive commands!");
            Ok(zmq_socket)
        }
        Err(err) => {
            eprintln!("Failed to bind to endpoint: {:?}", err);
            Err(WiregoError::SocketBindError(err.to_string()))
        }
    }
}

pub(crate) async fn receive_zmq_message(
    zmq_socket: &mut zeromq::RepSocket,
) -> Result<zeromq::ZmqMessage, WiregoError> {
    match zmq_socket.recv().await {
        Ok(zmq_message) => Ok(zmq_message),
        Err(err) => {
            eprintln!("Failed to receive ZMQ message: {:?}", err);
            Err(WiregoError::SocketReceiveError(err.to_string()))
        }
    }
}

pub(crate) async fn send_zmq_message(
    zmq_socket: &mut zeromq::RepSocket,
    zmq_message: zeromq::ZmqMessage,
) -> Result<(), WiregoError> {
    println!("Sending ZMQ message: {:?}", zmq_message);
    match zmq_socket.send(zmq_message).await {
        Ok(_) => Ok(()),
        Err(err) => {
            eprintln!("Failed to send ZMQ message: {:?}", err);
            Err(WiregoError::SocketSendError(err.to_string()))
        }
    }
}

pub(crate) fn parse_nth_frame_as_string(
    index: usize,
    zmq_message: &zeromq::ZmqMessage,
) -> Result<String, WiregoError>
where
{
    let frame = zmq_message
        .get(index)
        .ok_or_else(|| WiregoError::ParseError(format!("Frame at index {} not found", index)))?;

    let frame_str = String::from_utf8(frame.to_vec()).map_err(|_| {
        WiregoError::ParseError(format!("Failed to convert frame to string: {:?}", frame))
    })?;

    let parsed_value = frame_str.parse::<String>().map_err(|err| {
        WiregoError::ParseError(format!("Failed to parse frame as String, error: {:?}", err))
    })?;

    Ok(parsed_value)
}

pub(crate) fn parse_nth_frame_as_numeric<T>(
    index: usize,
    zmq_message: &zeromq::ZmqMessage,
) -> Result<T, WiregoError>
where
    T: std::str::FromStr + FromFrameBytes,
    T::Err: std::fmt::Debug,
{
    let frame = zmq_message
        .get(index)
        .ok_or_else(|| WiregoError::ParseError(format!("Frame at index {} not found", index)))?;

    T::from_frame_bytes(frame.as_ref())
}

pub(crate) trait FromFrameBytes: Sized {
    fn from_frame_bytes(bytes: &[u8]) -> Result<Self, WiregoError>;
}

macro_rules! impl_from_frame_bytes {
    ($t:ty, $size:expr, $from_bytes:expr) => {
        impl FromFrameBytes for $t {
            fn from_frame_bytes(bytes: &[u8]) -> Result<Self, WiregoError> {
                if bytes.len() < $size {
                    return Err(WiregoError::ParseError(format!(
                        "Too few bytes for {}: expected {}, got {}",
                        stringify!($t),
                        $size,
                        bytes.len()
                    )));
                }
                Ok($from_bytes(&bytes[0..$size]))
            }
        }
    };
}

impl_from_frame_bytes!(u8, 1, |b: &[u8]| b[0]);
impl_from_frame_bytes!(i8, 1, |b: &[u8]| b[0] as i8);
impl_from_frame_bytes!(u16, 2, |b: &[u8]| u16::from_le_bytes(b.try_into().unwrap()));
impl_from_frame_bytes!(i16, 2, |b: &[u8]| i16::from_le_bytes(b.try_into().unwrap()));
impl_from_frame_bytes!(u32, 4, |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap()));
impl_from_frame_bytes!(i32, 4, |b: &[u8]| i32::from_le_bytes(b.try_into().unwrap()));
impl_from_frame_bytes!(u64, 8, |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap()));
impl_from_frame_bytes!(i64, 8, |b: &[u8]| i64::from_le_bytes(b.try_into().unwrap()));

#[cfg(test)]
mod tests {
    use super::*;
    use zeromq::ZmqMessage;

    #[test]
    fn test_parse_nth_frame_as_string() {
        let zmq_message = ZmqMessage::from("Hello, World!");
        let result = parse_nth_frame_as_string(0, &zmq_message);
        assert_eq!(result.unwrap(), "Hello, World!");
    }

    #[test]
    fn test_parse_nth_frame_as_string_error_with_too_big_frame_index() {
        let zmq_message = ZmqMessage::from(vec![0, 0, 0]);
        let result = parse_nth_frame_as_string(5, &zmq_message);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parse error: Frame at index 5 not found"
        );
    }

    #[test]
    fn test_parse_nth_frame_as_string_with_multiple_frames() {
        let mut frames: Vec<bytes::Bytes> = vec![];
        frames.push("frame0".into());
        frames.push("frame1".into());
        frames.push("frame2".into());

        let zmq_message =
            zeromq::ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");
        let result = parse_nth_frame_as_string(0, &zmq_message);
        assert_eq!(result.unwrap(), "frame0");
        let result = parse_nth_frame_as_string(1, &zmq_message);
        assert_eq!(result.unwrap(), "frame1");
        let result = parse_nth_frame_as_string(2, &zmq_message);
        assert_eq!(result.unwrap(), "frame2");
    }

    #[test]
    fn test_parse_nth_frame_as_numeric() {
        let zmq_message = ZmqMessage::from(vec![42, 0, 0, 0]);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(0, &zmq_message);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_parse_nth_frame_as_numeric_error() {
        let zmq_message = ZmqMessage::from(vec![0, 0, 0]);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(0, &zmq_message);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parse error: Too few bytes for u32: expected 4, got 3"
        );
    }

    #[test]
    fn test_parse_nth_frame_as_numeric_error_with_too_big_frame_index() {
        let zmq_message = ZmqMessage::from(vec![0, 0, 0]);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(5, &zmq_message);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Parse error: Frame at index 5 not found"
        );
    }

    #[test]
    fn test_parse_nth_frame_as_numeric_with_multiple_frames() {
        let mut frames: Vec<bytes::Bytes> = vec![];
        frames.push(vec![42, 0, 0, 0].into());
        frames.push(vec![43, 0, 0, 0].into());
        frames.push(vec![44, 0, 0, 0].into());

        let zmq_message =
            zeromq::ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(0, &zmq_message);
        assert_eq!(result.unwrap(), 42);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(1, &zmq_message);
        assert_eq!(result.unwrap(), 43);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(2, &zmq_message);
        assert_eq!(result.unwrap(), 44);
    }
}
