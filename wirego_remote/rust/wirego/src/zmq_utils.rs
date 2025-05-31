use crate::error::WiregoError;

use log::{debug, error, info};
use zeromq::{Socket, SocketRecv, SocketSend};

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
            info!("Wirego bridge is ready to receive commands!");
            Ok(zmq_socket)
        }
        Err(err) => {
            error!("Failed to bind to endpoint: {:?}", err);
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
            error!("Failed to receive ZMQ message: {:?}", err);
            Err(WiregoError::SocketReceiveError(err.to_string()))
        }
    }
}

pub(crate) async fn send_zmq_message(
    zmq_socket: &mut zeromq::RepSocket,
    zmq_message: zeromq::ZmqMessage,
) -> Result<(), WiregoError> {
    debug!("Sending ZMQ message: {:?}", zmq_message);
    match zmq_socket.send(zmq_message).await {
        Ok(_) => Ok(()),
        Err(err) => {
            error!("Failed to send ZMQ message: {:?}", err);
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
                if bytes.len() != $size {
                    return Err(WiregoError::ParseError(format!(
                        "Wrong number of bytes for {}: expected {}, got {}",
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
    use bytes::Bytes;
    use zeromq::ZmqMessage;

    fn get_random_tmp_path() -> String {
        let random_ptr = Box::into_raw(Box::new(454545));
        format!("/tmp/{:p}", random_ptr)
    }

    #[tokio::test]
    async fn test_bind_zmq_socket_with_empty_endpoint() {
        let result = bind_zmq_socket("").await;
        match result {
            Err(WiregoError::SocketInvalidEndpoint(msg)) => {
                assert_eq!(msg, "Empty endpoint".to_string());
            }
            _ => panic!("Expected SocketInvalidEndpoint error"),
        }
    }

    #[tokio::test]
    async fn test_bind_zmq_socket_with_invalid_endpoint() {
        let result = bind_zmq_socket("invalid://endpoint").await;
        match result {
            Err(WiregoError::SocketTypeNotSupported(msg)) => {
                assert_eq!(
                    msg,
                    "Invalid endpoint, must start with tcp:// or ipc://".to_string()
                );
            }
            _ => panic!("Expected SocketTypeNotSupported error"),
        }
    }

    #[cfg(target_family = "unix")]
    #[tokio::test]
    async fn test_bind_zmq_socket_with_valid_ipc_endpoint() {
        let random_addr = get_random_tmp_path();
        let zmq_endpoint = format!("ipc://{}", random_addr);
        let result = bind_zmq_socket(zmq_endpoint.as_str()).await;
        assert!(result.is_ok());

        // Cleanup the test endpoint
        let _ = std::fs::remove_file(random_addr.to_owned());
    }

    #[tokio::test]
    async fn test_bind_zmq_socket_with_valid_tcp_endpoint() {
        let zmq_endpoint = "tcp://127.0.0.1:54321";
        let result = bind_zmq_socket(zmq_endpoint).await;
        assert!(result.is_ok());
    }

    #[cfg(target_family = "unix")]
    #[tokio::test]
    async fn test_bind_zmq_socket_fail_on_bind_ipc() {
        let random_addr = get_random_tmp_path();
        let zmq_endpoint = format!("ipc://{}", random_addr);
        let result = bind_zmq_socket(zmq_endpoint.as_str()).await;
        assert!(result.is_ok());

        // Attempt to bind again to the same endpoint
        let result = bind_zmq_socket(zmq_endpoint.as_str()).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(WiregoError::SocketBindError(_))));

        let _ = std::fs::remove_file(random_addr.to_owned());
    }

    #[tokio::test]
    async fn test_bind_zmq_socket_fail_on_bind_tcp() {
        let zmq_endpoint = "tcp://127.0.0.1:54322";
        let result = bind_zmq_socket(zmq_endpoint).await;
        assert!(result.is_ok());

        // Attempt to bind again to the same endpoint
        let result = bind_zmq_socket(zmq_endpoint).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(WiregoError::SocketBindError(_))));
    }

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
        let mut frames: Vec<Bytes> = vec![];
        frames.push("frame0".into());
        frames.push("frame1".into());
        frames.push("frame2".into());

        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");
        let result = parse_nth_frame_as_string(0, &zmq_message);
        assert_eq!(result.unwrap(), "frame0");
        let result = parse_nth_frame_as_string(1, &zmq_message);
        assert_eq!(result.unwrap(), "frame1");
        let result = parse_nth_frame_as_string(2, &zmq_message);
        assert_eq!(result.unwrap(), "frame2");
    }

    #[test]
    fn test_parse_nth_frame_as_numeric_success() {
        fn assert_frame_value<T>(zmq_message: &ZmqMessage, frame_index: usize, expected: T)
        where
            T: std::str::FromStr + FromFrameBytes + PartialEq + std::fmt::Debug,
            T::Err: std::fmt::Debug,
        {
            assert_eq!(
                parse_nth_frame_as_numeric::<T>(frame_index, zmq_message).unwrap(),
                expected
            );
        }

        let frames: Vec<Bytes> = vec![
            vec![240].into(),                                    // frame idx: 0, type: i8
            vec![240].into(),                                    // frame idx: 1, type: u8
            vec![240, 240].into(),                               // frame idx: 2, type: i16
            vec![240, 240].into(),                               // frame idx: 3, type: u16
            vec![240, 240, 240, 240].into(),                     // frame idx: 4, type: i32
            vec![240, 240, 240, 240].into(),                     // frame idx: 5, type: u32
            vec![240, 240, 240, 240, 240, 240, 240, 240].into(), // frame idx: 6, type: i64
            vec![240, 240, 240, 240, 240, 240, 240, 240].into(), // frame idx: 7, type: u64
        ];

        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");
        assert_frame_value::<i8>(&zmq_message, 0, -16);
        assert_frame_value::<u8>(&zmq_message, 1, 240);
        assert_frame_value::<i16>(&zmq_message, 2, -3856);
        assert_frame_value::<u16>(&zmq_message, 3, 61680);
        assert_frame_value::<i32>(&zmq_message, 4, -252645136);
        assert_frame_value::<u32>(&zmq_message, 5, 4042322160);
        assert_frame_value::<i64>(&zmq_message, 6, -1085102592571150096);
        assert_frame_value::<u64>(&zmq_message, 7, 17361641481138401520);
    }

    #[test]
    fn test_parse_nth_frame_as_numeric_wrong_number_of_input_bytes_error() {
        fn assert_wrong_size<T>(zmq_message: &ZmqMessage, expected_bytes_count: usize)
        where
            T: std::str::FromStr + FromFrameBytes + PartialEq + std::fmt::Debug,
            T::Err: std::fmt::Debug,
        {
            let result: Result<T, WiregoError> = parse_nth_frame_as_numeric(0, zmq_message);
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                format!(
                    "Parse error: Wrong number of bytes for {}: expected {}, got {}",
                    std::any::type_name::<T>(),
                    expected_bytes_count,
                    zmq_message.get(0).unwrap().len()
                )
            );
        }

        let zmq_message = ZmqMessage::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);

        assert_wrong_size::<i8>(&zmq_message, 1);
        assert_wrong_size::<u8>(&zmq_message, 1);
        assert_wrong_size::<i16>(&zmq_message, 2);
        assert_wrong_size::<u16>(&zmq_message, 2);
        assert_wrong_size::<i32>(&zmq_message, 4);
        assert_wrong_size::<u32>(&zmq_message, 4);
        assert_wrong_size::<i64>(&zmq_message, 8);
        assert_wrong_size::<u64>(&zmq_message, 8);
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
        let mut frames: Vec<Bytes> = vec![];
        frames.push(vec![42, 0, 0, 0].into());
        frames.push(vec![43, 0, 0, 0].into());
        frames.push(vec![44, 0, 0, 0].into());

        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(0, &zmq_message);
        assert_eq!(result.unwrap(), 42);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(1, &zmq_message);
        assert_eq!(result.unwrap(), 43);
        let result: Result<u32, WiregoError> = parse_nth_frame_as_numeric(2, &zmq_message);
        assert_eq!(result.unwrap(), 44);
    }
}
