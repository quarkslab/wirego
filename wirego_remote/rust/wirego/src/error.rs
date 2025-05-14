/// WiregoError enum to represent various error types
/// that can occur in the Wirego library.
#[derive(Debug)]
pub enum WiregoError {
    /// Represents an error when the socket endpoint is invalid.
    SocketInvalidEndpoint(String),
    /// Represents an error when the socket type is not supported.
    /// For example, if the endpoint does not start with "tcp://" or "ipc://".
    SocketTypeNotSupported(String),
    /// Represents an error when binding the socket to given endpoint fails.
    SocketBindError(String),
    /// Represents an error when receiving a message from the socket fails.
    SocketReceiveError(String),
    /// Represents an error when sending a message through the socket fails.
    SocketSendError(String),
    /// Represents an error when the received message is invalid.
    InvalidMessage(String),
    /// Represents an error when parsing a message fails.
    ParseError(String),
}

impl std::fmt::Display for WiregoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WiregoError::SocketInvalidEndpoint(msg) => write!(f, "Invalid endpoint: {}", msg),
            WiregoError::SocketTypeNotSupported(msg) => {
                write!(f, "Socket type not supported: {}", msg)
            }
            WiregoError::SocketBindError(msg) => write!(f, "Socket bind error: {}", msg),
            WiregoError::SocketReceiveError(msg) => write!(f, "Socket receive error: {}", msg),
            WiregoError::SocketSendError(msg) => write!(f, "Socket send error: {}", msg),
            WiregoError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            WiregoError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERROR_MESSAGE: &str = "test message";

    #[test]
    fn test_wirego_error_socket_invalid_endpoint() {
        let error = WiregoError::SocketInvalidEndpoint(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Invalid endpoint: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_socket_type_not_supported() {
        let error = WiregoError::SocketTypeNotSupported(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Socket type not supported: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_socket_bind_error() {
        let error = WiregoError::SocketBindError(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Socket bind error: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_socket_receive_error() {
        let error = WiregoError::SocketReceiveError(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Socket receive error: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_socket_send_error() {
        let error = WiregoError::SocketSendError(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Socket send error: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_invalid_message() {
        let error = WiregoError::InvalidMessage(ERROR_MESSAGE.to_string());
        assert_eq!(
            error.to_string(),
            format!("Invalid message: {}", ERROR_MESSAGE)
        );
    }

    #[test]
    fn test_wirego_error_parse_error() {
        let error = WiregoError::ParseError(ERROR_MESSAGE.to_string());
        assert_eq!(error.to_string(), format!("Parse error: {}", ERROR_MESSAGE));
    }
}
