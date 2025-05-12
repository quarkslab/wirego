#[derive(Debug)]
pub enum WiregoError {
    SocketInvalidEndpoint(String),
    SocketTypeNotSupported(String),
    SocketBindError(String),
    SocketReceiveError(String),
    SocketSendError(String),
    InvalidMessage(String),
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
