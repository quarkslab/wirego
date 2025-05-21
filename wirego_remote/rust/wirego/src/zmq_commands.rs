use crate::{
    error::WiregoError,
    types::{DisplayMode, ValueType},
    zmq_utils::{parse_nth_frame_as_numeric, parse_nth_frame_as_string},
};
use bytes::Bytes;
use zeromq::ZmqMessage;

pub(crate) const WIREGO_RESPONSE_SUCCESS: &[u8; 1] = b"\x01";
pub(crate) const WIREGO_RESPONSE_FAILURE: &[u8; 1] = b"\x00";

#[derive(Debug, Clone)]
pub(crate) struct UtilityPingReq {}

#[derive(Debug, Clone)]
pub(crate) struct UtilityPingResp {
    pub command_status: [u8; 1],
}

#[derive(Debug, Clone)]
pub(crate) struct UtilityGetVersionReq {}

#[derive(Debug, Clone)]
pub(crate) struct UtilityGetVersionResp {
    pub command_status: [u8; 1],
    pub major: [u8; 1],
    pub minor: [u8; 1],
}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetPluginNameReq {}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetPluginNameResp {
    pub command_status: [u8; 1],
    pub plugin_name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetPluginFilterReq {}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetPluginFilterResp {
    pub command_status: [u8; 1],
    pub plugin_filter: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetFieldsCountReq {}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetFieldsCountResp {
    pub command_status: [u8; 1],
    pub fields_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetFieldReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupGetFieldResp {
    pub command_status: [u8; 1],
    pub wirego_field_id: u32,
    pub field_name: String,
    pub field_filter: String,
    pub field_value_type: ValueType,
    pub field_display_mode: DisplayMode,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectIntReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectIntResp {
    pub command_status: [u8; 1],
    pub filter_name: String,
    pub filter_value: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectStringReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectStringResp {
    pub command_status: [u8; 1],
    pub filter_name: String,
    pub filter_value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectHeuristicParentReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupDetectHeuristicParentResp {
    pub command_status: [u8; 1],
    pub plugin_detection_heuristic_parent: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessHeuristicReq {
    pub packet_number: u32,
    pub src: String,
    pub dst: String,
    pub layer: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessHeuristicResp {
    pub command_status: [u8; 1],
    pub detection_result: [u8; 1],
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessDissectPacketReq {
    pub packet_number: u32,
    pub src: String,
    pub dst: String,
    pub layer: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProcessDissectPacketResp {
    pub command_status: [u8; 1],
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetProtocolReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetProtocolResp {
    pub command_status: [u8; 1],
    pub protocol_column_name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetInfoReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetInfoResp {
    pub command_status: [u8; 1],
    pub protocol_column_info: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetFieldsCountReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetFieldsCountResp {
    pub command_status: [u8; 1],
    pub fields_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetFieldReq {
    pub dissect_handler: u32,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultGetFieldResp {
    pub command_status: [u8; 1],
    pub parent_idx: i32,
    pub wirego_field_id: u32,
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultReleaseReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResultReleaseResp {
    pub command_status: [u8; 1],
}

#[derive(Debug, Clone)]
pub(crate) enum ZmqCommandReq {
    UtilityPing(UtilityPingReq),
    UtilityGetVersion(UtilityGetVersionReq),
    SetupGetPluginName(SetupGetPluginNameReq),
    SetupGetPluginFilter(SetupGetPluginFilterReq),
    SetupGetFieldsCount(SetupGetFieldsCountReq),
    SetupGetField(SetupGetFieldReq),
    SetupDetectInt(SetupDetectIntReq),
    SetupDetectString(SetupDetectStringReq),
    SetupDetectHeuristicParent(SetupDetectHeuristicParentReq),
    ProcessHeuristic(ProcessHeuristicReq),
    ProcessDissectPacket(ProcessDissectPacketReq),
    ResultGetProtocol(ResultGetProtocolReq),
    ResultGetInfo(ResultGetInfoReq),
    ResultGetFieldsCount(ResultGetFieldsCountReq),
    ResultGetField(ResultGetFieldReq),
    ResultRelease(ResultReleaseReq),
    InvalidMessage(String),
}

/// Converts a ZMQ message into a ZmqCommandReq
impl TryFrom<ZmqMessage> for ZmqCommandReq {
    type Error = WiregoError;

    fn try_from(zmq_message: ZmqMessage) -> Result<Self, Self::Error> {
        fn check_number_of_frames(
            zmq_message: &ZmqMessage,
            expected: usize,
        ) -> Result<(), WiregoError> {
            if zmq_message.len() != expected {
                return Err(WiregoError::ParseError(format!(
                    "Expected {} frames, got {}. Command: {}",
                    expected,
                    zmq_message.len(),
                    parse_nth_frame_as_string(0, &zmq_message)
                        .expect("At this point frame 0 should already exist"),
                )));
            }
            Ok(())
        }

        let command: String = parse_nth_frame_as_string(0, &zmq_message)?;

        match command.to_string().as_bytes() {
            b"utility_ping\x00" => {
                check_number_of_frames(&zmq_message, 1)?;
                Ok(ZmqCommandReq::UtilityPing(UtilityPingReq {}))
            }
            b"utility_get_version\x00" => {
                check_number_of_frames(&zmq_message, 1)?;
                Ok(ZmqCommandReq::UtilityGetVersion(UtilityGetVersionReq {}))
            }
            b"setup_get_plugin_name\x00" => {
                check_number_of_frames(&zmq_message, 1)?;
                Ok(ZmqCommandReq::SetupGetPluginName(SetupGetPluginNameReq {}))
            }
            b"setup_get_plugin_filter\x00" => {
                check_number_of_frames(&zmq_message, 1)?;
                Ok(ZmqCommandReq::SetupGetPluginFilter(
                    SetupGetPluginFilterReq {},
                ))
            }
            b"setup_get_fields_count\x00" => {
                check_number_of_frames(&zmq_message, 1)?;
                Ok(ZmqCommandReq::SetupGetFieldsCount(
                    SetupGetFieldsCountReq {},
                ))
            }
            b"setup_get_field\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let index: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::SetupGetField(SetupGetFieldReq { index }))
            }
            b"setup_detect_int\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let index: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::SetupDetectInt(SetupDetectIntReq { index }))
            }
            b"setup_detect_string\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let index: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::SetupDetectString(SetupDetectStringReq {
                    index,
                }))
            }
            b"setup_detect_heuristic_parent\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let index: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::SetupDetectHeuristicParent(
                    SetupDetectHeuristicParentReq { index },
                ))
            }
            b"process_heuristic\x00" => {
                check_number_of_frames(&zmq_message, 6)?;
                let packet_number: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                let src: String = parse_nth_frame_as_string(2, &zmq_message)?;
                let dst: String = parse_nth_frame_as_string(3, &zmq_message)?;
                let layer: String = parse_nth_frame_as_string(4, &zmq_message)?;
                let data: Vec<u8> = zmq_message
                    .get(5)
                    .ok_or_else(|| WiregoError::ParseError("Data frame not found".to_string()))?
                    .to_vec();

                Ok(ZmqCommandReq::ProcessHeuristic(ProcessHeuristicReq {
                    packet_number,
                    src,
                    dst,
                    layer,
                    data,
                }))
            }
            b"process_dissect_packet\x00" => {
                check_number_of_frames(&zmq_message, 6)?;
                let packet_number: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                let src: String = parse_nth_frame_as_string(2, &zmq_message)?;
                let dst: String = parse_nth_frame_as_string(3, &zmq_message)?;
                let layer: String = parse_nth_frame_as_string(4, &zmq_message)?;
                let data: Vec<u8> = zmq_message
                    .get(5)
                    .ok_or_else(|| WiregoError::ParseError("Data frame not found".to_string()))?
                    .to_vec();
                Ok(ZmqCommandReq::ProcessDissectPacket(
                    ProcessDissectPacketReq {
                        packet_number,
                        src,
                        dst,
                        layer,
                        data,
                    },
                ))
            }
            b"result_get_protocol\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let dissect_handler: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::ResultGetProtocol(ResultGetProtocolReq {
                    dissect_handler,
                }))
            }
            b"result_get_info\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let dissect_handler: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::ResultGetInfo(ResultGetInfoReq {
                    dissect_handler,
                }))
            }
            b"result_get_fields_count\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let dissect_handler: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::ResultGetFieldsCount(
                    ResultGetFieldsCountReq { dissect_handler },
                ))
            }
            b"result_get_field\x00" => {
                check_number_of_frames(&zmq_message, 3)?;
                let dissect_handler: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                let index: u32 = parse_nth_frame_as_numeric(2, &zmq_message)?;
                Ok(ZmqCommandReq::ResultGetField(ResultGetFieldReq {
                    dissect_handler,
                    index,
                }))
            }
            b"result_release\x00" => {
                check_number_of_frames(&zmq_message, 2)?;
                let dissect_handler: u32 = parse_nth_frame_as_numeric(1, &zmq_message)?;
                Ok(ZmqCommandReq::ResultRelease(ResultReleaseReq {
                    dissect_handler,
                }))
            }
            _ => Ok(ZmqCommandReq::InvalidMessage(command)),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ZmqCommandResp {
    UtilityPing(UtilityPingResp),
    UtilityGetVersion(UtilityGetVersionResp),
    SetupGetPluginName(SetupGetPluginNameResp),
    SetupGetPluginFilter(SetupGetPluginFilterResp),
    SetupGetFieldsCount(SetupGetFieldsCountResp),
    SetupGetField(SetupGetFieldResp),
    SetupDetectInt(SetupDetectIntResp),
    SetupDetectString(SetupDetectStringResp),
    SetupDetectHeuristicParent(SetupDetectHeuristicParentResp),
    ProcessHeuristic(ProcessHeuristicResp),
    ProcessDissectPacket(ProcessDissectPacketResp),
    ResultGetProtocol(ResultGetProtocolResp),
    ResultGetInfo(ResultGetInfoResp),
    ResultGetFieldsCount(ResultGetFieldsCountResp),
    ResultGetField(ResultGetFieldResp),
    ResultRelease(ResultReleaseResp),
    Failure,
}

/// Converts a ZmqCommandReq into a ZMQ message
impl From<ZmqCommandResp> for ZmqMessage {
    fn from(zmq_command_resp: ZmqCommandResp) -> Self {
        let mut frames: Vec<Bytes> = vec![];

        match zmq_command_resp {
            ZmqCommandResp::UtilityPing(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
            }
            ZmqCommandResp::UtilityGetVersion(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.major));
                frames.push(Bytes::copy_from_slice(&resp.minor));
            }
            ZmqCommandResp::SetupGetPluginName(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.plugin_name + "\x00"));
            }
            ZmqCommandResp::SetupGetPluginFilter(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.plugin_filter + "\x00"));
            }
            ZmqCommandResp::SetupGetFieldsCount(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.fields_count.to_le_bytes()));
            }
            ZmqCommandResp::SetupGetField(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.wirego_field_id.to_le_bytes()));
                frames.push(Bytes::from(resp.field_name + "\x00"));
                frames.push(Bytes::from(resp.field_filter + "\x00"));

                let field_display_mode = (resp.field_display_mode as u32).to_le_bytes();
                let field_value_type = (resp.field_value_type as u32).to_le_bytes();
                frames.push(Bytes::copy_from_slice(&field_value_type));
                frames.push(Bytes::copy_from_slice(&field_display_mode));
            }
            ZmqCommandResp::SetupDetectInt(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.filter_name + "\x00"));
                frames.push(Bytes::copy_from_slice(&resp.filter_value.to_le_bytes()));
            }
            ZmqCommandResp::SetupDetectString(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.filter_name + "\x00"));
                frames.push(Bytes::from(resp.filter_value + "\x00"));
            }
            ZmqCommandResp::SetupDetectHeuristicParent(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.plugin_detection_heuristic_parent + "\x00"));
            }
            ZmqCommandResp::ProcessDissectPacket(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.dissect_handler.to_le_bytes()));
            }
            ZmqCommandResp::ProcessHeuristic(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.detection_result));
            }
            ZmqCommandResp::ResultGetProtocol(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.protocol_column_name + "\x00"));
            }
            ZmqCommandResp::ResultGetInfo(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::from(resp.protocol_column_info + "\x00"));
            }
            ZmqCommandResp::ResultGetFieldsCount(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.fields_count.to_le_bytes()));
            }
            ZmqCommandResp::ResultGetField(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
                frames.push(Bytes::copy_from_slice(&resp.parent_idx.to_le_bytes()));
                frames.push(Bytes::copy_from_slice(&resp.wirego_field_id.to_le_bytes()));
                frames.push(Bytes::copy_from_slice(&resp.offset.to_le_bytes()));
                frames.push(Bytes::copy_from_slice(&resp.length.to_le_bytes()));
            }
            ZmqCommandResp::ResultRelease(resp) => {
                frames.push(Bytes::copy_from_slice(&resp.command_status));
            }
            ZmqCommandResp::Failure => {
                frames.push(Bytes::copy_from_slice(WIREGO_RESPONSE_FAILURE));
            }
        }

        match ZmqMessage::try_from(frames) {
            Ok(zmq_message) => zmq_message,
            Err(_) => {
                // This part should never happen, but if it does, we create a failure message
                // to avoid crashing the Wirego Bridge.
                ZmqMessage::from(Vec::<u8>::from(WIREGO_RESPONSE_FAILURE))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use zeromq::ZmqMessage;

    #[test]
    fn test_try_from_zmq_message_utility_ping() {
        let zmq_message = ZmqMessage::from("utility_ping\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_zmq_message_utility_get_version() {
        let zmq_message = ZmqMessage::from("utility_get_version\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_zmq_message_setup_get_plugin_name() {
        let zmq_message = ZmqMessage::from("setup_get_plugin_name\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_zmq_message_setup_get_plugin_filter() {
        let zmq_message = ZmqMessage::from("setup_get_plugin_filter\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_zmq_message_setup_get_fields_count() {
        let zmq_message = ZmqMessage::from("setup_get_fields_count\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_from_zmq_message_setup_get_field() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("setup_get_field\x00"),          // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // index
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::SetupGetField(SetupGetFieldReq { index: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_setup_detect_int() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("setup_detect_int\x00"),         // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // index
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::SetupDetectInt(SetupDetectIntReq { index: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_setup_detect_string() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("setup_detect_string\x00"),      // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // index
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::SetupDetectString(SetupDetectStringReq { index: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_setup_detect_heuristic_parent() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("setup_detect_heuristic_parent\x00"), // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()),      // index
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::SetupDetectHeuristicParent(SetupDetectHeuristicParentReq { index: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_process_heuristic() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("process_heuristic\x00"),        // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // packet_number
            Bytes::from("src"),                          // src
            Bytes::from("dst"),                          // dst
            Bytes::from("layer"),                        // layer
            Bytes::copy_from_slice(&[1, 2, 3]),          // data
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());

        if let ZmqCommandReq::ProcessHeuristic(req) = result.unwrap() {
            assert_eq!(req.packet_number, 5);
            assert_eq!(req.src, "src".to_string());
            assert_eq!(req.dst, "dst".to_string());
            assert_eq!(req.layer, "layer".to_string());
            assert_eq!(req.data, vec![1, 2, 3]);
        } else {
            panic!("Result does not match expected variant");
        }
    }

    #[test]
    fn test_try_from_zmq_message_process_dissect_packet() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("process_dissect_packet\x00"),   // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // packet_number
            Bytes::from("src"),                          // src
            Bytes::from("dst"),                          // dst
            Bytes::from("layer"),                        // layer
            Bytes::copy_from_slice(&[1, 2, 3]),          // data
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());

        if let ZmqCommandReq::ProcessDissectPacket(req) = result.unwrap() {
            assert_eq!(req.packet_number, 5);
            assert_eq!(req.src, "src".to_string());
            assert_eq!(req.dst, "dst".to_string());
            assert_eq!(req.layer, "layer".to_string());
            assert_eq!(req.data, vec![1, 2, 3]);
        } else {
            panic!("Result does not match expected variant");
        }
    }

    #[test]
    fn test_try_from_zmq_message_result_get_protocol() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("result_get_protocol\x00"),      // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // dissect_handler
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::ResultGetProtocol(ResultGetProtocolReq { dissect_handler: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_result_get_info() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("result_get_info\x00"),          // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // dissect_handler
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::ResultGetInfo(ResultGetInfoReq { dissect_handler: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_result_get_fields_count() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("result_get_fields_count\x00"),  // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // dissect_handler
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::ResultGetFieldsCount(ResultGetFieldsCountReq { dissect_handler: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_result_get_field() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("result_get_field\x00"),          // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()),  // dissect_handler
            Bytes::copy_from_slice(&10u32.to_le_bytes()), // index
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::ResultGetField(ResultGetFieldReq {
                dissect_handler: 5,
                index: 10
            })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_result_release() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("result_release\x00"),           // command
            Bytes::copy_from_slice(&5u32.to_le_bytes()), // dissect_handler
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ZmqCommandReq::ResultRelease(ResultReleaseReq { dissect_handler: 5 })
        ));
    }

    #[test]
    fn test_try_from_zmq_message_invalid_message() {
        let zmq_message = ZmqMessage::from("invalid_command\x00");
        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ZmqCommandReq::InvalidMessage(_)));
    }

    #[test]
    fn test_try_from_zmq_message_utility_ping_with_wrong_number_of_frames() {
        let frames: Vec<Bytes> = vec![
            Bytes::from("utility_ping\x00"), // command
            Bytes::copy_from_slice(&[1]),    // extra frame
        ];
        let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZMQ message");

        let result: Result<ZmqCommandReq, WiregoError> = zmq_message.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_from_zmq_command_resp_utility_ping() {
        let resp = ZmqCommandResp::UtilityPing(UtilityPingResp {
            command_status: [15],
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 1);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
    }

    #[test]
    fn test_from_zmq_command_resp_utility_get_version() {
        let resp = ZmqCommandResp::UtilityGetVersion(UtilityGetVersionResp {
            command_status: [15],
            major: [1],
            minor: [2],
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 3);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![1]);
        assert_eq!(zmq_message.get(2).unwrap().to_owned(), vec![2]);
    }

    #[test]
    fn test_from_zmq_command_resp_setup_get_plugin_name() {
        let resp = ZmqCommandResp::SetupGetPluginName(SetupGetPluginNameResp {
            command_status: [15],
            plugin_name: "plugin_name".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"plugin_name\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_setup_get_plugin_filter() {
        let resp = ZmqCommandResp::SetupGetPluginFilter(SetupGetPluginFilterResp {
            command_status: [15],
            plugin_filter: "plugin_filter".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"plugin_filter\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_setup_get_fields_count() {
        let resp = ZmqCommandResp::SetupGetFieldsCount(SetupGetFieldsCountResp {
            command_status: [15],
            fields_count: 5,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![5, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_setup_get_field() {
        let resp = ZmqCommandResp::SetupGetField(SetupGetFieldResp {
            command_status: [15],
            wirego_field_id: 5,
            field_name: "field_name".to_string(),
            field_filter: "field_filter".to_string(),
            field_value_type: ValueType::Int8,
            field_display_mode: DisplayMode::Hexadecimal,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 6);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![5, 0, 0, 0]);
        assert_eq!(
            zmq_message.get(2).unwrap().to_owned(),
            b"field_name\x00".to_vec()
        );
        assert_eq!(
            zmq_message.get(3).unwrap().to_owned(),
            b"field_filter\x00".to_vec()
        );
        assert_eq!(zmq_message.get(4).unwrap().to_owned(), vec![4, 0, 0, 0]);
        assert_eq!(zmq_message.get(5).unwrap().to_owned(), vec![3, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_setup_detect_int() {
        let resp = ZmqCommandResp::SetupDetectInt(SetupDetectIntResp {
            command_status: [15],
            filter_name: "filter_name".to_string(),
            filter_value: 5,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 3);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"filter_name\x00".to_vec()
        );
        assert_eq!(zmq_message.get(2).unwrap().to_owned(), vec![5, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_setup_detect_string() {
        let resp = ZmqCommandResp::SetupDetectString(SetupDetectStringResp {
            command_status: [15],
            filter_name: "filter_name".to_string(),
            filter_value: "filter_value".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 3);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"filter_name\x00".to_vec()
        );
        assert_eq!(
            zmq_message.get(2).unwrap().to_owned(),
            b"filter_value\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_setup_detect_heuristic_parent() {
        let resp = ZmqCommandResp::SetupDetectHeuristicParent(SetupDetectHeuristicParentResp {
            command_status: [15],
            plugin_detection_heuristic_parent: "plugin_detection_heuristic_parent".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"plugin_detection_heuristic_parent\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_process_dissect_packet() {
        let resp = ZmqCommandResp::ProcessDissectPacket(ProcessDissectPacketResp {
            command_status: [15],
            dissect_handler: 5,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![5, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_process_heuristic() {
        let resp = ZmqCommandResp::ProcessHeuristic(ProcessHeuristicResp {
            command_status: [15],
            detection_result: [1],
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![1]);
    }

    #[test]
    fn test_from_zmq_command_resp_result_get_protocol() {
        let resp = ZmqCommandResp::ResultGetProtocol(ResultGetProtocolResp {
            command_status: [15],
            protocol_column_name: "protocol_column_name".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"protocol_column_name\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_result_get_info() {
        let resp = ZmqCommandResp::ResultGetInfo(ResultGetInfoResp {
            command_status: [15],
            protocol_column_info: "protocol_column_info".to_string(),
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            b"protocol_column_info\x00".to_vec()
        );
    }

    #[test]
    fn test_from_zmq_command_resp_result_get_fields_count() {
        let resp = ZmqCommandResp::ResultGetFieldsCount(ResultGetFieldsCountResp {
            command_status: [15],
            fields_count: 5,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 2);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(zmq_message.get(1).unwrap().to_owned(), vec![5, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_result_get_field() {
        let resp = ZmqCommandResp::ResultGetField(ResultGetFieldResp {
            command_status: [15],
            parent_idx: -1,
            wirego_field_id: 5,
            offset: 10,
            length: 20,
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 5);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
        assert_eq!(
            zmq_message.get(1).unwrap().to_owned(),
            vec![255, 255, 255, 255]
        );
        assert_eq!(zmq_message.get(2).unwrap().to_owned(), vec![5, 0, 0, 0]);
        assert_eq!(zmq_message.get(3).unwrap().to_owned(), vec![10, 0, 0, 0]);
        assert_eq!(zmq_message.get(4).unwrap().to_owned(), vec![20, 0, 0, 0]);
    }

    #[test]
    fn test_from_zmq_command_resp_result_release() {
        let resp = ZmqCommandResp::ResultRelease(ResultReleaseResp {
            command_status: [15],
        });
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 1);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), vec![15]);
    }

    #[test]
    fn test_from_zmq_command_resp_failure() {
        let resp = ZmqCommandResp::Failure;
        let zmq_message: ZmqMessage = resp.into();
        assert_eq!(zmq_message.len(), 1);
        assert_eq!(zmq_message.get(0).unwrap().to_owned(), "\x00");
    }
}
