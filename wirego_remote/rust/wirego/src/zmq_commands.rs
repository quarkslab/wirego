use crate::{
    DisplayMode, ValueType,
    error::WiregoError,
    zmq_utils::{parse_nth_frame_as_numeric, parse_nth_frame_as_string},
};
use bytes::Bytes;
use zeromq::ZmqMessage;

pub(crate) const WIREGO_RESPONSE_SUCCESS: &[u8; 1] = b"\x01";
pub(crate) const WIREGO_RESPONSE_FAILURE: &[u8; 1] = b"\x00";

#[derive(Debug, Clone)]
pub struct UtilityPingReq {}

#[derive(Debug, Clone)]
pub struct UtilityPingResp {
    pub command_status: [u8; 1],
}

#[derive(Debug, Clone)]
pub struct UtilityGetVersionReq {}

#[derive(Debug, Clone)]
pub struct UtilityGetVersionResp {
    pub command_status: [u8; 1],
    pub major: [u8; 1],
    pub minor: [u8; 1],
}

#[derive(Debug, Clone)]
pub struct SetupGetPluginNameReq {}

#[derive(Debug, Clone)]
pub struct SetupGetPluginNameResp {
    pub command_status: [u8; 1],
    pub plugin_name: String,
}

#[derive(Debug, Clone)]
pub struct SetupGetPluginFilterReq {}

#[derive(Debug, Clone)]
pub struct SetupGetPluginFilterResp {
    pub command_status: [u8; 1],
    pub plugin_filter: String,
}

#[derive(Debug, Clone)]
pub struct SetupGetFieldsCountReq {}

#[derive(Debug, Clone)]
pub struct SetupGetFieldsCountResp {
    pub command_status: [u8; 1],
    pub fields_count: u32,
}

#[derive(Debug, Clone)]
pub struct SetupGetFieldReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct SetupGetFieldResp {
    pub command_status: [u8; 1],
    pub wirego_field_id: u32,
    pub field_name: String,
    pub field_filter: String,
    pub field_value_type: ValueType,
    pub field_display_mode: DisplayMode,
}

#[derive(Debug, Clone)]
pub struct SetupDetectIntReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct SetupDetectIntResp {
    pub command_status: [u8; 1],
    pub filter_name: String,
    pub filter_value: u32,
}

#[derive(Debug, Clone)]
pub struct SetupDetectStringReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct SetupDetectStringResp {
    pub command_status: [u8; 1],
    pub filter_name: String,
    pub filter_value: String,
}

#[derive(Debug, Clone)]
pub struct SetupDetectHeuristicParentReq {
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct SetupDetectHeuristicParentResp {
    pub command_status: [u8; 1],
    pub plugin_detection_heuristic_parent: String,
}

#[derive(Debug, Clone)]
pub struct ProcessHeuristicReq {
    pub packet_number: u32,
    pub src: String,
    pub dst: String,
    pub layer: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProcessHeuristicResp {
    pub command_status: [u8; 1],
    pub detection_result: [u8; 1],
}

#[derive(Debug, Clone)]
pub struct ProcessDissectPacketReq {
    pub packet_number: u32,
    pub src: String,
    pub dst: String,
    pub layer: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProcessDissectPacketResp {
    pub command_status: [u8; 1],
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetProtocolReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetProtocolResp {
    pub command_status: [u8; 1],
    pub protocol_column_name: String,
}

#[derive(Debug, Clone)]
pub struct ResultGetInfoReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetInfoResp {
    pub command_status: [u8; 1],
    pub protocol_column_info: String,
}

#[derive(Debug, Clone)]
pub struct ResultGetFieldsCountReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetFieldsCountResp {
    pub command_status: [u8; 1],
    pub fields_count: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetFieldReq {
    pub dissect_handler: u32,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct ResultGetFieldResp {
    pub command_status: [u8; 1],
    pub parent_idx: i32,
    pub wirego_field_id: u32,
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub struct ResultReleaseReq {
    pub dissect_handler: u32,
}

#[derive(Debug, Clone)]
pub struct ResultReleaseResp {
    pub command_status: [u8; 1],
}

#[derive(Debug, Clone)]
pub enum ZmqCommandReq {
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
        // TODO: this function has to be refactored so that instead of returning the WiregoError
        // it returns a ZmqCommandReq::InvalidMessage with the error message. This way the
        // communication with WiregoBridge will not cause the main loop to exit.
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
pub enum ZmqCommandResp {
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
impl TryFrom<ZmqCommandResp> for ZmqMessage {
    type Error = WiregoError;

    fn try_from(zmq_command_resp: ZmqCommandResp) -> Result<Self, Self::Error> {
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

        let zmq_message = ZmqMessage::try_from(frames)
            .map_err(|_| WiregoError::InvalidMessage("Failed to create ZMQ message".to_string()))?;

        Ok(zmq_message)
    }
}
