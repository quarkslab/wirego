mod error;
mod zmq_commands;
mod zmq_utils;

use error::WiregoError;
use zeromq::ZmqMessage;
use zmq_commands::{
    ResultGetFieldResp, ResultGetFieldsCountResp, ResultGetInfoResp, ResultGetProtocolResp,
    ResultReleaseResp, ZmqCommandReq,
};

use crate::zmq_commands::*;
use crate::zmq_utils::send_zmq_message;

pub const WIREGO_API_VERSION_MAJOR: &[u8; 1] = b"\x02";
pub const WIREGO_API_VERSION_MINOR: &[u8; 1] = b"\x00";

#[derive(Debug, Copy, Clone)]
pub enum ValueType {
    None = 0x01,
    Bool = 0x02,
    Uint8 = 0x03,
    Int8 = 0x04,
    Uint16 = 0x05,
    Int16 = 0x06,
    Uint32 = 0x07,
    Int32 = 0x08,
    CString = 0x09,
    String = 0x10,
}

#[derive(Debug, Copy, Clone)]
pub enum DisplayMode {
    None = 0x01,
    Decimal = 0x02,
    Hexadecimal = 0x03,
}

#[derive(Debug, Clone)]
pub struct DetectionFilterInt {
    pub filter_name: String,
    pub filter_value: i32,
}

#[derive(Debug, Clone)]
pub struct DetectionFilterString {
    pub filter_name: String,
    pub filter_value: String,
}

/// DetectionFilter defines a detection filter, e.g. tcp.port = 12
#[derive(Debug, Clone)]
pub enum DetectionFilter {
    Int(DetectionFilterInt),
    String(DetectionFilterString),
}

/// WiresharkField holds the description of a field
#[derive(Debug, Clone)]
pub struct WiresharkField {
    pub wirego_field_id: u32,
    pub field_name: String,
    pub filter: String,
    pub value_type: ValueType,
    pub display_mode: DisplayMode,
}

/// DissectField holds a dissection result field (refers to a WiresharkField and specifies offset+length)
#[derive(Debug, Clone)]
pub struct DissectField {
    /// Wirego field ID
    pub wirego_field_id: u32,
    /// Field offset in the packet
    pub offset: i64,
    /// Field length in the packet
    pub length: i64,
    /// Sub fields (optional)
    pub sub_fields: Vec<DissectField>,
}

/// DissectResult holds a dissection result for a given packet
#[derive(Debug, Clone)]
pub struct DissectResult {
    /// Protocol column in Wireshark
    pub protocol_column_str: String,
    /// Info column in Wireshark
    pub protocol_info_str: String,
    /// List of dissected fields
    pub dissected_fields: Vec<DissectField>,
}

/// DissectResultFieldFlatten stores a given field from a dissection result
#[derive(Debug, Clone)]
pub struct DissectResultFieldFlatten {
    /// Index of the parent field (for nested fields)
    pub parent_index: i64,
    /// Wirego field ID
    pub wirego_field_id: u32,
    /// Field offset in the packet
    pub offset: i64,
    /// Field length in the packet
    pub length: i64,
}

/// DissectResultFlattenEntry stores a complete dissection result as a flat list
#[derive(Debug, Clone)]
pub struct DissectResultFlattenEntry {
    /// Protocol column for Wireshark
    pub protocol_column_str: String,
    /// Info column for Wireshark
    pub protocol_info_str: String,
    /// List of dissected fields for Wireshark
    pub dissected_fields: Vec<DissectResultFieldFlatten>,
}

pub trait WiregoListener {
    fn get_name(&self) -> String;
    fn get_filter(&self) -> String;
    fn get_fields(&self) -> Vec<WiresharkField>;
    fn get_detection_filters(&self) -> Vec<DetectionFilter>;
    fn get_detection_heuristics_parents(&self) -> Vec<String>;

    fn detection_heuristic(
        &self,
        packet_number: u32,
        src: String,
        dst: String,
        layer: String,
        packet_data: &[u8],
    ) -> bool;

    fn dissect_packet(
        &self,
        packet_number: u32,
        src: String,
        dst: String,
        layer: String,
        packet_data: &[u8],
    ) -> DissectResult;
}

pub struct Wirego {
    /// ZMQ Socket
    zmq_socket: zeromq::RepSocket,
    /// Wirego listener instance
    wirego_listener: Box<dyn WiregoListener>,
    /// Cache for storing dissected packets to speed up the plugin
    cache: std::collections::HashMap<u32, DissectResultFlattenEntry>,
    /// Set of all diefined field IDs for a quick access
    wirego_field_ids: std::collections::HashSet<u32>,
    /// Fetched plugin name from the WiregoListener
    plugin_name: String,
    /// Fetched plugin filter from the WiregoListener
    plugin_filter: String,
    /// Fetched plugin fields from the WiregoListener
    plugin_fields: Vec<WiresharkField>,
    /// Fetched plugin detection filters from the WiregoListener
    plugin_detection_filters: Vec<DetectionFilter>,
    /// Fetched plugin detection heuristics parents from the WiregoListener
    plugin_detection_heuristics_parents: Vec<String>,
}

impl Wirego {
    pub async fn new(
        zmq_endpoint: &str,
        wirego_listener: Box<dyn WiregoListener>,
    ) -> Result<Self, WiregoError> {
        let plugin_name = wirego_listener.get_name();
        let plugin_filter = wirego_listener.get_filter();
        let plugin_fields = wirego_listener.get_fields();
        let plugin_detection_filters = wirego_listener.get_detection_filters();
        let plugin_detection_heuristics_parents =
            wirego_listener.get_detection_heuristics_parents();

        Ok(Wirego {
            zmq_socket: zmq_utils::bind_zmq_socket(zmq_endpoint).await?,
            wirego_listener,
            cache: std::collections::HashMap::new(),
            wirego_field_ids: std::collections::HashSet::new(),
            plugin_name,
            plugin_filter,
            plugin_fields,
            plugin_detection_filters,
            plugin_detection_heuristics_parents,
        })
    }

    pub async fn listen(&mut self) -> Result<(), WiregoError> {
        loop {
            let received_message = zmq_utils::receive_zmq_message(&mut self.zmq_socket).await?;
            let wirego_zmq_command = ZmqCommandReq::try_from(received_message)?;
            let result = self.handle_wirego_zmq_command(wirego_zmq_command).await;

            if result.is_err() {
                return Err(result.err().unwrap());
            }
        }
    }

    async fn handle_wirego_zmq_command(
        &mut self,
        wirego_zmq_command: ZmqCommandReq,
    ) -> Result<(), WiregoError> {
        println!("Received command: {:?}", wirego_zmq_command);

        match wirego_zmq_command {
            ZmqCommandReq::UtilityPing(_utility_ping) => {
                let zmq_response: ZmqMessage = ZmqCommandResp::UtilityPing(UtilityPingResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                })
                .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::UtilityGetVersion(_utility_get_version) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::UtilityGetVersion(UtilityGetVersionResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        major: WIREGO_API_VERSION_MAJOR.clone(),
                        minor: WIREGO_API_VERSION_MINOR.clone(),
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetPluginName(_setup_get_plugin_name) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetPluginName(SetupGetPluginNameResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_name: self.plugin_name.clone(),
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetPluginFilter(_setup_get_plugin_filter) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetPluginFilter(SetupGetPluginFilterResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_filter: self.plugin_filter.clone(),
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetFieldsCount(_setup_get_fields_count) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetFieldsCount(SetupGetFieldsCountResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        fields_count: self.plugin_fields.len() as u32,
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetField(setup_get_field) => {
                let field_index = setup_get_field.index as usize;
                if field_index >= self.plugin_fields.len() {
                    eprintln!(
                        "Invalid field index: {}. Total fields: {}",
                        field_index,
                        self.plugin_fields.len()
                    );

                    let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;

                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let field = &self.plugin_fields[field_index];
                self.wirego_field_ids.insert(field.wirego_field_id);

                let zmq_response: ZmqMessage = ZmqCommandResp::SetupGetField(SetupGetFieldResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                    wirego_field_id: field.wirego_field_id,
                    field_name: field.field_name.clone(),
                    field_filter: field.filter.clone(),
                    field_value_type: field.value_type.clone(),
                    field_display_mode: field.display_mode.clone(),
                })
                .try_into()?;

                println!("Field from listener: {:?}", field);
                println!("Response: {:?}", zmq_response);
                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupDetectInt(setup_detect_int) => {
                let index = setup_detect_int.index as usize;
                if index >= self.plugin_detection_filters.len() {
                    eprintln!(
                        "Invalid detection filter index: {}. Total detection filters count: {}",
                        index,
                        self.plugin_detection_filters.len()
                    );

                    let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;

                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_filter = &self.plugin_detection_filters[index];
                match detection_filter {
                    DetectionFilter::Int(detection_filter_int) => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::SetupDetectInt(SetupDetectIntResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                filter_value: detection_filter_int.filter_value as u32,
                                filter_name: detection_filter_int.filter_name.clone(),
                            })
                            .try_into()?;

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                    _ => {
                        eprintln!(
                            "Unsupported detection filter type for SetupDetectInt: {:?}",
                            detection_filter
                        );
                        let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;
                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                }
            }
            ZmqCommandReq::SetupDetectString(setup_detect_string) => {
                let index = setup_detect_string.index as usize;
                if index >= self.plugin_detection_filters.len() {
                    eprintln!(
                        "Invalid detection filter index: {}. Total detection filters count: {}",
                        index,
                        self.plugin_detection_filters.len()
                    );

                    let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;

                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_filter = &self.plugin_detection_filters[index];
                match detection_filter {
                    DetectionFilter::String(detection_filter_string) => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::SetupDetectString(SetupDetectStringResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                filter_value: detection_filter_string.filter_value.clone(),
                                filter_name: detection_filter_string.filter_name.clone(),
                            })
                            .try_into()?;

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                    _ => {
                        eprintln!(
                            "Unsupported detection filter type for SetupDetectString: {:?}",
                            detection_filter
                        );
                        let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;
                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                }
            }
            ZmqCommandReq::SetupDetectHeuristicParent(setup_detect_heuristic_parent) => {
                let index = setup_detect_heuristic_parent.index as usize;
                if index >= self.plugin_detection_heuristics_parents.len() {
                    eprintln!(
                        "Invalid detection heuristic parent index: {}. Total detection heuristics parents count: {}",
                        index,
                        self.plugin_detection_heuristics_parents.len()
                    );

                    let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;
                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_heuristic_parent = &self.plugin_detection_heuristics_parents[index];

                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupDetectHeuristicParent(SetupDetectHeuristicParentResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_detection_heuristic_parent: detection_heuristic_parent.clone(),
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ProcessDissectPacket(process_dissect_packet) => {
                if let Some(dissected_packet) =
                    self.cache.get(&process_dissect_packet.packet_number)
                {
                    let zmq_response: ZmqMessage =
                        ZmqCommandResp::ProcessDissectPacket(ProcessDissectPacketResp {
                            command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                            dissect_handler: process_dissect_packet.packet_number,
                        })
                        .try_into()?;

                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let result = self.wirego_listener.dissect_packet(
                    process_dissect_packet.packet_number,
                    process_dissect_packet.src,
                    process_dissect_packet.dst,
                    process_dissect_packet.layer,
                    &process_dissect_packet.data,
                );

                for dissected_field in &result.dissected_fields {
                    println!("Dissected field: {:?}", dissected_field);
                    if dissected_field.offset >= process_dissect_packet.data.len() as i64 {
                        eprintln!(
                            "Invalid dissected field offset: {}. Packet length: {}",
                            dissected_field.offset,
                            process_dissect_packet.data.len()
                        );
                        let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;
                        return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                    }

                    if dissected_field.offset + dissected_field.length
                        > process_dissect_packet.data.len() as i64
                    {
                        eprintln!(
                            "Invalid dissected field length: {}. Packet length: {}",
                            dissected_field.length,
                            process_dissect_packet.data.len()
                        );
                        let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;
                        return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                    }
                }

                let mut flattened_fields = DissectResultFlattenEntry {
                    protocol_column_str: result.protocol_column_str,
                    protocol_info_str: result.protocol_info_str,
                    dissected_fields: vec![],
                };

                for dissected_field in &result.dissected_fields {
                    self.add_fields_recursively(
                        &mut flattened_fields,
                        -1,
                        &dissected_field.clone(),
                    );
                }

                self.cache.insert(
                    process_dissect_packet.packet_number,
                    flattened_fields.clone(),
                );
                println!("Current cache: {:?}", self.cache);

                let zmq_response: ZmqMessage =
                    ZmqCommandResp::ProcessDissectPacket(ProcessDissectPacketResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        dissect_handler: process_dissect_packet.packet_number,
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetProtocol(result_get_protocol) => {
                let dissect_handler = result_get_protocol.dissect_handler;
                let dissected_packet = self.cache.get(&dissect_handler).ok_or_else(|| {
                    WiregoError::ParseError(format!(
                        "Dissect handler {} not found in cache",
                        dissect_handler
                    ))
                })?;

                let protocol_column_name = dissected_packet.protocol_column_str.clone();
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::ResultGetProtocol(ResultGetProtocolResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        protocol_column_name,
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetInfo(result_get_info) => {
                let dissect_handler = result_get_info.dissect_handler;
                let dissected_packet = self.cache.get(&dissect_handler).ok_or_else(|| {
                    WiregoError::ParseError(format!(
                        "Dissect handler {} not found in cache",
                        dissect_handler
                    ))
                })?;

                let protocol_info_str = dissected_packet.protocol_info_str.clone();
                let zmq_response: ZmqMessage = ZmqCommandResp::ResultGetInfo(ResultGetInfoResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                    protocol_column_info: protocol_info_str,
                })
                .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultRelease(result_release) => {
                let dissect_handler = result_release.dissect_handler;
                self.cache.remove(&dissect_handler);

                let zmq_response: ZmqMessage = ZmqCommandResp::ResultRelease(ResultReleaseResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                })
                .try_into()?;
                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetFieldsCount(result_get_fields_count) => {
                let dissect_handler = result_get_fields_count.dissect_handler;
                let dissected_packet = self.cache.get(&dissect_handler).ok_or_else(|| {
                    WiregoError::ParseError(format!(
                        "Dissect handler {} not found in cache",
                        dissect_handler
                    ))
                })?;

                let fields_count = dissected_packet.dissected_fields.len() as u32;
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::ResultGetFieldsCount(ResultGetFieldsCountResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        fields_count,
                    })
                    .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetField(result_get_field) => {
                let dissect_handler = result_get_field.dissect_handler;
                let dissected_packet = self.cache.get(&dissect_handler).ok_or_else(|| {
                    WiregoError::ParseError(format!(
                        "Dissect handler {} not found in cache",
                        dissect_handler
                    ))
                })?;

                let field_index = result_get_field.index as usize;
                if field_index >= dissected_packet.dissected_fields.len() {
                    eprintln!(
                        "Invalid field index: {}. Total fields: {}",
                        field_index,
                        dissected_packet.dissected_fields.len()
                    );

                    let zmq_response: ZmqMessage = ZmqCommandResp::Failure.try_into()?;

                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let dissected_field = &dissected_packet.dissected_fields[field_index];
                let zmq_response: ZmqMessage = ZmqCommandResp::ResultGetField(ResultGetFieldResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                    parent_idx: dissected_field.parent_index as i32,
                    wirego_field_id: dissected_field.wirego_field_id,
                    offset: dissected_field.offset as u32,
                    length: dissected_field.length as u32,
                })
                .try_into()?;

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            _ => {
                todo!("Unknown command: {:?}", wirego_zmq_command);
            }
        }
    }

    fn add_fields_recursively(
        &mut self,
        flattened_fields: &mut DissectResultFlattenEntry,
        parent_index: i64,
        dissected_field: &DissectField,
    ) {
        flattened_fields
            .dissected_fields
            .push(DissectResultFieldFlatten {
                parent_index,
                wirego_field_id: dissected_field.wirego_field_id,
                offset: dissected_field.offset,
                length: dissected_field.length,
            });

        let new_parent_index = flattened_fields.dissected_fields.len() as i64 - 1;
        for sub_field in &dissected_field.sub_fields {
            self.add_fields_recursively(flattened_fields, new_parent_index, sub_field);
        }
    }
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
