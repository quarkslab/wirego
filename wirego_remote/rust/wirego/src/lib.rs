mod error;
pub mod types;
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

/// Wirego Major API version that is used to communicate with the Wirego Bridge.
/// This version is hardcoded and if there is a version mismatch, the Wirego Bridge
/// will not be able to communicate with the Wirego Remote.
const WIREGO_API_VERSION_MAJOR: &[u8; 1] = b"\x02";

/// Wirego Minor API version that is used to communicate with the Wirego Bridge.
/// This version is hardcoded and if there is a version mismatch, the Wirego Bridge
/// will not be able to communicate with the Wirego Remote.
const WIREGO_API_VERSION_MINOR: &[u8; 1] = b"\x00";

/// WiregoListener is a trait that should be implemented by the user to provide
/// the dissecting logic for Wireshark packets. All methods are used for internal
/// communication with the Wirego Bridge and should not be called directly.
pub trait WiregoListener: Send {
    /// get_name returns the name of the plugin that is used to identify the
    /// plugin in the Wirego Bridge. This name is used to display the plugin name
    /// in the Wirego Bridge and should be unique for each plugin. An example
    /// of a plugin name could be "eCPRI 2.0".
    fn get_name(&self) -> String;

    /// get_filter returns the filter that is used to identify the plugin in the
    /// Wirego Bridge. This filter is used to display the plugin name in the
    /// Wirego Bridge and should be unique for each plugin. An example of a plugin
    /// filter could be "ecpri".
    fn get_filter(&self) -> String;

    /// get_fields returns the fields that are decoded by the plugin.
    fn get_fields(&self) -> Vec<types::WiresharkField>;

    /// get_detection_filters returns the detection filters that are used to
    /// filter the packets that are processed by the plugin.
    fn get_detection_filters(&self) -> Vec<types::DetectionFilter>;

    /// get_detection_heuristics_parents returns the detection heuristics parents
    /// that are used to filter the packets that are processed by the plugin.
    fn get_detection_heuristics_parents(&self) -> Vec<String>;

    /// detection_heuristic is a method that is called by the Wirego Bridge to
    /// determine if the packet should be processed by the plugin. This method
    /// should return true if the packet should be processed by the plugin and
    /// false if the packet should not be processed by the plugin.
    fn detection_heuristic(
        &self,
        packet_number: u32,
        src: String,
        dst: String,
        layer: String,
        packet_data: &[u8],
    ) -> bool;

    /// dissect_packet is a method that is called by the Wirego Bridge to dissect
    /// the packet. This method should return a dissected packet that contains
    /// the dissected fields.
    fn dissect_packet(
        &self,
        packet_number: u32,
        src: String,
        dst: String,
        layer: String,
        packet_data: &[u8],
    ) -> types::DissectResult;
}

pub struct Wirego {
    /// ZMQ Rep Socket that connects to the Wirego Bridge
    zmq_socket: zeromq::RepSocket,
    /// Wirego listener instance
    wirego_listener: Box<dyn WiregoListener>,
    /// Cache for storing dissected packets to speed up the plugin
    cache: std::collections::HashMap<u32, types::DissectResultFlattenEntry>,
    /// Set of all diefined field IDs for a quick access
    wirego_field_ids: std::collections::HashSet<u32>,
    /// Fetched plugin name from the WiregoListener for quicker access
    plugin_name: String,
    /// Fetched plugin filter from the WiregoListener for quicker access
    plugin_filter: String,
    /// Fetched plugin fields from the WiregoListener for quicker access
    plugin_fields: Vec<types::WiresharkField>,
    /// Fetched plugin detection filters from the WiregoListener for quicker access
    plugin_detection_filters: Vec<types::DetectionFilter>,
    /// Fetched plugin detection heuristics parents from the WiregoListener for quicker access
    plugin_detection_heuristics_parents: Vec<String>,
}

/// Wirego is the main part of the Wirego Remote that allow to communicate with
/// the Wirego Bridge. It is responsible for handling all ZMQ messages from
/// Wirego Bridge and responding with appropriate messages.
impl Wirego {
    /// Creates a new Wirego instance
    pub async fn new(
        zmq_endpoint: &str,
        wirego_listener: Box<dyn WiregoListener + Send>,
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

    /// Starts the Wirego listener and listens for incoming ZMQ messages
    /// from the Wirego Bridge. That is the main loop of the Wirego Remote.
    pub async fn listen(&mut self) -> Result<(), WiregoError> {
        loop {
            let received_message = zmq_utils::receive_zmq_message(&mut self.zmq_socket).await?;
            let wirego_zmq_command = ZmqCommandReq::try_from(received_message);
            if wirego_zmq_command.is_err() {
                eprintln!(
                    "Failed to parse ZMQ message: {:?}",
                    wirego_zmq_command.err()
                );
                let zmq_response: ZmqMessage = self.create_failure_response();
                send_zmq_message(&mut self.zmq_socket, zmq_response).await?;
                continue;
            }

            let result = self
                .handle_wirego_zmq_command(wirego_zmq_command.unwrap())
                .await;

            if result.is_err() {
                return Err(result.err().unwrap());
            }
        }
    }

    /// Creates a failure response message just to avoid duplicating the code.
    fn create_failure_response(&self) -> ZmqMessage {
        ZmqCommandResp::Failure
            .try_into()
            .expect("Failed to create failure response")
    }

    /// Handles the incoming ZMQ command from the Wirego Bridge.
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
                .try_into()
                .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::UtilityGetVersion(_utility_get_version) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::UtilityGetVersion(UtilityGetVersionResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        major: WIREGO_API_VERSION_MAJOR.clone(),
                        minor: WIREGO_API_VERSION_MINOR.clone(),
                    })
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetPluginName(_setup_get_plugin_name) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetPluginName(SetupGetPluginNameResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_name: self.plugin_name.clone(),
                    })
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetPluginFilter(_setup_get_plugin_filter) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetPluginFilter(SetupGetPluginFilterResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_filter: self.plugin_filter.clone(),
                    })
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::SetupGetFieldsCount(_setup_get_fields_count) => {
                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupGetFieldsCount(SetupGetFieldsCountResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        fields_count: self.plugin_fields.len() as u32,
                    })
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

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

                    let zmq_response: ZmqMessage = self.create_failure_response();
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
                .try_into()
                .unwrap_or_else(|_| self.create_failure_response());

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

                    let zmq_response: ZmqMessage = self.create_failure_response();
                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_filter = &self.plugin_detection_filters[index];
                match detection_filter {
                    types::DetectionFilter::Int(detection_filter_int) => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::SetupDetectInt(SetupDetectIntResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                filter_value: detection_filter_int.filter_value as u32,
                                filter_name: detection_filter_int.filter_name.clone(),
                            })
                            .try_into()
                            .unwrap_or_else(|_| self.create_failure_response());

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                    _ => {
                        eprintln!(
                            "Unsupported detection filter type for SetupDetectInt: {:?}",
                            detection_filter
                        );
                        let zmq_response: ZmqMessage = self.create_failure_response();
                        return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
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

                    let zmq_response: ZmqMessage = self.create_failure_response();
                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_filter = &self.plugin_detection_filters[index];
                match detection_filter {
                    types::DetectionFilter::String(detection_filter_string) => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::SetupDetectString(SetupDetectStringResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                filter_value: detection_filter_string.filter_value.clone(),
                                filter_name: detection_filter_string.filter_name.clone(),
                            })
                            .try_into()
                            .unwrap_or_else(|_| self.create_failure_response());

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                    _ => {
                        eprintln!(
                            "Unsupported detection filter type for SetupDetectString: {:?}",
                            detection_filter
                        );
                        let zmq_response: ZmqMessage = self.create_failure_response();
                        return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
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

                    let zmq_response: ZmqMessage = self.create_failure_response();
                    return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                }

                let detection_heuristic_parent = &self.plugin_detection_heuristics_parents[index];

                let zmq_response: ZmqMessage =
                    ZmqCommandResp::SetupDetectHeuristicParent(SetupDetectHeuristicParentResp {
                        command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                        plugin_detection_heuristic_parent: detection_heuristic_parent.clone(),
                    })
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ProcessHeuristic(process_heuristic) => {
                match self.wirego_listener.detection_heuristic(
                    process_heuristic.packet_number,
                    process_heuristic.src,
                    process_heuristic.dst,
                    process_heuristic.layer,
                    &process_heuristic.data,
                ) {
                    true => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::ProcessHeuristic(ProcessHeuristicResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                detection_result: WIREGO_RESPONSE_SUCCESS.clone(),
                            })
                            .try_into()
                            .unwrap_or_else(|_| self.create_failure_response());

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                    false => {
                        let zmq_response: ZmqMessage =
                            ZmqCommandResp::ProcessHeuristic(ProcessHeuristicResp {
                                command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                                detection_result: WIREGO_RESPONSE_FAILURE.clone(),
                            })
                            .try_into()
                            .unwrap_or_else(|_| self.create_failure_response());

                        send_zmq_message(&mut self.zmq_socket, zmq_response).await
                    }
                }
            }
            ZmqCommandReq::ProcessDissectPacket(process_dissect_packet) => {
                if let Some(_dissected_packet) =
                    self.cache.get(&process_dissect_packet.packet_number)
                {
                    let zmq_response: ZmqMessage =
                        ZmqCommandResp::ProcessDissectPacket(ProcessDissectPacketResp {
                            command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                            dissect_handler: process_dissect_packet.packet_number,
                        })
                        .try_into()
                        .unwrap_or_else(|_| self.create_failure_response());

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
                        let zmq_response: ZmqMessage = self.create_failure_response();
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
                        let zmq_response: ZmqMessage = self.create_failure_response();
                        return send_zmq_message(&mut self.zmq_socket, zmq_response).await;
                    }
                }

                let mut flattened_fields = types::DissectResultFlattenEntry {
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
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetProtocol(result_get_protocol) => {
                let dissect_handler = result_get_protocol.dissect_handler;
                // TODO: instead of ok_or_else, the Failure message should be sent
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
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetInfo(result_get_info) => {
                let dissect_handler = result_get_info.dissect_handler;
                // TODO: instead of ok_or_else, the Failure message should be sent
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
                .try_into()
                .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetFieldsCount(result_get_fields_count) => {
                let dissect_handler = result_get_fields_count.dissect_handler;
                // TODO: instead of ok_or_else, the Failure message should be sent
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
                    .try_into()
                    .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultGetField(result_get_field) => {
                let dissect_handler = result_get_field.dissect_handler;
                // TODO: instead of ok_or_else, the Failure message should be sent
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

                    let zmq_response: ZmqMessage = self.create_failure_response();
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
                .try_into()
                .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::ResultRelease(result_release) => {
                let dissect_handler = result_release.dissect_handler;
                self.cache.remove(&dissect_handler);

                let zmq_response: ZmqMessage = ZmqCommandResp::ResultRelease(ResultReleaseResp {
                    command_status: WIREGO_RESPONSE_SUCCESS.clone(),
                })
                .try_into()
                .unwrap_or_else(|_| self.create_failure_response());

                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
            ZmqCommandReq::InvalidMessage(invalid_message) => {
                eprintln!("Invalid message: {:?}", invalid_message);
                let zmq_response: ZmqMessage = self.create_failure_response();
                send_zmq_message(&mut self.zmq_socket, zmq_response).await
            }
        }
    }

    /// Recursively adds fields to the flattened fields list.
    fn add_fields_recursively(
        &mut self,
        flattened_fields: &mut types::DissectResultFlattenEntry,
        parent_index: i64,
        dissected_field: &types::DissectField,
    ) {
        flattened_fields
            .dissected_fields
            .push(types::DissectResultFieldFlatten {
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
