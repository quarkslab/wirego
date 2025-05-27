use log::{LevelFilter, error, info};
use simple_logger::SimpleLogger;
use tokio;
use wirego::{Wirego, WiregoListener};

#[tokio::main]
async fn main() {
    // Instantiate a simple logger
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .with_module_level("wirego", LevelFilter::Warn)
        .init()
        .unwrap();

    info!("Wirego Minimal Example");
    info!("=========================");
    info!("This is a minimal example of a Wirego dissector.");

    // Create our listener
    let minimal_listener = Box::new(WiregoMinimalListener);
    info!("Listener name: {}", minimal_listener.get_name());

    // Instantiate Wirego with the listener
    let wirego = Wirego::new("ipc:///tmp/wirego0", minimal_listener).await;
    if wirego.is_err() {
        error!("Error: {}", wirego.err().unwrap());
        return;
    }

    let mut wirego = wirego.unwrap();

    // Start listening on given ZMQ socket
    if let Err(error) = wirego.listen().await {
        error!("Error: {}", error);
    };
}

struct WiregoMinimalListener;

// Define here enum identifiers, used to refer to a specific field
enum MinimalFieldId {
    Custom1 = 1,
    Custom2 = 2,
    CustomSubs = 3,
}

impl WiregoListener for WiregoMinimalListener {
    // This function shall return the plugin name
    fn get_name(&self) -> String {
        "Wirego Minimal Example".to_string()
    }

    // This function shall return the wireshark filter
    fn get_filter(&self) -> String {
        "wgminexample".to_string()
    }

    // get_fields returns the list of fields descriptor that we may eventually return when dissecting a packet payload
    fn get_fields(&self) -> Vec<wirego::types::WiresharkField> {
        vec![
            wirego::types::WiresharkField {
                wirego_field_id: MinimalFieldId::Custom1 as u32,
                field_name: "Custom1".to_string(),
                filter: "wgminexample.custom01".to_string(),
                value_type: wirego::types::ValueType::Uint8,
                display_mode: wirego::types::DisplayMode::Hexadecimal,
            },
            wirego::types::WiresharkField {
                wirego_field_id: MinimalFieldId::Custom2 as u32,
                field_name: "Custom2".to_string(),
                filter: "wgminexample.custom02".to_string(),
                value_type: wirego::types::ValueType::Uint16,
                display_mode: wirego::types::DisplayMode::Decimal,
            },
            wirego::types::WiresharkField {
                wirego_field_id: MinimalFieldId::CustomSubs as u32,
                field_name: "Custom with subfields".to_string(),
                filter: "wgminexample.custom_subs".to_string(),
                value_type: wirego::types::ValueType::Uint32,
                display_mode: wirego::types::DisplayMode::Hexadecimal,
            },
        ]
    }

    // get_detection_filters returns a wireshark filter that will select which packets
    // will be sent to your dissector for parsing.
    // Two types of filters can be defined: Integers (DetectionFilter::Int)
    // or Strings (DetectionFilter::String).
    fn get_detection_filters(&self) -> Vec<wirego::types::DetectionFilter> {
        vec![
            wirego::types::DetectionFilter::Int(wirego::types::DetectionFilterInt {
                filter_name: "udp.port".to_string(),
                filter_value: 137,
            }),
            wirego::types::DetectionFilter::String(wirego::types::DetectionFilterString {
                filter_name: "bluetooth.uuid".to_string(),
                filter_value: "1234".to_string(),
            }),
        ]
    }

    // get_detection_heuristics_parents returns a list of protocols on top of which detection heuristic should be called.
    fn get_detection_heuristics_parents(&self) -> Vec<String> {
        vec!["udp".to_string()]
    }

    // detection_heuristic applies an heuristic to identify the protocol.
    fn detection_heuristic(
        &self,
        _packet_number: u32,
        _src: String,
        _dst: String,
        _layer: String,
        packet: &[u8],
    ) -> bool {
        // All packets starting with 0x00 should be passed to our dissector (super advanced heuristic)
        packet.len() != 0 && packet[0] == 0x00
    }

    // dissect_packet provides the packet payload to be parsed.
    fn dissect_packet(
        &self,
        packet_number: u32,
        _src: String,
        _dst: String,
        _stack: String,
        packet: &[u8],
    ) -> wirego::types::DissectResult {
        let mut dissected_fields: Vec<wirego::types::DissectField> = vec![];

        // Add a few fields and refer to them using our own "internalId" - MinimalFieldId
        if packet.len() > 6 {
            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: MinimalFieldId::Custom1 as u32,
                offset: 0,
                length: 2,
                sub_fields: vec![],
            });

            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: MinimalFieldId::Custom2 as u32,
                offset: 2,
                length: 4,
                sub_fields: vec![],
            });
        }

        // Add a field with two sub field
        if packet.len() > 10 {
            let sub_field_1 = wirego::types::DissectField {
                wirego_field_id: MinimalFieldId::Custom1 as u32,
                offset: 6,
                length: 2,
                sub_fields: vec![],
            };

            let sub_field_2 = wirego::types::DissectField {
                wirego_field_id: MinimalFieldId::Custom2 as u32,
                offset: 8,
                length: 2,
                sub_fields: vec![],
            };

            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: MinimalFieldId::CustomSubs as u32,
                offset: 6,
                length: 4,
                sub_fields: vec![sub_field_1, sub_field_2],
            });
        }

        wirego::types::DissectResult {
            protocol_column_str: "Minimal protocol example".to_string(), // It will appear in the protocol column
            protocol_info_str: format!("Info from packet #{}", packet_number), // It will appear in the info column
            dissected_fields,
        }
    }
}
