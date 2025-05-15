use wirego::{Wirego, WiregoListener};
use tokio;

#[tokio::main]
async fn main() {
    println!("Wirego Minimal Example");
    println!("=========================");
    println!("This is a minimal example of a Wirego dissector.");

    let minimal_listener = Box::new(WiregoMinimalListener);
    println!("minimal listener name: {}", minimal_listener.get_name());

    let wirego = Wirego::new("ipc:///tmp/wirego2", minimal_listener).await;
    if wirego.is_err() {
        eprintln!("Error: {}", wirego.err().unwrap());
        return;
    }

    let mut wirego = wirego.unwrap();
    if let Err(error) = wirego.listen().await {
        eprintln!("Error: {}", error);
    };
}

struct WiregoMinimalListener;

impl WiregoListener for WiregoMinimalListener {
    fn get_name(&self) -> String {
        "Wirego Minimal Example".to_string()
    }

    fn get_filter(&self) -> String {
        "wgminexample".to_string()
    }

    fn get_fields(&self) -> Vec<wirego::types::WiresharkField> {
        vec![
            wirego::types::WiresharkField {
                wirego_field_id: 1,
                field_name: "Custom1".to_string(),
                filter: "wgminexample.custom01".to_string(),
                value_type: wirego::types::ValueType::Uint8,
                display_mode: wirego::types::DisplayMode::Hexadecimal,
            },
            wirego::types::WiresharkField {
                wirego_field_id: 2,
                field_name: "Custom2".to_string(),
                filter: "wgminexample.custom02".to_string(),
                value_type: wirego::types::ValueType::Uint16,
                display_mode: wirego::types::DisplayMode::Decimal,
            },
            wirego::types::WiresharkField {
                wirego_field_id: 3,
                field_name: "Custom with subfields".to_string(),
                filter: "wgminexample.custom_subs".to_string(),
                value_type: wirego::types::ValueType::Uint32,
                display_mode: wirego::types::DisplayMode::Hexadecimal,
            }
        ]
    }

    fn get_detection_filters(&self) -> Vec<wirego::types::DetectionFilter> {
        vec![
            wirego::types::DetectionFilter::Int(wirego::types::DetectionFilterInt {
                filter_name: "udp.port".to_string(),
                filter_value: 137,
            }),
            wirego::types::DetectionFilter::String(wirego::types::DetectionFilterString {
                filter_name: "bluetooth.uuid".to_string(),
                filter_value: "1234".to_string(),
            })
        ]
    }

    fn get_detection_heuristics_parents(&self) -> Vec<String> {
        vec![
            "udp".to_string(),
        ]
    }

    fn detection_heuristic(
        &self,
        _packet_number: u32,
        _src: String,
        _dst: String,
        _layer: String,
        packet: &[u8],
    ) -> bool {
        if packet.len() != 0 && packet[0] == 0x00 {
            return true;
        }

        false
    }

    fn dissect_packet(
        &self,
        packet_number: u32,
        _src: String,
        _dst: String,
        _stack: String,
        packet: &[u8],
    ) -> wirego::types::DissectResult {
        let mut dissected_fields: Vec<wirego::types::DissectField> = vec![];

        if packet.len() > 6 {
            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: 1,
                offset: 0,
                length: 2,
                sub_fields: vec![],
            });

            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: 2,
                offset: 2,
                length: 4,
                sub_fields: vec![],
            });
        }

        if packet.len() > 10 {
            let sub_field_1 = wirego::types::DissectField {
                wirego_field_id: 1,
                offset: 6,
                length: 2,
                sub_fields: vec![],
            };

            let sub_field_2 = wirego::types::DissectField {
                wirego_field_id: 1,
                offset: 8,
                length: 2,
                sub_fields: vec![],
            };

            dissected_fields.push(wirego::types::DissectField {
                wirego_field_id: 3,
                offset: 6,
                length: 4,
                sub_fields: vec![sub_field_1, sub_field_2],
            });
        }

        wirego::types::DissectResult {
            protocol_column_str: "Minimal protocol example".to_string(),
            protocol_info_str: format!("Info from packet #{}", packet_number),
            dissected_fields,
        }
    }
}
