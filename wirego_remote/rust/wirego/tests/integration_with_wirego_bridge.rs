use tokio;
use wirego::{Wirego, WiregoListener};
use zeromq::{Socket, SocketRecv, SocketSend, ZmqMessage};

const TEST_ENDPOINT: &str = "/tmp/test_wirego";
const ZMQ_TEST_ENDPOINT: &str = "ipc:///tmp/test_wirego";

struct WiregoTestListener;
unsafe impl Send for WiregoTestListener {}
impl WiregoListener for WiregoTestListener {
    fn get_name(&self) -> String {
        "Wirego Test Example".to_string()
    }

    fn get_filter(&self) -> String {
        "wgtestexample".to_string()
    }

    fn get_fields(&self) -> Vec<wirego::types::WiresharkField> {
        vec![
            wirego::types::WiresharkField {
                wirego_field_id: 1,
                field_name: "Test Field 1".to_string(),
                filter: "wgtestexample.test01".to_string(),
                value_type: wirego::types::ValueType::Uint8,
                display_mode: wirego::types::DisplayMode::Hexadecimal,
            },
            wirego::types::WiresharkField {
                wirego_field_id: 2,
                field_name: "Test Field 2".to_string(),
                filter: "wgtestexample.test02".to_string(),
                value_type: wirego::types::ValueType::Uint16,
                display_mode: wirego::types::DisplayMode::Decimal,
            },
        ]
    }

    fn get_detection_filters(&self) -> Vec<wirego::types::DetectionFilter> {
        vec![
            wirego::types::DetectionFilter::Int(wirego::types::DetectionFilterInt {
                filter_name: "udp.port".to_string(),
                filter_value: 12345,
            }),
            wirego::types::DetectionFilter::String(wirego::types::DetectionFilterString {
                filter_name: "bluetooth.uuid".to_string(),
                filter_value: "5678".to_string(),
            }),
        ]
    }

    fn get_detection_heuristics_parents(&self) -> Vec<String> {
        vec!["udp".to_string()]
    }

    fn detection_heuristic(
        &self,
        _packet_number: u32,
        _src: String,
        _dst: String,
        _layer: String,
        packet_data: &[u8],
    ) -> bool {
        if packet_data.len() != 0 && packet_data[0] == 0x00 {
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

async fn create_zmq_req_socket() -> Result<zeromq::ReqSocket, zeromq::ZmqError> {
    let mut socket = zeromq::ReqSocket::new();
    socket
        .connect(ZMQ_TEST_ENDPOINT)
        .await
        .expect("Failed to connect to socket");

    Ok(socket)
}

#[tokio::test]
async fn full_plugin_setup() {
    // Cleanup the test endpoint if it exists
    let _ = std::fs::remove_file(TEST_ENDPOINT);
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Start the Wirego listener in a separate task, so we can simulate the plugin behavior
    // and test the communication with the ZMQ Req Socket.
    tokio::task::spawn(async {
        let listener = WiregoTestListener;
        let mut wirego = Wirego::new(ZMQ_TEST_ENDPOINT, Box::new(listener))
            .await
            .expect("Failed to create Wirego instance");
        wirego
            .listen()
            .await
            .expect("Something wrong happened with the Wirego Remote");
    });

    // Make sure the listener is up and running
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    // Create a ZMQ Req Socket to communicate with the Wirego listener
    let mut zmq_req_socket = create_zmq_req_socket()
        .await
        .expect("Failed to create ZMQ Req Socket");

    // Validate the unknown command does not crash
    validate_unknown_command_does_not_crash(&mut zmq_req_socket)
        .await
        .expect("Failed to validate unknown command");

    // Validate the utility_ping message
    validate_utility_ping(&mut zmq_req_socket)
        .await
        .expect("Failed to validate utility_ping");

    // Validate the utility_get_version message
    validate_utility_get_version(&mut zmq_req_socket)
        .await
        .expect("Failed to validate utility_get_version");
}

async fn validate_unknown_command_does_not_crash(
    zmq_req_socket: &mut zeromq::ReqSocket,
) -> Result<(), Box<dyn std::error::Error>> {
    let zmq_message = ZmqMessage::from("unknown_command\x00");
    zmq_req_socket
        .send(zmq_message)
        .await
        .expect("Failed to send unknown_command message");

    let response: ZmqMessage = zmq_req_socket
        .recv()
        .await
        .expect("Failed to receive unknown_command response");
    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");

    Ok(())
}

async fn validate_utility_ping(
    zmq_req_socket: &mut zeromq::ReqSocket,
) -> Result<(), Box<dyn std::error::Error>> {
    let zmq_message = ZmqMessage::from("utility_ping\x00");
    zmq_req_socket
        .send(zmq_message)
        .await
        .expect("Failed to send utility_ping message");

    let utility_ping_response: ZmqMessage = zmq_req_socket
        .recv()
        .await
        .expect("Failed to receive utility_ping response");
    assert_eq!(utility_ping_response.len(), 1);
    assert_eq!(utility_ping_response.get(0).unwrap().to_vec(), b"\x01");

    Ok(())
}

async fn validate_utility_get_version(
    zmq_req_socket: &mut zeromq::ReqSocket,
) -> Result<(), Box<dyn std::error::Error>> {
    let zmq_message = ZmqMessage::from("utility_get_version\x00");
    zmq_req_socket
        .send(zmq_message)
        .await
        .expect("Failed to send utility_get_version message");

    let response: ZmqMessage = zmq_req_socket
        .recv()
        .await
        .expect("Failed to receive utility_get_version response");
    assert_eq!(response.len(), 3);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"\x02");
    assert_eq!(response.get(2).unwrap().to_vec(), b"\x00");

    Ok(())
}
