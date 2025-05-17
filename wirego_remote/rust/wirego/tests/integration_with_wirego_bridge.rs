use bytes::Bytes;
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

    // Error scenarios - validation of no crashes
    validate_unknown_command_does_not_crash(&mut zmq_req_socket).await;
    validate_command_with_wrong_number_of_frames_does_not_crash(&mut zmq_req_socket).await;

    // Valid scenarios - validation of correct responses
    validate_utility_ping(&mut zmq_req_socket).await;
    validate_utility_get_version(&mut zmq_req_socket).await;
    validate_setup_get_plugin_name(&mut zmq_req_socket).await;
    validate_setup_get_plugin_filter(&mut zmq_req_socket).await;
    validate_setup_get_fields_count(&mut zmq_req_socket).await;
    validate_setup_get_field(&mut zmq_req_socket).await;
    validate_setup_get_field_too_big_index(&mut zmq_req_socket).await;
    validate_setup_detect_int(&mut zmq_req_socket).await;
    validate_setup_detect_int_with_index_pointing_to_string(&mut zmq_req_socket).await;
    validate_setup_detect_int_too_big_index(&mut zmq_req_socket).await;
    validate_setup_detect_string(&mut zmq_req_socket).await;
    validate_setup_detect_string_with_index_pointing_to_int(&mut zmq_req_socket).await;
    validate_setup_detect_string_too_big_index(&mut zmq_req_socket).await;
    validate_setup_detect_heuristic_parent(&mut zmq_req_socket).await;
    validate_setup_detect_heuristic_parent_too_big_index(&mut zmq_req_socket).await;
    validate_process_heuristic(&mut zmq_req_socket).await;
    validate_process_dissect_packet(&mut zmq_req_socket).await;
    validate_process_dissect_packet(&mut zmq_req_socket).await; // get the dissected result from cache
    validate_result_get_protocol(&mut zmq_req_socket).await;
    validate_result_get_info(&mut zmq_req_socket).await;
    validate_result_get_fields_count(&mut zmq_req_socket).await;
    validate_result_get_field(&mut zmq_req_socket).await;
    validate_result_release(&mut zmq_req_socket).await;
}

async fn send(zmq_req_socket: &mut zeromq::ReqSocket, zmq_message: ZmqMessage) {
    zmq_req_socket
        .send(zmq_message)
        .await
        .expect("Failed to send message");
}

async fn receive(zmq_req_socket: &mut zeromq::ReqSocket) -> ZmqMessage {
    zmq_req_socket
        .recv()
        .await
        .expect("Failed to receive message")
}

async fn validate_unknown_command_does_not_crash(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("unknown_command\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_command_with_wrong_number_of_frames_does_not_crash(
    zmq_req_socket: &mut zeromq::ReqSocket,
) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("utility_ping\x00"),
        Bytes::from("extra_frame\x00"),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_utility_ping(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("utility_ping\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
}

async fn validate_utility_get_version(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("utility_get_version\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 3);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"\x02");
    assert_eq!(response.get(2).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_get_plugin_name(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("setup_get_plugin_name\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(
        response.get(1).unwrap().to_vec(),
        b"Wirego Test Example\x00"
    );
}

async fn validate_setup_get_plugin_filter(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("setup_get_plugin_filter\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"wgtestexample\x00");
}

async fn validate_setup_get_fields_count(zmq_req_socket: &mut zeromq::ReqSocket) {
    let zmq_message = ZmqMessage::from("setup_get_fields_count\x00");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), &2u32.to_le_bytes());
}

async fn validate_setup_get_field(zmq_req_socket: &mut zeromq::ReqSocket) {
    // Get first field with index 0
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_get_field\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 6);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), &1u32.to_le_bytes());
    assert_eq!(response.get(2).unwrap().to_vec(), b"Test Field 1\x00");
    assert_eq!(
        response.get(3).unwrap().to_vec(),
        b"wgtestexample.test01\x00"
    );
    assert_eq!(response.get(4).unwrap().to_vec(), b"\x03\x00\x00\x00");
    assert_eq!(response.get(5).unwrap().to_vec(), b"\x03\x00\x00\x00");

    // Get second field with index 1
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_get_field\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 6);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), &2u32.to_le_bytes());
    assert_eq!(response.get(2).unwrap().to_vec(), b"Test Field 2\x00");
    assert_eq!(
        response.get(3).unwrap().to_vec(),
        b"wgtestexample.test02\x00"
    );
    assert_eq!(response.get(4).unwrap().to_vec(), b"\x05\x00\x00\x00");
    assert_eq!(response.get(5).unwrap().to_vec(), b"\x02\x00\x00\x00");
}

async fn validate_setup_get_field_too_big_index(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_get_field\x00"),
        Bytes::from(2u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_detect_int(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_int\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 3);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"udp.port\x00");
    assert_eq!(response.get(2).unwrap().to_vec(), &12345u32.to_le_bytes());
}

async fn validate_setup_detect_int_with_index_pointing_to_string(
    zmq_req_socket: &mut zeromq::ReqSocket,
) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_int\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_detect_int_too_big_index(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_int\x00"),
        Bytes::from(2u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_detect_string(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_string\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 3);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"bluetooth.uuid\x00");
    assert_eq!(response.get(2).unwrap().to_vec(), b"5678\x00");
}

async fn validate_setup_detect_string_with_index_pointing_to_int(
    zmq_req_socket: &mut zeromq::ReqSocket,
) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_string\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_detect_string_too_big_index(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_string\x00"),
        Bytes::from(2u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_setup_detect_heuristic_parent(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_heuristic_parent\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"udp\x00");
}

async fn validate_setup_detect_heuristic_parent_too_big_index(
    zmq_req_socket: &mut zeromq::ReqSocket,
) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("setup_detect_heuristic_parent\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x00");
}

async fn validate_process_heuristic(zmq_req_socket: &mut zeromq::ReqSocket) {
    // First packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("process_heuristic\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
        Bytes::from("src\x00"),
        Bytes::from("dst\x00"),
        Bytes::from("tcp\x00"),
        Bytes::from(vec![0x01, 0x01, 0x02, 0x03, 0x04, 0x05]),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"\x00"); // wrong heuristic and heuristic parent

    // Second packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("process_heuristic\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
        Bytes::from("src\x00"),
        Bytes::from("dst\x00"),
        Bytes::from("udp\x00"),
        Bytes::from(vec![
            0x00, 0x55, 0x66, 0x77, 0x04, 0x05, 0x00, 0x55, 0x66, 0x77, 0x04, 0x05,
        ]),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), b"\x01");
}

async fn validate_process_dissect_packet(zmq_req_socket: &mut zeromq::ReqSocket) {
    // First packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("process_dissect_packet\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
        Bytes::from("src\x00"),
        Bytes::from("dst\x00"),
        Bytes::from("tcp\x00"),
        Bytes::from(vec![0x01, 0x01, 0x02, 0x03, 0x04, 0x05]),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), 0u32.to_le_bytes());

    // Second packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("process_dissect_packet\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
        Bytes::from("src\x00"),
        Bytes::from("dst\x00"),
        Bytes::from("udp\x00"),
        Bytes::from(vec![
            0x00, 0x55, 0x66, 0x77, 0x04, 0x05, 0x00, 0x55, 0x66, 0x77, 0x04, 0x05,
        ]),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), 1u32.to_le_bytes());
}

async fn validate_result_get_protocol(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_get_protocol\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(
        response.get(1).unwrap().to_vec(),
        b"Minimal protocol example\x00"
    );
}

async fn validate_result_get_info(zmq_req_socket: &mut zeromq::ReqSocket) {
    // First packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_get_info\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(
        response.get(1).unwrap().to_vec(),
        b"Info from packet #0\x00"
    );

    // Second packet
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_get_info\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(
        response.get(1).unwrap().to_vec(),
        b"Info from packet #1\x00"
    );
}

async fn validate_result_get_fields_count(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_get_fields_count\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 2);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), &0u32.to_le_bytes());
}

async fn validate_result_get_field(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_get_field\x00"),
        Bytes::from(1u32.to_le_bytes().to_vec()),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];
    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 5);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
    assert_eq!(response.get(1).unwrap().to_vec(), (-1i32).to_le_bytes());
    assert_eq!(response.get(2).unwrap().to_vec(), &1u32.to_le_bytes());
    assert_eq!(response.get(3).unwrap().to_vec(), 0u32.to_le_bytes());
    assert_eq!(response.get(4).unwrap().to_vec(), 2u32.to_le_bytes());
}

async fn validate_result_release(zmq_req_socket: &mut zeromq::ReqSocket) {
    let frames: Vec<Bytes> = vec![
        Bytes::from("result_release\x00"),
        Bytes::from(0u32.to_le_bytes().to_vec()),
    ];

    let zmq_message = ZmqMessage::try_from(frames).expect("Failed to create ZmqMessage");

    send(zmq_req_socket, zmq_message).await;
    let response = receive(zmq_req_socket).await;

    assert_eq!(response.len(), 1);
    assert_eq!(response.get(0).unwrap().to_vec(), b"\x01");
}
