/// ValueType defines the type of field value for decoding and displaying in Wireshark
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

/// DisplayMode defines how the field value should be displayed in Wireshark
#[derive(Debug, Copy, Clone)]
pub enum DisplayMode {
    None = 0x01,
    Decimal = 0x02,
    Hexadecimal = 0x03,
}

/// DetectionFilterInt holds a detection filter with an integer value
#[derive(Debug, Clone)]
pub struct DetectionFilterInt {
    pub filter_name: String,
    pub filter_value: i32,
}

/// DetectionFilterString holds a detection filter with a string value
#[derive(Debug, Clone)]
pub struct DetectionFilterString {
    pub filter_name: String,
    pub filter_value: String,
}

/// DetectionFilter defines a detection filter, e.g. tcp.port = 12 or bluetooth.uuid = "1234"
#[derive(Debug, Clone)]
pub enum DetectionFilter {
    Int(DetectionFilterInt),
    String(DetectionFilterString),
}

/// WiresharkField holds the description of a field to be dissected
#[derive(Debug, Clone)]
pub struct WiresharkField {
    /// Internal Wirego field ID
    pub wirego_field_id: u32,
    /// Displayed field name in Wireshark
    pub field_name: String,
    /// Filter name for the field in Wireshark, e.g. "ecpri.header.protocol_revision"
    pub filter: String,
    /// Field value type
    pub value_type: ValueType,
    /// Field display mode
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
