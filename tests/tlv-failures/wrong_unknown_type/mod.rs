#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[derive(NetworkEncode, NetworkDecode)]
#[network_encoding(use_tlv)]
struct TlvUnknown {
    field: Vec<u8>,

    #[network_encoding(tlv = 1)]
    tlv_int: Option<u16>,

    #[network_encoding(tlv = 2)]
    tlv_int2: Option<String>,

    #[network_encoding(unknown_tlvs)]
    rest_of_tlvs: BTreeMap<usize, Box<[u8]>>,
}
