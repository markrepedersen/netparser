use crate::{
    core::parse::{self, BitParsable},
    core::ux::*,
    layer2::datalink::*,
};

use custom_debug_derive::*;
use derive_try_from_primitive::*;
use nom::{
    bits::bits,
    bytes::complete::take,
    combinator::map,
    error::context,
    multi::many0,
    number::complete::{le_u16, le_u64, le_u8},
    sequence::tuple,
};
use serde::{Deserialize, Serialize};
use std::string::ToString;
use strum_macros::Display;

static SEQ_CONTROL_SIZE: usize = 4;

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct CapabilityInfo {
    //// These two bits are mutually exclusive. Access points set the ESS field to 1 and the IBSS field to 0 to indicate that the access point is part of an infrastructure network. Stations in an IBSS set the ESS field to 0 and the IBSS field to 1.
    #[debug(format = "{}")]
    pub ess: u1,

    /// These two bits are mutually exclusive. Access points set the ESS field to 1 and the IBSS field to 0 to indicate that the access point is part of an infrastructure network. Stations in an IBSS set the ESS field to 0 and the IBSS field to 1.
    #[debug(format = "{}")]
    pub ibss: u1,

    #[debug(format = "{}")]
    pub cf_pollable: u1,

    #[debug(format = "{}")]
    pub cf_poll_request: u1,

    #[debug(format = "{}")]
    /// Setting the Privacy bit to 1 requires the use of WEP for confidentiality. In infrastructure networks, the transmitter is an access point. In IBSSs, Beacon transmission must be handled by a station in the IBSS.
    pub privacy: u1,

    #[debug(format = "{}")]
    /// This field was added to 802.11b to support the high-rate DSSS PHY. Setting it to 1 indicates that the network is using short preamble. Zero means the option is not in use and is forbidden in the BSS. 802.11g requires use of the short preamble, so this field is always set to 1 in a network built on the 802.11g standard.
    pub short_preamble: u1,

    #[debug(format = "{}")]
    /// This field was added to 802.11b to support the high-rate DSSS PHY. When it is set to 1, it indicates that the network is using the packet binary convolution coding modulation scheme, or a higher-speed 802.11g PBCC modulation.. Zero means that the option is not in use and is forbidden in the BSS.
    pub pbcc: u1,

    #[debug(format = "{}")]
    /// This field was added to 802.11b to support the high rate DSSS PHY. Zero means the option is not in use and is forbidden in the BSS.
    pub channel_agility: u1,

    #[debug(format = "{}")]
    /// This bit is set to one to indicate the use of the shorter slot time supported by 802.11g.
    pub short_slot_time: u1,

    #[debug(format = "{}")]
    /// This bit is set to one to indicate that the optional DSSS-OFDM frame construction in 802.11g is in use.
    pub dsss_ofdm: u1,
}

impl CapabilityInfo {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame CapabilityInfo", |i| {
            let (i, (ess, ibss, cf_pollable, cf_poll_request, privacy, short_preamble, pbcc, channel_agility)) = bits(tuple((
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
            )))(i)?;
            let (i, (_, _, short_slot_time, _, _, dsss_ofdm, _, _)) = bits(tuple((
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
            )))(i)?;

            let res = Self {
                ess,
                ibss,
                cf_pollable,
                cf_poll_request,
                privacy,
                short_preamble,
                pbcc,
                channel_agility,
                short_slot_time,
                dsss_ofdm,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(Serialize, Deserialize, Debug, TryFromPrimitive, Clone, Copy, Display)]
#[repr(u16)]
pub enum ReasonCode {
    #[strum(serialize = "Reserved; unused")]
    Reserved1 = 0x0,
    #[strum(serialize = "Unspecified reason code")]
    Unspecified,
    #[strum(serialize = "Prior authentication is not valid")]
    Invalid1,
    #[strum(
        serialize = "Station has left the basic service area or extended service area and is deauthenticated"
    )]
    OutOfRange1,
    #[strum(serialize = "Inactivity timer expired and station was disassociated")]
    Inactive,
    #[strum(serialize = "Disassociated due to insufficient resources at the access point")]
    InsufficientResources,
    #[strum(serialize = "Incorrect frame type or subtype received from unauthenticated station")]
    IncorrectFrameType1,
    #[strum(
        serialize = "Station has left the basic service area or extended service area and is disassociated"
    )]
    OutOfRange2,
    #[strum(
        serialize = "Disassociated because of unacceptable values in Power Capability element"
    )]
    UnacceptableValue1,
    #[strum(
        serialize = "Disassociated because of unacceptable values in Supported Channels element"
    )]
    UnacceptableValue2,
    #[strum(serialize = "Reserved")]
    Reserved2,
    #[strum(
        serialize = "Invalid information element (added with 802.11i, and likely one of the 802.11i information elements)"
    )]
    Invalid2,
    #[strum(serialize = "Message integrity check failure")]
    MessageIntegrityCheckFailed,
    #[strum(serialize = "4-way keying handshake timeout")]
    HandshakeTimeout1,
    #[strum(serialize = "Group key handshake timeout")]
    HandshakeTimeout2,
    #[strum(
        serialize = "4-way handshake information element has different security parameters from initial parameter set"
    )]
    HandshakeTimeout3,
    #[strum(serialize = "Invalid group cipher")]
    Invalid3,
    #[strum(serialize = "Invalid pairwise cipher")]
    Invalid4,
    #[strum(serialize = "Invalid Authentication and Key Management Protocol")]
    Invalid5,
    #[strum(
        serialize = "Unsupported Robust Security Network Information Element (RSN IE) version"
    )]
    Unsupported,
    #[strum(serialize = "Invalid capabilities in RSN information element")]
    Invalid6,
    #[strum(serialize = "802.1X authentication failure")]
    AuthenticationFailure,
    #[strum(serialize = "Proposed cipher suite rejected due to configured policy")]
    Rejected,
    #[strum(serialize = "Reserved; unused")]
    Reserved3,
}

impl ReasonCode {
    pub fn parse(i: parse::Input) -> parse::Result<String> {
        context("Reason Code", |i| {
            let (i, s) = map(le_u16, Self::try_from)(i)?;
            match s {
                Some(s) => Ok((i, s.to_string())),
                None => Ok((i, "Unknown reason code".to_string())),
            }
        })(i)
    }
}

#[derive(Serialize, Deserialize, Debug, TryFromPrimitive, Clone, Copy, Display)]
#[repr(u16)]
pub enum StatusCode {
    #[strum(serialize = "Operation completed successfully")]
    Success = 0x0,
    #[strum(serialize = "Unspecified failure")]
    Unspecified,
    #[strum(serialize = "Reserved; unused")]
    Reserved1,
    #[strum(serialize = "Requested capability set is too broad and cannot be supported")]
    Unsupported1 = 0xA,
    #[strum(
        serialize = "Reassociation denied; prior association cannot be identified and transferred"
    )]
    Denied1,
    #[strum(serialize = "Association denied for a reason not specified in the 802.11 standard")]
    Denied2,
    #[strum(serialize = "Requested authentication algorithm not supported")]
    Unsupported2,
    #[strum(serialize = "Unexpected authentication sequence number")]
    Unexpected,
    #[strum(serialize = "Authentication rejected; the response to the challenge failed")]
    Rejected1,
    #[strum(
        serialize = "Authentication rejected; the next frame in the sequence did not arrive in the expected window"
    )]
    Rejected2,
    #[strum(serialize = "Association denied; the access point is resource-constrained")]
    Denied3,
    #[strum(
        serialize = "Association denied; the mobile station does not support all of the data rates required by the BSS"
    )]
    Denied4,
    #[strum(
        serialize = "Association denied; the mobile station does not support the Short Preamble option"
    )]
    Denied5,
    #[strum(
        serialize = "Association denied; the mobile station does not support the PBCC modulation option"
    )]
    Denied6,
    #[strum(
        serialize = "Association denied; the mobile station does not support the Channel Agility option"
    )]
    Denied7,
    #[strum(serialize = "Association denied; Spectrum Management is required")]
    Denied8,
    #[strum(serialize = "Association denied; Power Capability value is not acceptable")]
    Denied9,
    #[strum(serialize = "Association denied; Supported Channels is not acceptable")]
    Denied10,
    #[strum(
        serialize = "Association denied; the mobile station does not support the Short Slot Time"
    )]
    Denied11,
    #[strum(serialize = "Association denied; the mobile station does not support DSSS-OFDM")]
    Denied12,
    #[strum(serialize = "Reserved")]
    Reserved2,
    #[strum(serialize = "Information element not valid")]
    Invalid1,
    #[strum(serialize = "Group (broadcast/multicast) cipher not valid")]
    Invalid2,
    #[strum(serialize = "Pairwise (unicast) cipher not valid")]
    Invalid3,
    #[strum(serialize = "Authentication and Key Management Protocol (AKMP) not valid")]
    Invalid4,
    #[strum(
        serialize = "Robust Security Network information element (RSN IE) version is not supported"
    )]
    Unsupported3,
    #[strum(serialize = "RSN IE capabilites are not supported")]
    Unsupported4,
    #[strum(serialize = "Cipher suite rejected due to policy")]
    Unsupported5,
    #[strum(serialize = "Reserved for future standardization work")]
    Unsupported6,
}

impl StatusCode {
    pub fn parse(i: parse::Input) -> parse::Result<String> {
        context("Status Code", |i| {
            let (i, s) = map(le_u16, Self::try_from)(i)?;
            match s {
                Some(s) => Ok((i, s.to_string())),
                None => Ok((i, "Unknown status code".to_string())),
            }
        })(i)
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug)]
#[repr(u8)]
/// A blob of information that follows a management frame header.
/// Each element contains an ID and a length.
pub enum Element {
    SSID(SSID) = 0,
    SupportedRates(SupportedRates) = 1,
    FHParameterSet(FHParamSet) = 2,
    DSParameterSet(DSParamSet) = 3,
    CFParamaterSet(UnknownElement) = 4,
    TrafficIndicationMap(TrafficIndicationMap) = 5,
    IBSSParameterSet(IBSSParamSet) = 6,
    Country(Country) = 7,
    HoppingParamSet(UnknownElement) = 8,
    HoppingPatternTable(UnknownElement) = 9,
    Request(RequestElement) = 10,
    ChallengeText(ChallengeText) = 16,
    PowerConstraint(PowerConstraint) = 32,
    PowerCapability(CommonFieldsElement) = 33,
    TPCRequest(UnknownElement) = 34,
    TPCReport(TPCReport) = 35,
    SupportedChannels(SupportedChannelsElement) = 36,
    ChannelSwitchAnnouncements(ChannelSwitchAnnouncement) = 37,
    MeasurementRequest(UnknownElement) = 38,
    MeasurementReport(UnknownElement) = 39,
    Quiet(QuietElement) = 40,
    IBSS_DFS(IBSSDFS) = 41,
    ERPInfo(ERPInfo) = 42,
    RobustSecurityInfo(UnknownElement) = 48,
    ExtendedSupportedRates(UnknownElement) = 50,
    WifiProtectedAccess(UnknownElement) = 221,
    Unknown(UnknownElement),
}

impl Element {
    fn parse_optional_fields(i: parse::Input) -> parse::Result<Vec<Element>> {
        let (i, new_i) = take(i.len() - SEQ_CONTROL_SIZE)(i)?;
        let (_, res) = many0(Self::parse)(new_i)?;
        Ok((i, res))
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context(
            "802.11 Management Frame: Variable Sized Management Info Element",
            |i| {
                let (i, (id, len)) = tuple((le_u8, le_u8))(i)?;
                let (i, res) = match id {
                    0 => {
                        let (i, ssid) = SSID::parse(i, id, len)?;
                        (i, Element::SSID(ssid))
                    }

                    1 => {
                        let (i, rates) = SupportedRates::parse(i, id, len)?;
                        (i, Element::SupportedRates(rates))
                    }

                    2 => {
                        let (i, fh_param_set) = FHParamSet::parse(i, id, len)?;
                        (i, Element::FHParameterSet(fh_param_set))
                    }

                    3 => {
                        let (i, ds_param_set) = DSParamSet::parse(i, id, len)?;
                        (i, Element::DSParameterSet(ds_param_set))
                    }

                    5 => {
                        let (i, tim) = TrafficIndicationMap::parse(i, id, len)?;
                        (i, Element::TrafficIndicationMap(tim))
                    }

                    6 => {
                        let (i, ibss_param_set) = IBSSParamSet::parse(i, id, len)?;
                        (i, Element::IBSSParameterSet(ibss_param_set))
                    }

                    7 => {
                        let (i, country) = Country::parse(i, id, len)?;
                        (i, Element::Country(country))
                    }

                    10 => {
                        let (i, request) = RequestElement::parse(i, id, len)?;
                        (i, Element::Request(request))
                    }

                    16 => {
                        let (i, challenge_text) = ChallengeText::parse(i, id, len)?;
                        (i, Element::ChallengeText(challenge_text))
                    }

                    32 => {
                        let (i, p) = PowerConstraint::parse(i, id, len)?;
                        (i, Element::PowerConstraint(p))
                    }

                    35 => {
                        let (i, r) = TPCReport::parse(i, id, len)?;
                        (i, Element::TPCReport(r))
                    }

                    36 => {
                        let (i, s) = SupportedChannelsElement::parse(i, id, len)?;
                        (i, Element::SupportedChannels(s))
                    }

                    37 => {
                        let (i, c) = ChannelSwitchAnnouncement::parse(i, id, len)?;
                        (i, Element::ChannelSwitchAnnouncements(c))
                    }

                    40 => {
                        let (i, c) = QuietElement::parse(i, id, len)?;
                        (i, Element::Quiet(c))
                    }

                    41 => {
                        let (i, c) = IBSSDFS::parse(i, id, len)?;
                        (i, Element::IBSS_DFS(c))
                    }

                    42 => {
                        let (i, c) = ERPInfo::parse(i, id, len)?;
                        (i, Element::ERPInfo(c))
                    }

                    _ => {
                        let (i, c) = UnknownElement::parse(i, id, len)?;
                        (i, Element::Unknown(c))
                    }
                };

                Ok((i, res))
            },
        )(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct UnknownElement {
    #[debug(format = "{}")]
    pub id: u8,

    #[debug(format = "{}")]
    pub len: u8,
}

impl UnknownElement {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Body Unknown Element", |i| {
            let (i, _) = take(len)(i)?;
            let res = Self { id, len };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct CommonFieldsElement {
    #[debug(format = "{}")]
    pub id: u8,

    #[debug(format = "{}")]
    pub len: u8,
}

#[derive(Serialize, Deserialize, Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum AuthenticationAlgorithm {
    OpenSystemAuthentication,
    SharedKeyAuthentication,
    Reserved,
}

impl AuthenticationAlgorithm {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        context(
            "802.11 Management Frame: auth algo",
            map(le_u16, Self::try_from),
        )(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SupportedRate {
    #[debug(format = "{}")]
    /// A 7 bit field that represents a supported rate in multiples of 500 kbps.
    pub label: u7,

    #[debug(format = "{}")]
    pub is_mandatory: u1,
}

impl SupportedRate {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame Supported Rate", |i| {
            let (i, (label, is_mandatory)) = bits(tuple((u7::parse, u1::parse)))(i)?;
            let res = Self {
                label,
                is_mandatory,
            };

            Ok((i, res))
        })(i)
    }
}

/// The Supported Rates information element allows an 802.11 network to specify the data rates it supports.
/// When mobile stations attempt to join the network, they check the data rates used in the network.
/// Some rates are mandatory and must be supported by the mobile station, while others are optional.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SupportedRates {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    pub supported_rates: Vec<SupportedRate>,
}

impl SupportedRates {
    /// Parses the variable amount of supported rates following the header.
    fn parse_rates(i: parse::Input, len: u8) -> parse::Result<Vec<SupportedRate>> {
        let (i, new_i) = take(len)(i)?;
        let (_, res) = many0(SupportedRate::parse)(new_i)?;
        Ok((i, res))
    }

    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Supported Rates", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, supported_rates) = Self::parse_rates(i, common.len)?;
            let res = Self {
                common,
                supported_rates,
            };

            Ok((i, res))
        })(i)
    }
}

/// The FH Parameter Set has four fields that uniquely specify an 802.11 network based on frequency hopping.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct FHParamSet {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    /// The amount of time spent on each channel in the hopping sequence is called the dwell time. It is expressed in time units (TUs).
    #[debug(format = "0x{:04X}")]
    pub dwell_time: u16,
    /// Several hopping patterns are defined by the 802.11 frequency-hopping PHY. This field, a single byte, identifies the set of hop patterns in use.
    #[debug(format = "0x{:02X}")]
    pub hop_set: u8,
    /// Stations select one of the hopping patterns from the set. This field, also a single byte, identifies the hopping pattern in use.
    #[debug(format = "0x{:02X}")]
    pub hop_pattern: u8,
    /// Each pattern consists of a long sequence of channel hops. This field, a single byte, identifies the current point in the hop sequence.
    #[debug(format = "0x{:02X}")]
    pub hop_index: u8,
}

impl FHParamSet {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame FH Parameter Set", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, dwell_time) = le_u16(i)?;
            let (i, hop_set) = le_u8(i)?;
            let (i, hop_pattern) = le_u8(i)?;
            let (i, hop_index) = le_u8(i)?;
            let res = Self {
                common,
                dwell_time,
                hop_set,
                hop_pattern,
                hop_index,
            };

            Ok((i, res))
        })(i)
    }
}

/// Direct-sequence 802.11 networks have only one parameter: the channel number used by the network.
/// - High-rate direct sequence networks use the same channels and thus can use the same parameter set.
/// - The channel number is encoded as a single byte.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct DSParamSet {
    #[debug(skip)]
    pub common: CommonFieldsElement,

    #[debug(format = "0x{:02X}")]
    pub current_channel: u8,
}

impl DSParamSet {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame DS Parameter Set", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, current_channel) = le_u8(i)?;
            let res = Self {
                common,
                current_channel,
            };

            Ok((i, res))
        })(i)
    }
}

/// IBSSs currently have only one parameter, the announcement traffic indication map (ATIM) window.
/// - This field is used only in IBSS Beacon frames. It indicates the number of time units (TUs) between ATIM frames in an IBSS.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct IBSSParamSet {
    #[debug(skip)]
    pub common: CommonFieldsElement,

    #[debug(format = "0x{:04X}")]
    pub atim_window: u16,
}

impl IBSSParamSet {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame IBSS Parameter Set", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, atim_window) = le_u16(i)?;
            let res = Self {
                common,
                atim_window,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct CountryConstraintTriplet {
    #[debug(format = "{}")]
    /// The first channel number is the lowest channel subject to the power constraint.
    pub first_channel_num: u8,
    /// - The size of the band subject to the power constraint is indicated by the number of channels.
    /// - The size of a channel is PHY-dependent.
    #[debug(format = "{}")]
    pub num_channels: u8,
    /// The maximum transmit power, expressed in dBm.
    #[debug(format = "{} dBm")]
    pub max_transmit_power: u8,
}

impl CountryConstraintTriplet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame Country Constaint Triplet", |i| {
            let (i, first_channel_num) = le_u8(i)?;
            let (i, num_channels) = le_u8(i)?;
            let (i, max_transmit_power) = le_u8(i)?;
            let res = Self {
                first_channel_num,
                num_channels,
                max_transmit_power,
            };

            Ok((i, res))
        })(i)
    }
}

/// The initial 802.11 specifications were designed around the existing regulatory constraints in place in the major industrialized countries.
/// Rather than continue to revise the specification each time a new country was added, a new specification was added that provides
/// a way for networks to describe regulatory constraints to new stations. The main pillar of this is the Country information element
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct Country {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    /// A three-character ASCII string of where the station is operating.
    /// - The first two letters are the ISO country code (e.g., “US” for the United States).
    /// - Many countries have different indoor and outdoor regulations, and the third character distinguishes between the two.
    /// - When a single set of omnibus regulations covers all environments, the third character is a space.
    /// - To designate indoor or outdoor regulations only, the third character may be set to “I” or “O”, respectively.
    pub country_string: String,
    /// A series of constraints for the country.
    pub constraints: Vec<CountryConstraintTriplet>,
}

impl Country {
    /// Parses the variable amount of 3 tuple constraints that follow the country code.
    fn parse_triplets(i: parse::Input, len: u8) -> parse::Result<Vec<CountryConstraintTriplet>> {
        let (i, new_i) = take(len)(i)?;
        let (_, res) = many0(CountryConstraintTriplet::parse)(new_i)?;
        Ok((i, res))
    }

    fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Country Field", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, country_string) = take(3usize)(i)?;
            let country_string = std::str::from_utf8(country_string)
                .expect("Invalid country string: Failed to convert binary to UTF-8 string.")
                .to_string();
            let (i, constraints) = Self::parse_triplets(i, common.len - 3)?;
            let res = Self {
                common,
                country_string,
                constraints,
            };

            Ok((i, res))
        })(i)
    }
}

/// Access points buffer frames for mobile stations sleeping in low-power mode.
/// Periodically, the access point attempts to deliver buffered frames to sleeping stations.
/// A practical reason for this arrangement is that much more power is required to power up a transmitter than to simply turn on a receiver.
/// The designers of 802.11 envisioned battery-powered mobile stations; the decision to have buffered frames delivered
/// to stations periodically was a way to extend battery life for low-power devices.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct TrafficIndicationMap {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    /// The number of Beacons that will be transmitted before the next DTIM frame.
    /// DTIM frames indicate that buffered broadcast and multicast frames will be delivered shortly. Not all Beacon frames are DTIM frames.
    #[debug(format = "{}")]
    pub dtim_count: u8,
    /// This one-byte field indicates the number of Beacon intervals between DTIM frames.
    /// Zero is reserved and is not used. The DTIM count cycles through from the period down to 0.
    #[debug(format = "{}")]
    pub dtim_period: u8,
    /// The Bitmap Control field is divided into two subfields.
    /// Bit 0 is used for the traffic indication status of Association ID 0, which is reserved for multicast traffic.
    /// The remaining seven bits of the Bitmap Control field are used for the Bitmap Offset field.
    #[debug(format = "{:02X}")]
    pub bitmap_control: u8,
    pub partial_virtual_bitmap: Vec<u8>,
}

impl TrafficIndicationMap {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Traffic Indication Map", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, dtim_count) = le_u8(i)?;
            let (i, dtim_period) = le_u8(i)?;
            let (i, bitmap_control) = le_u8(i)?;
            let (i, partial_virtual_bitmap) = take(common.len - 3)(i)?;
            let partial_virtual_bitmap = Vec::from(partial_virtual_bitmap);

            let res = Self {
                common,
                dtim_count,
                dtim_period,
                bitmap_control,
                partial_virtual_bitmap,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SSID {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    pub ssid: String,
}

impl SSID {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame SSID", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, ssid) = take(common.len)(i)?;
            let ssid = std::str::from_utf8(ssid)
                .unwrap_or("Invalid/Malformed SSID")
                .to_string();
            let res = Self { common, ssid };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct RequestElement {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    pub requested_elements: Vec<u8>,
}

impl RequestElement {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Requested Elements", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, new_i) = take(common.len)(i)?;
            let requested_elements = Vec::from(new_i);
            let res = Self {
                common,
                requested_elements,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ChallengeText {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    pub challenge_text: String,
}

impl ChallengeText {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Challenge Text", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, challenge_text) = take(common.len)(i)?;
            let challenge_text = std::str::from_utf8(challenge_text)
                .expect("Invalid conversion of challenge text.")
                .to_string();
            let res = Self {
                common,
                challenge_text,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct PowerConstraint {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    #[debug(format = "{}")]
    pub local_power_constraint: u8,
}

impl PowerConstraint {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Power Constraint", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, local_power_constraint) = le_u8(i)?;
            let res = Self {
                common,
                local_power_constraint,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct TPCReport {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    #[debug(format = "{}")]
    pub transmit_power: u8,
    #[debug(format = "{}")]
    pub link_margin: u8,
}

impl TPCReport {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame TPC Report", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, transmit_power) = le_u8(i)?;
            let (i, link_margin) = le_u8(i)?;
            let res = Self {
                common,
                transmit_power,
                link_margin,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct SupportedChannelsElement {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    #[debug(format = "{}")]
    pub first_channel: u8,
    #[debug(format = "{}")]
    pub num_channels: u8,
}

impl SupportedChannelsElement {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Supported Channels", |i| {
            let common = CommonFieldsElement { id, len };
            let (i, first_channel) = le_u8(i)?;
            let (i, num_channels) = le_u8(i)?;
            let res = Self {
                common,
                first_channel,
                num_channels,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ChannelSwitchAnnouncement {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    /// When the operating channel is changed, it disrupts communication.
    /// If this field is set to 1, associated stations should stop transmitting frames until the channel switch has occurred.
    /// If it is set to zero, there is no restriction on frame transmission.
    #[debug(format = "{}")]
    pub channel_switch_mode: u8,
    /// The new channel number after the switch. At present, there is no need for this field to exceed a value of 255.
    #[debug(format = "{}")]
    pub new_channel_num: u8,
    /// Channel switching can be scheduled. This field is the number of Beacon frame transmission intervals that it will take to change the channel.
    /// Channel switch occurs just before the Beacon transmission is to begin.
    /// A non-zero value indicates the number of Beacon intervals to wait; a zero indicates that the channel switch may occur without any further warning.
    #[debug(format = "{}")]
    pub channel_switch_count: u8,
}

impl ChannelSwitchAnnouncement {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Channel Switch Announcement", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, channel_switch_mode) = le_u8(i)?;
            let (i, new_channel_num) = le_u8(i)?;
            let (i, channel_switch_count) = le_u8(i)?;
            let res = Self {
                common,
                channel_switch_mode,
                new_channel_num,
                channel_switch_count,
            };

            Ok((i, res))
        })(i)
    }
}

/// To find the presence of radar or other interference, an AP can use the Quiet element to
/// temporarily shut down the channel to improve the quality of measurements.
#[derive(CustomDebug, Serialize, Deserialize)]
pub struct QuietElement {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    #[debug(format = "{}")]
    pub quiet_count: u8,
    #[debug(format = "{}")]
    pub quiet_period: u8,
    #[debug(format = "0x{:04X}")]
    pub quiet_duration: u16,
    #[debug(format = "0x{:04X}")]
    pub quiet_offset: u16,
}

impl QuietElement {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame Quiet Element", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, quiet_count) = le_u8(i)?;
            let (i, quiet_period) = le_u8(i)?;
            let (i, quiet_duration) = le_u16(i)?;
            let (i, quiet_offset) = le_u16(i)?;
            let res = Self {
                common,
                quiet_count,
                quiet_period,
                quiet_duration,
                quiet_offset,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct IBSSDFSChannelMap {
    /// This bit will be set if frames from another network are detected during a measurement period.
    #[debug(format = "{}")]
    pub bss: u1,
    /// This bit is set if the 802.11a short training sequence is detected, but without being followed by the rest of the frame.
    /// HIPERLAN/2 networks use the same preamble, but obviously not the same frame construction.
    #[debug(format = "{}")]
    pub ofdm_preamble: u1,
    /// This bit is set when the received power is high, but the signal cannot be classified as
    /// either another 802.11 network (and hence, set the BSS bit), another OFDM network (and hence, set the OFDM Preamble bit), or
    /// a radar signal (and hence, set the Radar bit).
    /// The standard does not specify what power level is high enough to trigger this bit being set.
    #[debug(format = "{}")]
    pub unidentified: u1,
    /// If a radar signal is detected during a measurement period, this bit will be set.
    /// Radar systems which must be detected are defined by regulators, not the 802.11 task group.
    #[debug(format = "{}")]
    pub radar: u1,
    /// If the channel was not measured, this bit will be set.
    /// Naturally, when there was no measurement taken, nothing can be detected in the band and the previous four bits will be set to zero.
    #[debug(format = "{}")]
    pub unmeasured: u1,
}

impl IBSSDFSChannelMap {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame Channel Map", |i| {
            let (i, (bss, ofdm_preamble, unidentified, radar, unmeasured)) = bits(tuple((
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
                u1::parse,
            )))(i)?;
            let res = Self {
                bss,
                ofdm_preamble,
                unidentified,
                radar,
                unmeasured,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct IBSSDFSChannelTuple {
    #[debug(format = "{}")]
    pub channel_num: u8,
    pub channel_map: IBSSDFSChannelMap,
}

impl IBSSDFSChannelTuple {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame IBSSDFS Channel Tuple", |i| {
            let (i, channel_num) = le_u8(i)?;
            let (i, channel_map) = IBSSDFSChannelMap::parse(i)?;
            let res = Self {
                channel_num,
                channel_map,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct IBSSDFS {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    pub dfs_owner: Addr,
    #[debug(format = "{}")]
    pub dfs_recovery_interval: u8,
    pub channel_maps: Vec<IBSSDFSChannelTuple>,
}

impl IBSSDFS {
    /// Parses the variable amount of 3 tuple channel maps that follow the header.
    fn parse_maps(i: parse::Input, len: u8) -> parse::Result<Vec<IBSSDFSChannelTuple>> {
        let (i, new_i) = take(len)(i)?;
        let (_, res) = many0(IBSSDFSChannelTuple::parse)(new_i)?;
        Ok((i, res))
    }

    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame IBSSDFS", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, dfs_owner) = Addr::parse(i)?;
            let (i, dfs_recovery_interval) = le_u8(i)?;
            let (i, channel_maps) = Self::parse_maps(i, common.len - 7)?;
            let res = Self {
                common,
                dfs_owner,
                dfs_recovery_interval,
                channel_maps,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ERPInfo {
    #[debug(skip)]
    pub common: CommonFieldsElement,
    /// This bit will be set when an older, non-802.11g station associates to a network.
    /// It may also be set when overlapping networks that are not capable of using 802.11g are detected.
    #[debug(format = "{}")]
    pub non_erp_present: u1,
    /// When stations incapable of operating at 802.11g data rates are present, the protection bit is set to 1.
    #[debug(format = "{}")]
    pub use_protection: u1,
    #[debug(format = "{}")]

    /// This bit will be set if the stations which have associated to the network are not capable of the short preamble mode.
    pub barker_preamble: u1,
}

impl ERPInfo {
    pub fn parse(i: parse::Input, id: u8, len: u8) -> parse::Result<Self> {
        context("802.11 Management Frame IBSSDFS", |i| {
            let common = CommonFieldsElement { id, len };

            let (i, (non_erp_present, use_protection, barker_preamble)) =
                bits(tuple((u1::parse, u1::parse, u1::parse)))(i)?;
            let res = Self {
                common,
                non_erp_present,
                use_protection,
                barker_preamble,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct BeaconFrameBody {
    #[debug(format = "{:X}")]
    pub timestamp: u64,
    #[debug(format = "{:04X}")]
    pub beacon_interval: u16,
    pub capability_info: CapabilityInfo,
    pub dynamic_fields: Vec<Element>,
}

impl BeaconFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: Beacon Body", |i| {
            let (i, timestamp) = le_u64(i)?;
            let (i, beacon_interval) = le_u16(i)?;
            let (i, capability_info) = CapabilityInfo::parse(i)?;
            let (i, dynamic_fields) = Element::parse_optional_fields(i)?;
            let res = Self {
                timestamp,
                beacon_interval,
                capability_info,
                dynamic_fields,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ProbeRequestFrameBody {
    pub ssid: Element,
    pub supported_rates: Element,
    pub extended_support_rates: Element,
}

impl ProbeRequestFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: Probe request body", |i| {
            let (i, ssid) = Element::parse(i)?;
            let (i, supported_rates) = Element::parse(i)?;
            let (i, extended_support_rates) = Element::parse(i)?;
            let res = Self {
                ssid,
                supported_rates,
                extended_support_rates,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ProbeResponseFrameBody {
    #[debug(format = "{:X}")]
    pub timestamp: u64,
    #[debug(format = "{:04X}")]
    pub beacon_interval: u16,
    pub capability_info: CapabilityInfo,
    pub dynamic_fields: Vec<Element>,
}

impl ProbeResponseFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: Probe repsonse body", |i| {
            let (i, timestamp) = le_u64(i)?;
            let (i, beacon_interval) = le_u16(i)?;
            let (i, capability_info) = CapabilityInfo::parse(i)?;
            let (i, dynamic_fields) = Element::parse_optional_fields(i)?;
            let res = Self {
                timestamp,
                beacon_interval,
                capability_info,
                dynamic_fields,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct AssociationRequestFrameBody {
    pub capability_info: CapabilityInfo,
    #[debug(format = "{:04X}")]
    pub listen_interval: u16,
    pub ssid: Element,
    pub supported_rates: Element,
}

impl AssociationRequestFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: association request body", |i| {
            let (i, capability_info) = CapabilityInfo::parse(i)?;
            let (i, listen_interval) = le_u16(i)?;
            let (i, ssid) = Element::parse(i)?;
            let (i, supported_rates) = Element::parse(i)?;
            let res = Self {
                capability_info,
                listen_interval,
                ssid,
                supported_rates,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct ReassociationRequestFrameBody {
    pub capability_info: CapabilityInfo,
    #[debug(format = "{:04X}")]
    pub listen_interval: u16,
    pub current_ap_address: Addr,
    pub ssid: Element,
    pub supported_rates: Element,
}

impl ReassociationRequestFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: reassociation request body", |i| {
            let (i, capability_info) = CapabilityInfo::parse(i)?;
            let (i, listen_interval) = le_u16(i)?;
            let (i, current_ap_address) = Addr::parse(i)?;
            let (i, ssid) = Element::parse(i)?;
            let (i, supported_rates) = Element::parse(i)?;
            let res = Self {
                capability_info,
                listen_interval,
                current_ap_address,
                ssid,
                supported_rates,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct AssociationResponseFrameBody {
    pub capability_info: CapabilityInfo,
    pub status_code: String,
    #[debug(format = "{:04X}")]
    pub association_id: u16,
    pub supported_rates: Element,
}

impl AssociationResponseFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: association request body", |i| {
            let (i, capability_info) = CapabilityInfo::parse(i)?;
            let (i, status_code) = StatusCode::parse(i)?;
            let (i, association_id) = le_u16(i)?;
            let (i, supported_rates) = Element::parse(i)?;
            let res = Self {
                capability_info,
                status_code,
                association_id,
                supported_rates,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct AuthenticationFrameBody {
    pub algo_num: Option<AuthenticationAlgorithm>,
    #[debug(format = "{:04X}")]
    pub auth_seq: u16,
    pub status_code: String,
    pub challenge_text: Element,
}

impl AuthenticationFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: auth frame body", |i| {
            let (i, algo_num) = AuthenticationAlgorithm::parse(i)?;
            let (i, auth_seq) = le_u16(i)?;
            let (i, status_code) = StatusCode::parse(i)?;
            let (i, challenge_text) = Element::parse(i)?;
            let res = Self {
                algo_num,
                auth_seq,
                status_code,
                challenge_text,
            };

            Ok((i, res))
        })(i)
    }
}

#[derive(CustomDebug, Serialize, Deserialize)]
pub struct DeauthenticationFrameBody {
    reason_code: String,
}

impl DeauthenticationFrameBody {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("802.11 Management Frame: deauthentication", |i| {
            let (i, reason_code) = ReasonCode::parse(i)?;
            let res = Self { reason_code };

            Ok((i, res))
        })(i)
    }
}

#[cfg(test)]
mod tests {}
