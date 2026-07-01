//! Iroh signaling codecs.

pub mod codec;

// Connection-level authentication.
pub use codec::{
    AuthRequest, AuthResponse, PinChallenge, PinConfirm, PinResponse, decode_auth_request,
    decode_auth_response, decode_pin_challenge, decode_pin_confirm, decode_pin_response,
    encode_auth_request, encode_auth_response, encode_pin_challenge, encode_pin_confirm,
    encode_pin_response,
};

// Per-stream dispatch.
pub use codec::{
    StreamAck, StreamHello, decode_stream_ack, decode_stream_hello, encode_stream_ack,
    encode_stream_hello, read_length_prefixed,
};
