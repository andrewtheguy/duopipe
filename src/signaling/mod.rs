//! Iroh signaling codecs.

pub mod codec;

// Connection-level authentication.
pub use codec::{
    AuthRequest, AuthResponse, decode_auth_request, decode_auth_response, encode_auth_request,
    encode_auth_response,
};

// Per-stream dispatch.
pub use codec::{
    StreamAck, StreamHello, decode_stream_ack, decode_stream_hello, encode_stream_ack,
    encode_stream_hello, read_length_prefixed,
};
