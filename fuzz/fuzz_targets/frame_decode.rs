#![no_main]

use libfuzzer_sys::fuzz_target;
use smpc_core::{PartyId, SessionId};
use smpc_net::{decode_frame_body, DEFAULT_MAX_FRAME_LEN};

fuzz_target!(|data: &[u8]| {
    let _ = decode_frame_body(
        data,
        SessionId::from_u64_for_testing(1),
        PartyId::P0,
        DEFAULT_MAX_FRAME_LEN,
    );
});
