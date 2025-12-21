#![no_main]

use libfuzzer_sys::fuzz_target;
use zp_core::frame::Frame;

fuzz_target!(|data: &[u8]| {
    // Fuzz frame parsing - should never panic on any input
    let _ = Frame::parse(data);
});
