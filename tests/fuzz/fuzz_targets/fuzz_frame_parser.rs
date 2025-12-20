#![no_main]

use libfuzzer_sys::fuzz_target;
use zp_core::frame::Frame;

fuzz_target!(|data: &[u8]| {
    // Fuzz Frame::parse() with arbitrary bytes
    // This tests:
    // - Buffer overruns
    // - Panic-free parsing
    // - Malformed frame handling
    // - Integer overflow in length fields
    // - Out-of-bounds access

    let _ = Frame::parse(data);

    // If parsing succeeds, verify round-trip
    if let Ok(frame) = Frame::parse(data) {
        if let Ok(serialized) = frame.serialize() {
            // Re-parse should succeed
            let reparsed = Frame::parse(&serialized);
            assert!(reparsed.is_ok(), "Roundtrip parsing failed for valid frame");

            // Verify idempotence: serialize(parse(serialize(parse(data)))) == serialize(parse(data))
            if let Ok(frame2) = reparsed {
                if let Ok(serialized2) = frame2.serialize() {
                    assert_eq!(
                        serialized, serialized2,
                        "Serialization not idempotent"
                    );
                }
            }
        }
    }
});
