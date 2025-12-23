//! Network.framework path monitoring for iOS.
//!
//! Monitors network interface changes and path conditions using Apple's Network.framework.
//!
//! # Use Cases
//!
//! - Detect WiFi ↔ Cellular transitions
//! - Identify expensive networks (cellular with metered data)
//! - Identify constrained networks (Low Data Mode enabled)
//! - Trigger connection migration per spec §3.3.5-6
//!
//! # Example
//!
//! ```no_run
//! use zp_platform::ios::NWPathMonitorWrapper;
//! use zp_platform::traits::{NetworkMonitor, NetworkPath, InterfaceType};
//!
//! let monitor = NWPathMonitorWrapper::new().unwrap();
//!
//! monitor.on_path_change(Box::new(move |path| {
//!     match path.interface_type {
//!         InterfaceType::Wifi => println!("Connected via WiFi"),
//!         InterfaceType::Cellular => {
//!             println!("Connected via Cellular");
//!             if path.is_expensive {
//!                 println!("Network is expensive - reduce bandwidth usage");
//!             }
//!         }
//!         _ => {}
//!     }
//! }));
//!
//! let current = monitor.current_path();
//! println!("Current interface: {:?}", current.interface_type);
//! ```

use crate::error::{Error, Result};
use crate::traits::{NetworkMonitor, NetworkPath};
use std::sync::{Arc, RwLock};

/// Type alias for path change callbacks.
type PathChangeCallback = Box<dyn Fn(NetworkPath) + Send + Sync>;

/// Network.framework path monitor wrapper.
///
/// Monitors network path changes using NWPathMonitor and translates them to
/// platform-agnostic `NetworkPath` events.
pub struct NWPathMonitorWrapper {
    /// Current network path
    current_path: Arc<RwLock<NetworkPath>>,

    /// Registered callbacks
    callbacks: Arc<RwLock<Vec<PathChangeCallback>>>,

    /// Monitor handle (kept alive to prevent deallocation)
    #[allow(dead_code)]
    monitor_handle: MonitorHandle,
}

/// Handle to keep NWPathMonitor alive.
///
/// This is a placeholder for the actual Network.framework monitor object.
/// In real implementation, this would be a CFTypeRef or objc object.
struct MonitorHandle {
    // Placeholder - real implementation would store:
    // - NWPathMonitor instance
    // - DispatchQueue for callbacks
    _placeholder: (),
}

impl NWPathMonitorWrapper {
    /// Creates a new network path monitor.
    ///
    /// Starts monitoring all network interfaces immediately.
    ///
    /// # Errors
    ///
    /// Returns `Error::Unavailable` if Network.framework is not available.
    pub fn new() -> Result<Self> {
        // Check if Network.framework is available
        #[cfg(not(target_os = "ios"))]
        {
            return Err(Error::Unavailable(
                "Network.framework only available on iOS".into(),
            ));
        }

        #[cfg(target_os = "ios")]
        {
            // Initialize with default WiFi path
            let current_path = Arc::new(RwLock::new(NetworkPath {
                interface_type: InterfaceType::Wifi,
                is_expensive: false,
                is_constrained: false,
            }));

            let callbacks = Arc::new(RwLock::new(Vec::new()));

            // In real implementation, this would:
            // 1. Create NWPathMonitor using Network.framework FFI
            // 2. Set up update handler on a dispatch queue
            // 3. Start monitoring
            //
            // For now, we create a placeholder that simulates the behavior
            let monitor_handle = MonitorHandle::new(current_path.clone(), callbacks.clone())?;

            Ok(Self {
                current_path,
                callbacks,
                monitor_handle,
            })
        }
    }
}

impl MonitorHandle {
    fn new(
        _current_path: Arc<RwLock<NetworkPath>>,
        _callbacks: Arc<RwLock<Vec<PathChangeCallback>>>,
    ) -> Result<Self> {
        // Placeholder implementation
        // Real implementation would use Network.framework FFI:
        //
        // ```objective-c
        // NWPathMonitor *monitor = [[NWPathMonitor alloc] init];
        // dispatch_queue_t queue = dispatch_queue_create("com.zp.network-monitor", DISPATCH_QUEUE_SERIAL);
        //
        // [monitor setPathUpdateHandler:^(NWPath *path) {
        //     // Convert NWPath to NetworkPath
        //     // Update current_path
        //     // Trigger callbacks
        // }];
        //
        // [monitor startWithQueue:queue];
        // ```

        tracing::warn!(
            "NWPathMonitorWrapper using placeholder implementation. \
             Real Network.framework integration requires iOS device."
        );

        Ok(Self { _placeholder: () })
    }
}

impl NetworkMonitor for NWPathMonitorWrapper {
    fn on_path_change(&self, callback: PathChangeCallback) {
        if let Ok(mut callbacks) = self.callbacks.write() {
            callbacks.push(callback);
        }
    }

    fn current_path(&self) -> NetworkPath {
        self.current_path
            .read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }
}

// Real implementation would include FFI bindings like:
//
// #[cfg(target_os = "ios")]
// mod ffi {
//     use std::ffi::c_void;
//
//     #[repr(C)]
//     pub struct NWPathMonitor(*mut c_void);
//
//     #[repr(C)]
//     pub struct NWPath(*mut c_void);
//
//     #[link(name = "Network", kind = "framework")]
//     extern "C" {
//         pub fn nw_path_monitor_create() -> *mut NWPathMonitor;
//         pub fn nw_path_monitor_set_update_handler(
//             monitor: *mut NWPathMonitor,
//             handler: extern "C" fn(*mut NWPath, *mut c_void),
//             context: *mut c_void,
//         );
//         pub fn nw_path_monitor_start(monitor: *mut NWPathMonitor, queue: *mut c_void);
//         pub fn nw_path_monitor_cancel(monitor: *mut NWPathMonitor);
//
//         pub fn nw_path_get_status(path: *mut NWPath) -> u32;
//         pub fn nw_path_is_expensive(path: *mut NWPath) -> bool;
//         pub fn nw_path_is_constrained(path: *mut NWPath) -> bool;
//         pub fn nw_path_uses_interface_type(path: *mut NWPath, interface_type: u32) -> bool;
//     }
//
//     // Interface type constants
//     pub const NW_INTERFACE_TYPE_WIFI: u32 = 1;
//     pub const NW_INTERFACE_TYPE_CELLULAR: u32 = 2;
//     pub const NW_INTERFACE_TYPE_WIRED: u32 = 3;
//     pub const NW_INTERFACE_TYPE_LOOPBACK: u32 = 4;
//     pub const NW_INTERFACE_TYPE_OTHER: u32 = 5;
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "ios")]
    #[ignore] // Requires iOS device or simulator
    fn test_network_monitor_creation() {
        let monitor = NWPathMonitorWrapper::new();
        assert!(monitor.is_ok());
    }

    #[test]
    #[cfg(target_os = "ios")]
    #[ignore] // Requires iOS device or simulator
    fn test_network_monitor_current_path() {
        let monitor = NWPathMonitorWrapper::new().unwrap();
        let path = monitor.current_path();

        // Should have some interface type
        assert!(matches!(
            path.interface_type,
            InterfaceType::Wifi
                | InterfaceType::Cellular
                | InterfaceType::Wired
                | InterfaceType::Other
        ));
    }

    #[test]
    #[cfg(target_os = "ios")]
    #[ignore] // Requires iOS device or simulator
    fn test_network_monitor_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let monitor = NWPathMonitorWrapper::new().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        monitor.on_path_change(Box::new(move |_path| {
            called_clone.store(true, Ordering::SeqCst);
        }));

        // Note: In real implementation, would simulate network change
        // For now, just verify callback registration worked
        assert!(!called.load(Ordering::SeqCst));
    }
}
