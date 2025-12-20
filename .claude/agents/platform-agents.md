# Agent: platform-ios

## Purpose

Handle iOS-specific implementation concerns including Secure Enclave, backgrounding, and Swift bindings.

## Activation

```
/agent platform-ios
```

## iOS Constraints

| Constraint | Impact | Mitigation |
|------------|--------|------------|
| No background sockets | Connection dies on suspend | State Token + resume |
| NSURLSession only in background | HTTP/3 for downloads | Use NSURLSession for bulk transfer |
| Secure Enclave key limit | ~10 keys per app | Use derivation from master key |
| App Transport Security | HTTPS required | N/A - we do our own encryption |
| No raw UDP access | Must use Network.framework | Use NWConnection with QUIC |

## Key APIs

### Network.framework (QUIC)
```swift
let connection = NWConnection(
    host: "peer.example.com",
    port: 443,
    using: .quic(alpn: ["zp"])
)
```

### Keychain (Secure Enclave)
```swift
let query: [String: Any] = [
    kSecClass: kSecClassKey,
    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
    kSecAttrKeySizeInBits: 256
]
```

### NSURLSession (Background)
```swift
let config = URLSessionConfiguration.background(withIdentifier: "zp.transfer")
config.isDiscretionary = false
config.sessionSendsLaunchEvents = true
```

## Binding Generation

Generate Swift bindings via UniFFI:
```toml
# uniffi.toml
[bindings.swift]
module_name = "ZpCore"
generate_immutable_records = true
```

---

# Agent: platform-android

## Purpose

Handle Android-specific implementation concerns including KeyStore, Foreground Services, and Kotlin bindings.

## Activation

```
/agent platform-android
```

## Android Constraints

| Constraint | Impact | Mitigation |
|------------|--------|------------|
| Doze mode | Network blocked | Foreground Service exemption |
| Battery optimization | Background killed | Request exemption, use WorkManager |
| API level fragmentation | Feature availability varies | Runtime checks, graceful degradation |
| StrongBox optional | Hardware backing not guaranteed | Fallback to software KeyStore |

## Key APIs

### Foreground Service (API 26+)
```kotlin
val notification = NotificationCompat.Builder(this, CHANNEL_ID)
    .setContentTitle("zp Active")
    .setSmallIcon(R.drawable.ic_zp)
    .build()

startForeground(NOTIFICATION_ID, notification, FOREGROUND_SERVICE_TYPE_DATA_SYNC)
```

### AndroidKeyStore
```kotlin
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("zp_device_key", PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setIsStrongBoxBacked(true) // Request StrongBox
        .build()
)
```

### WorkManager (Deferred)
```kotlin
val request = OneTimeWorkRequestBuilder<ZpSyncWorker>()
    .setConstraints(
        Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
    )
    .build()
```

## Binding Generation

Generate Kotlin bindings via UniFFI:
```toml
# uniffi.toml
[bindings.kotlin]
package_name = "io.zp.core"
generate_immutable_records = true
```

---

# Agent: platform-browser

## Purpose

Handle browser-specific implementation concerns including WebCrypto, WASM, and TypeScript bindings.

## Activation

```
/agent platform-browser
```

## Browser Constraints

| Constraint | Impact | Mitigation |
|------------|--------|------------|
| No raw sockets | Must use WebTransport/WebRTC/WebSocket | Fallback chain |
| WebCrypto async only | All crypto is Promise-based | Async API design |
| No Secure Enclave | Keys extractable in memory | Acknowledge in security model |
| No background execution | Tab suspension stops everything | Warn users, chunk transfers |
| CORS restrictions | Can't reach arbitrary hosts | Relay through allowed origins |

## Key APIs

### WebTransport (Chromium 97+)
```typescript
const transport = new WebTransport("https://peer.example.com:443");
await transport.ready;
const stream = await transport.createBidirectionalStream();
```

### WebRTC DataChannel
```typescript
const pc = new RTCPeerConnection(config);
const dc = pc.createDataChannel("zp", {
    ordered: false,
    maxRetransmits: 0
});
```

### WebSocket Fallback
```typescript
const ws = new WebSocket("wss://peer.example.com/zp", ["zp.v1"]);
ws.binaryType = "arraybuffer";
```

### WebCrypto
```typescript
const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"]
);
```

### IndexedDB (State Token)
```typescript
const db = await openDB("zp", 1, {
    upgrade(db) {
        db.createObjectStore("tokens", { keyPath: "sessionId" });
    }
});
```

## WASM Build

```bash
# Build for wasm32
cargo build --target wasm32-unknown-unknown --release

# Generate bindings with wasm-bindgen
wasm-bindgen target/wasm32-unknown-unknown/release/zp_core.wasm \
    --out-dir pkg --typescript
```

## TypeScript Wrapper

```typescript
// zp.ts - High-level API
export class ZpConnection {
    private inner: WasmConnection;
    
    async connect(peer: string): Promise<void> { ... }
    async send(stream: number, data: Uint8Array): Promise<void> { ... }
    async recv(stream: number): Promise<Uint8Array> { ... }
}
```

## Security Acknowledgment

Browser deployments MUST display:
> "Browser connections provide transport encryption only. For full security guarantees, use the native SDK."

This matches spec §1.5 security boundaries.
