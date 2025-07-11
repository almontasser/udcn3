# UDCN Network Testing Guide

This guide provides instructions for testing the UDCN (Userland Defined Compute Network) multi-node setup and NDN file transfer functionality.

## Prerequisites

1. Build the project:
```bash
cargo build --all
```

2. Ensure you have sudo access (required for virtual network interface creation and eBPF).

## Setting Up the Multi-Node Network

### Start the Network

```bash
sudo bash setup-multi-node.sh start
```

This command will:
- Create three virtual network interfaces (udcn1, udcn2, udcn3)
- Configure IP addresses (10.0.100.1/24, 10.0.100.2/24, 10.0.100.3/24)
- Start three UDCN daemon instances on different ports
- Load eBPF programs for packet processing

### Check Network Status

```bash
sudo bash setup-multi-node.sh status
```

This shows:
- Network interface status
- Running daemon processes
- Configuration details

## Testing NDN File Transfer

### 1. Create a Test File

```bash
echo "Hello from UDCN!" > test.txt
```

### 2. Send a File

Send a file to be stored in node1's content store:

```bash
./target/debug/udcn-cli send --file test.txt --name "/test/file" --target 10.0.100.1:8080
```

Expected output: `File sent successfully`

### 3. Receive a File

Retrieve the file from node1:

```bash
./target/debug/udcn-cli receive --name "/test/file" --output received.txt --source 10.0.100.1:8080
```

Expected output: `File received successfully`

### 4. Verify the Transfer

```bash
cat received.txt
```

Should display: `Hello from UDCN!`

## Testing Cross-Node Routing

### Send to Node 2, Receive from Node 3

1. Send file to node2:
```bash
./target/debug/udcn-cli send --file test.txt --name "/data/test" --target 10.0.100.2:8081
```

2. Try to receive from node3 (tests routing):
```bash
./target/debug/udcn-cli receive --name "/data/test" --output routed.txt --source 10.0.100.3:8082
```

Note: This will only work if proper FIB (Forwarding Information Base) entries are configured for cross-node routing.

## Monitoring and Debugging

### View Daemon Logs

Monitor real-time logs for each node:

```bash
# Node 1
tail -f /tmp/udcnd-node1.log

# Node 2
tail -f /tmp/udcnd-node2.log

# Node 3
tail -f /tmp/udcnd-node3.log
```

### Check for Packet Activity

Look for packet processing in the logs:
```bash
grep -E "(Received|Interest|Data|Cache)" /tmp/udcnd-node1.log | tail -20
```

Key log messages to look for:
- `Received packet: X bytes from Y` - Raw packet reception
- `Received Interest for /name` - Interest packet received
- `Received Data for /name` - Data packet received
- `Cache hit for /name` - Content found in store
- `Cache miss for /name` - Content not found
- `Stored data for /name` - Data stored in content store
- `Sent data response for /name` - Data sent in response to Interest

### Enable Debug Logging

For more detailed output, run commands with debug logging:
```bash
RUST_LOG=debug ./target/debug/udcn-cli send --file test.txt --name "/test/file" --target 10.0.100.1:8080
```

## Testing Different File Sizes

### Small File
```bash
echo "Small test" > small.txt
./target/debug/udcn-cli send --file small.txt --name "/files/small" --target 10.0.100.1:8080
```

### Large File
```bash
dd if=/dev/urandom of=large.txt bs=1M count=10
./target/debug/udcn-cli send --file large.txt --name "/files/large" --target 10.0.100.1:8080
```

## Cleanup

### Stop the Network

```bash
sudo bash setup-multi-node.sh stop
```

This will:
- Stop all daemon processes
- Clean up XDP programs
- Restore original configuration files

### Complete Cleanup (including interfaces)

```bash
sudo bash setup-multi-node.sh cleanup
```

This additionally removes the virtual network interfaces.

## Troubleshooting

### Issue: "File receive failed: Request timed out"

**Possible causes:**
1. The file was not sent first
2. Wrong NDN name used
3. Daemon not running
4. Network connectivity issue

**Solution:**
1. Ensure file is sent before trying to receive
2. Check exact NDN name used in send command
3. Verify daemon is running: `ps aux | grep udcnd`
4. Check logs for errors

### Issue: "Address already in use"

**Cause:** Previous daemon instance still running

**Solution:**
```bash
sudo bash setup-multi-node.sh stop
# Wait a few seconds
sudo bash setup-multi-node.sh start
```

### Issue: XDP attach failures

**Cause:** Virtual interfaces don't support all XDP modes

**Solution:** Already handled - the system automatically uses SKB_MODE for virtual interfaces

## Performance Testing

### Measure Transfer Time
```bash
time ./target/debug/udcn-cli send --file large.txt --name "/perf/test" --target 10.0.100.1:8080
time ./target/debug/udcn-cli receive --name "/perf/test" --output perf-received.txt --source 10.0.100.1:8080
```

### Monitor Content Store
Check content store statistics in the logs after multiple transfers to see cache performance.

## Advanced Testing

### Test with Custom Chunk Size
```bash
./target/debug/udcn-cli send --file test.txt --name "/test/chunked" --chunk-size 4096 --target 10.0.100.1:8080
```

### Test Progress Monitoring
```bash
./target/debug/udcn-cli send --file large.txt --name "/test/progress" --progress --target 10.0.100.1:8080
```

## Expected Behavior

1. **Send Operation**: Data packets are sent to the daemon and stored in its content store
2. **Receive Operation**: 
   - Interest packets are sent for each chunk
   - Daemon responds with cached Data packets
   - File is reconstructed from received chunks
3. **Caching**: Subsequent requests for the same content are served from cache (faster)
4. **Expiration**: Content expires after 5 minutes by default

## Summary

The UDCN network demonstrates:
- NDN (Named Data Networking) principles
- Content-based addressing
- In-network caching
- eBPF integration for packet processing
- Multi-node routing capabilities

For development and debugging, always check the daemon logs as they provide detailed information about packet flow and processing.