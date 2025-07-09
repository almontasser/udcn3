# UDCN System Commands (Linux)

## Git Operations
```bash
git status              # Check repository status
git add .              # Stage all changes
git commit -m "msg"    # Commit changes
git push               # Push to remote
git pull               # Pull latest changes
```

## File Operations
```bash
ls -la                 # List files with details
cd <directory>         # Change directory
find . -name "*.rs"    # Find Rust files
grep -r "pattern" .    # Search for patterns
cat <file>             # Display file contents
less <file>            # Page through file
```

## System Information
```bash
uname -a               # System information
lscpu                  # CPU information
free -h                # Memory usage
df -h                  # Disk usage
ps aux                 # Process list
netstat -tlnp          # Network connections
```

## Network Interface Management
```bash
ip link show           # Show network interfaces
ip addr show           # Show IP addresses
sudo ip link set <iface> up    # Bring interface up
sudo ip link set <iface> down  # Bring interface down
```

## Permission Management
```bash
sudo <command>         # Run with root privileges
chmod +x <file>        # Make file executable
chown <user>:<group> <file>  # Change ownership
```

## Development Tools
```bash
which cargo           # Find cargo location
rustc --version       # Check Rust version
cargo --version       # Check Cargo version
```

## Process Management
```bash
jobs                  # List background jobs
fg                    # Bring job to foreground
bg                    # Send job to background
kill <pid>            # Kill process
killall <name>        # Kill processes by name
```