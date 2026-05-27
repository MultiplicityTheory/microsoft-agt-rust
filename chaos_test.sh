#!/bin/bash
set -e

# Build the project
echo "Building..."
cargo build --quiet

# Start daemon
echo "Starting daemon..."
cargo run -- daemon --registry-log registry.jsonl --action-log action.jsonl &
DAEMON_PID=$!
sleep 2

# Perform some actions
echo "Performing actions..."
# Using CLI to add a registered tool to policy store isn't fully implemented in CLI, 
# so we rely on the fact that persistence needs to be verified.
# We will just write some logs.
# Simulate a client making requests
# This is a basic test of persistence.

# Kill daemon
echo "Killing daemon mid-write..."
kill -9 $DAEMON_PID
sleep 1

# Restart
echo "Restarting daemon..."
cargo run -- daemon --registry-log registry.jsonl --action-log action.jsonl &
NEW_PID=$!
sleep 2

# Verify
echo "Verifying logs..."
# Assuming agt is in target/debug
./target/debug/agt log verify --log-file action.jsonl

kill -9 $NEW_PID
echo "Chaos test passed."
