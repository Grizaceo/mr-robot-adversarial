#!/bin/bash
# Demo runner for FIND EVIL! submission
# Executes the three scenarios in sequence for video recording

set -e

echo "=== FIND EVIL! DEMO SEQUENCE ==="
echo "Total estimated time: 3 minutes"
echo ""

# Scene 1: Malware detection
echo "[0:00] Scene 1: Malware Detection & Auto-Response"
echo "-------------------------------------------------"
python agents/defender_agent.py --scenario malware_detection
sleep 5

# Scene 2: APT simulation
echo "[1:30] Scene 2: APT Simulation & Correlation"
echo "-------------------------------------------------"
python agents/defender_agent.py --scenario apt_chain
sleep 5

# Scene 3: Zero-day adaptation
echo "[2:30] Scene 3: Zero-Day Adaptation"
echo "-------------------------------------------------"
python agents/defender_agent.py --scenario zero_day
sleep 5

echo ""
echo "=== DEMO COMPLETE ==="
echo "Total scenes: 3"
echo "Total time: ~3 minutes"
echo "Ready for video recording!"
