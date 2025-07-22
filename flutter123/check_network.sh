#!/bin/bash

echo "🌐 Network Troubleshooting for Phone Connection"
echo "=============================================="
echo ""

# Check if server is running
if lsof -i:8085 > /dev/null 2>&1; then
    echo "✅ Flutter server is running on port 8085"
else
    echo "❌ Flutter server is NOT running on port 8085"
    echo "   Please make sure run_original_simple.bat is running"
fi

echo ""
echo "📱 To connect from your phone:"
echo ""

# For WSL2, we need to use the Windows host IP
if grep -q microsoft /proc/version; then
    echo "Detected WSL2 environment"
    echo ""
    
    # Get Windows host IP (from WSL perspective)
    WINDOWS_IP=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
    echo "Option 1 - Windows Host IP (if running on Windows):"
    echo "  http://${WINDOWS_IP}:8085"
    echo ""
fi

# Get all network interfaces
echo "Option 2 - Other available IPs on this system:"
ip -4 addr show | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v 127.0.0.1 | while read ip; do
    echo "  http://${ip}:8085"
done

echo ""
echo "📝 Troubleshooting Steps:"
echo "1. Make sure your phone is on the SAME Wi-Fi network as your computer"
echo "2. Try each URL above in your phone's browser"
echo "3. If none work, check your Windows Firewall settings:"
echo "   - Allow incoming connections on port 8085"
echo "   - Or temporarily disable Windows Firewall to test"
echo "4. Make sure the Flutter server is running (check the command window)"
echo ""
echo "🔥 Windows Firewall Quick Fix:"
echo "Run this in Windows PowerShell as Administrator:"
echo 'New-NetFirewallRule -DisplayName "Flutter Dev Server" -Direction Inbound -Protocol TCP -LocalPort 8085 -Action Allow'