# Troubleshooting Plugin Load Issues

## Error: "cannot add context to list"

### Root Cause
This error occurs when Java's HttpServer tries to create URL contexts that already exist in memory from a previous plugin instance.

### Why This Happens
1. Ghidra's classloader caches plugin classes
2. When you disable/re-enable the plugin without restarting Ghidra, old contexts remain
3. The JVM doesn't fully release HttpServer resources immediately

---

## Solution 1: Clean Installation (RECOMMENDED)

**Use the automated script:**

```bash
# Close Ghidra completely first!
powershell -File clean-install.ps1
```

This script:
- ✅ Verifies Ghidra is closed
- ✅ Removes ALL old GhidraMCP files
- ✅ Waits for filesystem sync
- ✅ Installs fresh copy
- ✅ Verifies installation

**Then:**
1. Start Ghidra
2. File > Configure > Plugin Configuration
3. Search for "GhidraMCP"
4. Check the checkbox
5. Click OK

---

## Solution 2: Manual Clean Installation

**Step 1: Close Ghidra Completely**
```bash
# Verify no Ghidra processes:
tasklist | findstr ghidra
tasklist | findstr java
```

**Step 2: Delete All Old Installations**
```bash
# Remove from Ghidra Extensions
del "F:\ghidra_11.4.2\Extensions\Ghidra\GhidraMCP*.zip"

# Remove from user Extensions
rmdir /s /q "C:\Users\benam\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP"
```

**Step 3: Wait 5 Seconds**
Let the filesystem and JVM fully release resources.

**Step 4: Build Fresh**
```bash
mvn clean package assembly:single -DskipTests
```

**Step 5: Deploy Fresh**
```bash
powershell -File deploy-to-ghidra.ps1
```

**Step 6: Start Ghidra and Enable Plugin**

---

## Solution 3: Change the Port

If the error persists, the port might be genuinely blocked.

**Before starting Ghidra:**

Edit the plugin source to use a different port:
```java
// In GhidraMCPPlugin.java
private static final int DEFAULT_PORT = 8090; // Changed from 8089
```

Then rebuild and reinstall.

**Or after first Ghidra startup:**
1. Edit > Tool Options > GhidraMCP
2. Change "Server Port" from 8089 to 8090
3. Restart Ghidra

---

## Verification Checklist

After installation, verify:

### 1. Files Exist
```bash
ls "F:\ghidra_11.4.2\Extensions\Ghidra\GhidraMCP-1.5.0.zip"
ls "C:\Users\benam\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP\lib\GhidraMCP.jar"
```

Both should show timestamp from today.

### 2. No Old Versions
```bash
ls "F:\ghidra_11.4.2\Extensions\Ghidra\GhidraMCP*.zip"
```

Should ONLY show v1.5.0, not v1.3.0 or v1.4.0.

### 3. Port is Free
```bash
netstat -ano | findstr :8089
```

Should show nothing (before starting Ghidra).

### 4. Plugin Loads Successfully
In Ghidra console, you should see:
```
GhidraMCPPlugin loaded successfully with HTTP server on port 8089
```

### 5. Server Responds
```bash
curl http://127.0.0.1:8089/check_connection
```

Should return:
```json
{"status": "connected", "version": "1.5.0"}
```

---

## Common Mistakes

### ❌ Enabling Plugin Without Closing Ghidra First
**Problem**: Old classes still in memory
**Solution**: Always close Ghidra completely before reinstalling

### ❌ Not Waiting After Closing Ghidra
**Problem**: Port/resources not fully released
**Solution**: Wait 5+ seconds after closing before reinstalling

### ❌ Multiple Ghidra Instances Running
**Problem**: Port conflict
**Solution**: Check Task Manager, kill all java.exe processes related to Ghidra

### ❌ Old Extension Files Still Present
**Problem**: Ghidra loads wrong version
**Solution**: Use clean-install.ps1 script or manually delete ALL old files

---

## Advanced Debugging

### Check Ghidra Console Logs

The console shows detailed error messages. Look for:

```
HTTP server created successfully on port 8089
```

If you see:
```
Port 8089 is already in use
```

Another process has the port. Find it:
```bash
netstat -ano | findstr :8089
# Note the PID, then:
tasklist | findstr <PID>
```

### Check Java Version
```bash
java -version
```

Should be Java 21 (same version Ghidra uses).

### Check Extension Manager

In Ghidra:
1. File > Install Extensions
2. Look for GhidraMCP
3. Version should be 1.5.0
4. Status should be "Installed"

### Check Plugin Configuration

In Ghidra:
1. File > Configure
2. Look for GhidraMCPPlugin under Miscellaneous
3. Should have checkbox (not grayed out)
4. After checking, should show in console

---

## Error Messages and Solutions

### "Error constructing plugin"
**Solution**: Use clean-install.ps1 script

### "cannot add context to list"
**Solution**: Close Ghidra, wait 5 seconds, use clean-install.ps1

### "Port 8089 is already in use"
**Solution**: Close all Ghidra instances, wait 5 seconds, restart

### "Failed to start HTTP server: Address already in use"
**Solution**: Change port in Tool Options to 8090

### No error, but plugin doesn't appear
**Solution**: Check File > Install Extensions to verify extension is installed

---

## Last Resort: Complete Reset

If nothing works:

**1. Uninstall Extension Completely**
```bash
# Close Ghidra
rm "F:\ghidra_11.4.2\Extensions\Ghidra\GhidraMCP*.zip"
rmdir /s /q "C:\Users\benam\AppData\Roaming\ghidra"
rmdir /s /q "C:\Users\benam\.ghidra"
```

**2. Restart Windows**
(Ensures all JVM instances are cleared)

**3. Rebuild from Scratch**
```bash
git pull
mvn clean package assembly:single -DskipTests
powershell -File clean-install.ps1
```

**4. Start Ghidra**
First time startup will recreate user directories.

**5. Enable Plugin**
File > Configure > Check GhidraMCP

---

## Success Indicators

✅ **Plugin Loads Successfully**
- No error dialogs
- Console shows: "GhidraMCPPlugin loaded successfully"
- Menu shows: Tools > GhidraMCP

✅ **Server Starts**
- Console shows: "HTTP server created successfully on port 8089"
- curl test works
- Port 8089 shows in netstat

✅ **Tools Available**
```bash
curl http://127.0.0.1:8089/get_valid_data_types
# Should return JSON with type lists
```

---

## Support

If issues persist after following all steps:

1. Collect diagnostics:
   ```bash
   java -version > diagnostics.txt
   netstat -ano >> diagnostics.txt
   tasklist >> diagnostics.txt
   ```

2. Check Ghidra console for full stack trace

3. Verify file timestamps match:
   ```bash
   ls -l target/GhidraMCP.jar
   ls -l "C:\Users\benam\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\Extensions\GhidraMCP\lib\GhidraMCP.jar"
   ```

4. Review HOTFIX_V1.5.0.1.md for recent fixes
