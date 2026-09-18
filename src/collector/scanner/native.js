const { execFile } = require('child_process');
const os = require('os');
const { probeNeighbors } = require('./orchestrator');

// Native-Windows scanner. No nmap — avoids SentinelOne/CrowdStrike false
// positives that Liongard hit when bundling nmap in their agent. Uses
// PowerShell cmdlets on Windows; on non-Windows we return a stub so the
// collector still runs end-to-end for development on macOS/Linux.

function runPowerShell(script, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const args = ['-NoProfile', '-NonInteractive', '-Command', script];
    execFile('powershell.exe', args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`PowerShell failed: ${err.message}\n${stderr || ''}`));
        return;
      }
      try {
        const parsed = stdout.trim() ? JSON.parse(stdout) : null;
        resolve(parsed);
      } catch (parseErr) {
        reject(new Error(`PowerShell output parse failed: ${parseErr.message}\n${stdout.slice(0, 500)}`));
      }
    });
  });
}

// PS 5.1's ConvertTo-Json unwraps single-element arrays into objects and emits
// nothing for empty pipelines. -AsArray was added in PS 7. Normalize here so
// callers that expect arrays always get one regardless of the host's PS version.
async function runPowerShellArray(script, timeoutMs) {
  const result = await runPowerShell(script, timeoutMs);
  if (result === null || result === undefined) return [];
  return Array.isArray(result) ? result : [result];
}

async function collectLocalHost() {
  if (os.platform() !== 'win32') {
    return {
      hostname: os.hostname(),
      platform: os.platform(),
      release: os.release(),
      user: os.userInfo().username,
      cpus: os.cpus().length,
      memory_gb: Math.round(os.totalmem() / 1e9),
      note: 'non-Windows dev stub',
    };
  }
  const script = `
    $obj = [pscustomobject]@{
      hostname      = $env:COMPUTERNAME
      user          = $env:USERNAME
      domain        = (Get-CimInstance Win32_ComputerSystem).Domain
      osCaption     = (Get-CimInstance Win32_OperatingSystem).Caption
      osVersion     = (Get-CimInstance Win32_OperatingSystem).Version
      osBuildNumber = (Get-CimInstance Win32_OperatingSystem).BuildNumber
      totalMemoryGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
      cpuModel      = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
      cpuCount      = (Get-CimInstance Win32_Processor).Count
      biosVendor    = (Get-CimInstance Win32_BIOS).Manufacturer
      systemModel   = (Get-CimInstance Win32_ComputerSystem).Model
      systemSerial  = (Get-CimInstance Win32_BIOS).SerialNumber
      lastBoot      = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
    }
    $obj | ConvertTo-Json -Compress
  `;
  return runPowerShell(script, 30000);
}

async function collectNetworkAdapters() {
  if (os.platform() !== 'win32') {
    const interfaces = os.networkInterfaces();
    const out = [];
    for (const [name, addrs] of Object.entries(interfaces)) {
      for (const addr of addrs) {
        if (addr.internal) continue;
        out.push({ name, mac: addr.mac, ip: addr.address, family: addr.family });
      }
    }
    return out;
  }
  const script = `
    Get-NetAdapter -Physical |
      Where-Object { $_.Status -eq 'Up' } |
      ForEach-Object {
        $adapter = $_
        $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
        [pscustomobject]@{
          name          = $adapter.Name
          description   = $adapter.InterfaceDescription
          mac           = $adapter.MacAddress
          linkSpeed     = $adapter.LinkSpeed
          ip            = if ($ipv4) { $ipv4.IPAddress } else { $null }
          prefixLength  = if ($ipv4) { $ipv4.PrefixLength } else { $null }
        }
      } | ConvertTo-Json -Compress
  `;
  return runPowerShellArray(script, 30000);
}

async function collectArpNeighbors() {
  if (os.platform() !== 'win32') return [];
  const script = `
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.State -in 'Reachable','Stale','Permanent' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress } |
      Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex |
      ConvertTo-Json -Compress
  `;
  return runPowerShellArray(script, 20000);
}

async function collectShares() {
  if (os.platform() !== 'win32') return [];
  const script = `
    Get-SmbShare -ErrorAction SilentlyContinue |
      Where-Object { $_.Special -eq $false -or $_.Name -in 'ADMIN$','C$','IPC$' } |
      Select-Object Name, Path, Description, ShareState, ShareType, Special |
      ConvertTo-Json -Compress
  `;
  return runPowerShellArray(script, 20000).catch(() => []);
}

async function collectInstalledSoftware() {
  if (os.platform() !== 'win32') return [];
  const script = `
    $paths = @(
      'HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*',
      'HKLM:\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*'
    )
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName } |
      Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
      Sort-Object DisplayName |
      ConvertTo-Json -Compress
  `;
  return runPowerShellArray(script, 45000).catch(() => []);
}

async function collectAll(onProgress) {
  const results = { scanned_at: new Date().toISOString(), platform: os.platform() };

  onProgress({ phase: 'Identifying this machine...', percent: 10 });
  results.localhost = await collectLocalHost().catch(e => ({ error: e.message }));

  onProgress({ phase: 'Inspecting network adapters...', percent: 25 });
  results.adapters = await collectNetworkAdapters().catch(e => ({ error: e.message }));

  onProgress({ phase: 'Mapping network neighbors...', percent: 40 });
  const neighbors = await collectArpNeighbors().catch(e => ({ error: e.message }));
  results.neighbors = neighbors;

  // Probe each neighbor for protocol-level fingerprints (SSH banner,
  // TLS cert, HTTP server/title/favicon) + OUI vendor/mac_age.
  if (Array.isArray(neighbors) && neighbors.length > 0) {
    onProgress({ phase: 'Fingerprinting hosts...', percent: 45 });
    results.probed = await probeNeighbors(neighbors, onProgress).catch(e => ({ error: e.message }));
  } else {
    results.probed = [];
  }

  onProgress({ phase: 'Enumerating shared folders...', percent: 65 });
  results.shares = await collectShares().catch(e => ({ error: e.message }));

  onProgress({ phase: 'Cataloging installed software...', percent: 85 });
  results.software = await collectInstalledSoftware().catch(e => ({ error: e.message }));

  return results;
}

module.exports = { collectAll };
