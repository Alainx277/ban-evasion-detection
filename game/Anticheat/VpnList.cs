using System.Net;

namespace Anticheat;

public class VpnList
{
    private readonly string _url;
    private readonly string _cacheFile;

    // Parallel arrays, sorted ascending
    private uint[] _starts = [];
    private uint[] _ends = [];

    public VpnList(string url, string cacheFilePath)
    {
        _url = url;
        _cacheFile = cacheFilePath;
    }

    public async Task InitializeAsync()
    {
        await EnsureCacheUpToDateAsync();
        LoadAndParseCache();
    }

    private async Task EnsureCacheUpToDateAsync()
    {
        if (File.Exists(_cacheFile))
        {
            // Use cached file if it is new enough
            var lastWrite = File.GetLastWriteTimeUtc(_cacheFile);
            if (DateTime.UtcNow - lastWrite < TimeSpan.FromDays(1))
                return;
        }

        using var http = new HttpClient();
        var data = await http.GetStringAsync(_url);
        await File.WriteAllTextAsync(_cacheFile, data);
    }

    private void LoadAndParseCache()
    {
        var entries = File.ReadAllLines(_cacheFile)
                          .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith('#'))
                          .Select(ParseCidr)
                          .Where(range => range != null)!
                          .ToList();

        // sort by start
        entries.Sort((a, b) => a!.Value.start.CompareTo(b!.Value.start));

        // unzip into two arrays
        _starts = entries.Select(r => r!.Value.start).ToArray();
        _ends = entries.Select(r => r!.Value.end).ToArray();
    }

    // returns (start, end) or null on parse error
    private static (uint start, uint end)? ParseCidr(string line)
    {
        var parts = line.Trim().Split('/');
        if (parts.Length != 2) return null;
        if (!IPAddress.TryParse(parts[0], out var ip)) return null;
        if (!int.TryParse(parts[1], out var prefixLen)) return null;
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            prefixLen < 0 || prefixLen > 32) return null;

        uint ipUint = IpToUint(ip);
        uint mask = 0xFFFFFFFF << (32 - prefixLen);

        uint start = ipUint & mask;
        uint end = start + (uint)((1UL << (32 - prefixLen)) - 1);
        return (start, end);
    }

    /// <summary>
    /// Checks if the given IPv4 address is within any of the loaded subnets.
    /// </summary>
    public bool Contains(IPAddress ip)
    {
        if (_starts.Length == 0)
            throw new InvalidOperationException("Call InitializeAsync() first.");

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;

        uint ipUint = IpToUint(ip);
        int idx = Array.BinarySearch(_starts, ipUint);

        if (idx >= 0)
        {
            // Exact match at the start of a subnet
            return true;
        }
        else
        {
            int ins = ~idx - 1;
            if (ins >= 0 && _ends[ins] >= ipUint)
            {
                // Falls within the previous subnet
                return true;
            }
        }

        return false;
    }

    private static uint IpToUint(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}
