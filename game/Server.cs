using System;
using System.Data.Common;
using System.Data.SqlTypes;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Anticheat;
using Anticheat.TpmCredential;
using Dapper;
using Google.Protobuf;
using LiteNetLib;
using LiteNetLib.Utils;

namespace game;

public class Server : INetEventListener
{
    private NetManager _server;
    private int _port;
    private readonly DbConnection _dbConnection;
    private readonly Dictionary<User, ClientState> _clients = new();
    private readonly Dictionary<IPEndPoint, ProfilerZone> _profilerZonesConnect = new();
    private readonly VpnList _vpnList;

    public Server(int port, DbConnection dbConnection, VpnList vpnList)
    {
        _port = port;
        _server = new NetManager(this);
        _dbConnection = dbConnection;
        _vpnList = vpnList;
        DefaultTypeMap.MatchNamesWithUnderscores = true;
    }

    public void Run()
    {
        Profiler.AppInfo("anticheat-poc");
        _server.Start(_port);
        Console.WriteLine("Server started on port " + _port);
        while (true)
        {
            _server.PollEvents();
            Thread.Sleep(15);
        }
    }

    public void OnConnectionRequest(ConnectionRequest request)
    {
        var clientAddress = request.RemoteEndPoint.Address;
        // clientAddress = IPAddress.Parse("185.171.224.5");
        if (_vpnList.Contains(clientAddress))
        {
            Console.WriteLine($"Connection from VPN/datacenter detected: {clientAddress}, blocking");
            ServerConfirm serverConfirm = new("Connections from VPNs are not allowed");
            byte[] serializedServerConfirm = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)serverConfirm));
            request.Reject(serializedServerConfirm);
            return;
        }
        request.AcceptIfKey("example");
    }

    public void OnPeerConnected(NetPeer peer)
    {
        if (_profilerZonesConnect.Remove(peer, out var zone))
        {
            zone.Dispose();
        }
        _profilerZonesConnect.Add(peer, Profiler.BeginZone("Connection"));
        Console.WriteLine("Inbound client: " + peer.Address);
    }

    public void OnPeerDisconnected(NetPeer peer, DisconnectInfo disconnectInfo)
    {
        if (_profilerZonesConnect.Remove(peer, out var zone))
        {
            zone.Dispose();
        }
        Console.WriteLine("Client disconnected: " + peer.Address + ", reason: " + disconnectInfo.Reason);
    }

    public void OnNetworkError(System.Net.IPEndPoint endPoint, System.Net.Sockets.SocketError socketError)
    {
        Console.WriteLine("Network error: " + socketError);
    }

    public void OnNetworkReceive(NetPeer peer, NetPacketReader reader, byte channelNumber, DeliveryMethod deliveryMethod)
    {
        // Read and deserialize the incoming message
        byte[] receivedData = reader.GetRemainingBytes();
        string json = Encoding.UTF8.GetString(receivedData);
        try
        {
            var message = JsonSerializer.Deserialize<Message>(json);
            if (message == null) {
                throw new Exception("Cannot be null");
            }
            switch (message)
            {
                case ClientHello hello:
                    HandleClientHello(peer, hello);
                    break;
                case ClientConfirm clientConfirm:
                    HandleClientConfirm(peer, clientConfirm);
                    break;
                default:
                    Console.WriteLine($"Ignored message from client: {message.GetType().Name}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to handle message: " + ex.ToString());
        }
        reader.Recycle();
    }

    private void HandleClientHello(NetPeer peer, ClientHello hello)
    {
        using var zone = Profiler.BeginZone("Client hello");

        // Header
        var defaultColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("=== Client Connecting ===\n");
        Console.ForegroundColor = defaultColor;

        Console.WriteLine($"IP ➜ {peer.Address}");

        // Upsert user
        var zoneUser = Profiler.BeginZone("User query");
        const string userSql = @"INSERT INTO users (user_id)
                                VALUES (@UserId)
                                ON CONFLICT (user_id) DO NOTHING;
                                SELECT * FROM users WHERE user_id = @UserId;";

        var user = _dbConnection.QuerySingle<User>(userSql, new { UserId = hello.UserId });
        Console.WriteLine($"User ➜ {JsonSerializer.Serialize(user)}\n");
        zoneUser.Dispose();

        if (user.Banned)
        {
            Console.WriteLine("User is banned, disconnecting");
            ServerConfirm message = new("You have been banned from this server");
            byte[] serializedServerConfirm = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)message));
            peer.Disconnect(serializedServerConfirm);
            return;
        }

        // Parse fingerprint
        var fingerprint = Fingerprint.Parser.ParseFrom(hello.Fingerprint);

        // We create challenges for the client to prove it possesses these fingerprints
        var challenge = new FingerprintChallenge();

        // Check if any TPM certificates are provided
        var zoneTpm = Profiler.BeginZone("TPM challenge");
        byte[]? tpmSecret = null;
        X509Certificate2? certificate = null;
        var rawCertificate = fingerprint.ManufacturerCertificates.FirstOrDefault() ?? fingerprint.AdditionalCertificates.FirstOrDefault();
        if (rawCertificate is not null) {
            // Create TPM attestation challenge
            tpmSecret = new byte[30];
            RandomNumberGenerator.Fill(tpmSecret);
            (certificate, var  activation) = TpmCredentialBlob.Create(tpmSecret, fingerprint.DerivedKeyName.Span, rawCertificate.Span);

            challenge.TpmChallenge = ByteString.CopyFrom(activation.EncIdentity);
            challenge.TpmSecret = ByteString.CopyFrom(activation.EncryptedSecret);
            challenge.TpmIntegrity = ByteString.CopyFrom(activation.Integrity);
        }
        zoneTpm.Dispose();

        // Create challenges for signed identifiers
        ByteString RandomChallenge()
        {
            var buf = new byte[32];
            RandomNumberGenerator.Fill(buf);
            return ByteString.CopyFrom(buf);
        }
        var zoneRand = Profiler.BeginZone("Signature challenge");
        challenge.RegistryKey = RandomChallenge();
        challenge.CpuSerial   = RandomChallenge();
        challenge.BiosSerial  = RandomChallenge();

        for (int i = 0; i < fingerprint.MonitorIds.Count; i++)
        {
            challenge.MonitorIds.Add(RandomChallenge());
        }
        for (int i = 0; i < fingerprint.MacAddresses.Count; i++)
        {
            challenge.MacAddresses.Add(RandomChallenge());
        }
        for (int i = 0; i < fingerprint.DiskSerials.Count; i++)
        {
            challenge.DiskSerials.Add(RandomChallenge());
        }
        for (int i = 0; i < fingerprint.VolumeSerials.Count; i++)
        {
            challenge.VolumeSerials.Add(RandomChallenge());
        }
        zoneRand.Dispose();

        _clients.Remove(user);
        _clients.Add(user, new ClientState.Connecting(fingerprint, tpmSecret, certificate, challenge));

        var serverHello = new ServerHello(challenge.ToByteArray());
        byte[] data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)serverHello));
        peer.Send(data, DeliveryMethod.ReliableOrdered);
    }

    private void HandleClientConfirm(NetPeer peer, ClientConfirm clientConfirm)
    {
        var zone = Profiler.BeginZone("Client confirm");

        var user = new User { UserId = clientConfirm.UserId };
        var client = _clients.GetValueOrDefault(user);
        if (client is not ClientState.Connecting(var fingerprint, var tpmSecret, var tpmCertificate, var issuedChallenge))
        {
            Console.WriteLine($"Client sent proof while not in connecting state");
            return;
        }
        var proof = FingerprintProof.Parser.ParseFrom(clientConfirm.FingerprintProof);



        ServerConfirm serverConfirm = new(null);

        if (tpmSecret is not null && tpmCertificate is not null)
        {
            var zoneTpm = Profiler.BeginZone("TPM verify");
            var tpmProof = proof.TpmChallenge.ToByteArray();
            Console.WriteLine($"TPM client proof: {BitConverter.ToString(tpmProof)}");
            Console.WriteLine($"TPM server proof: {BitConverter.ToString(tpmSecret)}");
            if (tpmProof.SequenceEqual(tpmSecret))
            {
                using var zoneCert = Profiler.BeginZone("TPM certificates");
                // TPM signature is valid, check certificate chain
                var authorities = TpmCertificateAuthorities.Load("tpm-certificates.zip");
                if (!TpmCertificate.Verify(tpmCertificate, [..fingerprint.CertificateChain.Select(f => f.ToByteArray())], authorities))
                {
                    serverConfirm = new("Not a trusted TPM");
                }
            }
            else
            {
                serverConfirm = new("Invalid TPM signature");
            }
            zoneTpm.Dispose();
        }
        else
        {
            Console.WriteLine("Client did not provide a TPM certificate");
        }

        if (serverConfirm.DisconnectReason is null)
        {
            using var zoneCert = Profiler.BeginZone("Fingerprint verify");
            if (!FingerprintVerifier.Verify(user.UserId, fingerprint, issuedChallenge, proof))
            {
                serverConfirm = new("Invalid fingerprint proof");
            }
        }

        if (serverConfirm.DisconnectReason is string reason)
        {
            Console.WriteLine($"Disconnecting client: {reason}");
            byte[] serializedDisconnect = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)serverConfirm));
            peer.Disconnect(serializedDisconnect);
            if (_profilerZonesConnect.Remove(peer, out var pZone))
            {
                zone.Dispose();
                pZone.Dispose();
            }
            return;
        }

        // --- Prepare individual fingerprint components -------------------------
        var fingerprintComponents = new[]
        {
            (Label: "RegistryKey", Data: fingerprint.RegistryKey.ToByteArray())
        }
        .Concat(fingerprint.MonitorIds.Select(id => (Label: "MonitorId", Data: id.ToByteArray())))
        .Concat(new []{tpmCertificate}.Where(x => x is not null).Select(x => (Label: "TPM", Data: x!.RawData)))
        .Concat(fingerprint.MacAddresses.Select(address => (Label: "NetworkDevice", Data: address.ToByteArray())))
        .Concat(fingerprint.DiskSerials.Select(s => (Label: "Disk", Data: s.ToByteArray())))
        .Concat(fingerprint.VolumeSerials.Select(s => (Label: "Volume", Data: s.ToByteArray())))
        .Append((Label: "IP", Data: peer.Address.GetAddressBytes()))
        .Append((Label: "CPU", Data: fingerprint.CpuSerial.ToByteArray()))
        .Append((Label: "BIOS", Data: fingerprint.BiosSerial.ToByteArray()))
        .ToList();

        var zoneQuery = Profiler.BeginZone("Fingerprint query");

        // Find each fingerprint or insert a new entry
        // Also gets the confidence level for each fingerprint
        const string fpUpsertSql = @"
            WITH ins AS (
                INSERT INTO fingerprints (kind, data)
                VALUES (@Kind, @Data)
                ON CONFLICT (kind, data) DO NOTHING
                RETURNING fingerprint_id, banned, kind
            ),
            base AS (
                SELECT fingerprint_id, banned, kind
                FROM ins
                UNION ALL
                SELECT fingerprint_id, banned, kind
                FROM fingerprints
                WHERE kind = @Kind
                AND data = @Data
            )
            SELECT
                b.fingerprint_id    AS Id,
                b.banned            AS Banned,
                k.confidence        AS Confidence
            FROM base b
            JOIN fingerprint_kind k
            ON k.kind = b.kind;
        ";

        const string linkSql = @"INSERT INTO user_fingerprints (user_id, fingerprint_id)
                                VALUES (@UserId, @FingerprintId)
                                ON CONFLICT DO NOTHING;";

        var componentResults = fingerprintComponents.Select(component =>
        {
            var result = _dbConnection.QuerySingle<(int Id, bool Banned, int Confidence)>(fpUpsertSql,
                new { Kind = component.Label, Data = component.Data });
            _dbConnection.Execute(linkSql, new { UserId = user.UserId, FingerprintId = result.Id });

            string valueString = component.Label switch
            {
                "TPM"=> Convert.ToBase64String(component.Data),
                "IP"=> new IPAddress(component.Data).ToString(),
                _             => BitConverter.ToString(component.Data)
            };

            return new { component.Label, Value = valueString, result.Confidence, result.Banned };
        }).ToList();
        zoneQuery.Dispose();

        // Show all identifiers
        var defaultColor = Console.ForegroundColor;
        int maxLabelLength = componentResults.Select(x => x.Label.Length).Max();
        Console.WriteLine("Confirmed client fingerprint:");
        foreach (var item in componentResults)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"  {item.Label.PadRight(maxLabelLength)} : ");
            Console.ForegroundColor = defaultColor;
            Console.WriteLine(item.Value);
        }

        // Calculate trust score based on present / missing identifiers
        var fingerprintKinds = _dbConnection
            .Query<(string Kind, int PresentTrust, int MissingTrust)>(
                @"SELECT kind, present_trust, missing_trust
                FROM fingerprint_kind");
        var trustModifier = fingerprintKinds.Select(k => fingerprintComponents.Any(f => f.Label == k.Kind) ? k.PresentTrust : -k.MissingTrust).Sum();

        // Check for user mode spoofing attempts
        if (!fingerprint.BiosSerial.IsEmpty && !fingerprint.KernelBiosSerial.IsEmpty && fingerprint.BiosSerial != fingerprint.KernelBiosSerial)
        {
            Console.WriteLine("Mismatched kernel bios serial");
            trustModifier -= 200;
        }
        // Is driver test signing mode enabled?
        if (fingerprint.TestSigning)
        {
            Console.WriteLine("Test signing enabled");
            // trustModifier -= 200;
        }
        // Are there any detected kernel hooks?
        if (fingerprint.KernelHooks)
        {
            Console.WriteLine("Kernel hooks detected");
            trustModifier -= 200;
        }

        // Base trust is 100
        var trust = 100 + trustModifier;
        _dbConnection.Execute("UPDATE users SET trust = @Trust WHERE user_id = @UserId", new { user.UserId, Trust = trust });

        // Check for banned identifiers
        Console.WriteLine("Matched Identifiers and Scores:");
        var bannedComponents = componentResults.Where(x => x.Banned);
        int maxBannedLength = bannedComponents.Select(x => (int?)x.Label.Length).Max() ?? 0;
        foreach (var item in bannedComponents)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"  {item.Label.PadRight(maxBannedLength)} : ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"{item.Value} (score {item.Confidence})");
            Console.ForegroundColor = defaultColor;
        }
        if (bannedComponents.Count() == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  None");
            Console.ForegroundColor = defaultColor;
        }
        int totalScore = bannedComponents.Sum(x => x.Confidence);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("  Total Score : ");
        Console.ForegroundColor = defaultColor;
        Console.WriteLine(totalScore);

        // Very low trust score leads to disconnection
        if (trust < 20)
        {
            Console.WriteLine($"Client has low trust ({trust}), disconnecting");
            ServerConfirm disconnect = new("Cannot verify integrity of your device, try again later or contact support");
            byte[] serializedDisconnect = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)disconnect));
            peer.Disconnect(serializedDisconnect);
            if (_profilerZonesConnect.Remove(peer, out var pZone))
            {
                zone.Dispose();
                pZone.Dispose();
            }
            return;
        }
        Console.WriteLine($"Trust Score: {trust}");

        // Decide action based on score
        bool thresholdBan = totalScore >= 100;
        bool suspicious = totalScore >= 30;
        Console.ForegroundColor = thresholdBan ? ConsoleColor.Red : (suspicious ? ConsoleColor.Yellow : ConsoleColor.Green);
        if (thresholdBan)
        {
            Console.WriteLine("Automatic ban - total score threshold exceeded.");
            _dbConnection.Execute("SELECT ban_user(@UserId)", user);
            serverConfirm = new("Ban evasion detected, your account has been banned");
            byte[] serializedBanMessage = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)serverConfirm));
            peer.Disconnect(serializedBanMessage);
            if (_profilerZonesConnect.Remove(peer, out var pZone))
            {
                zone.Dispose();
                pZone.Dispose();
            }
        }
        else if (suspicious)
        {
            Console.WriteLine("Client is connected but marked as suspicious");
            _dbConnection.Execute("UPDATE users SET suspicious = TRUE WHERE user_id = @UserId", user);
        }
        else
        {
            Console.WriteLine("Client is connected");
        }
        Console.ForegroundColor = defaultColor;
        Console.WriteLine();
 
        _clients[user] = new ClientState.Connected();
        byte[] serializedServerConfirm = Encoding.UTF8.GetBytes(JsonSerializer.Serialize((Message)serverConfirm));
        peer.Send(serializedServerConfirm, DeliveryMethod.ReliableOrdered);

        if (_profilerZonesConnect.Remove(peer, out var endZone))
        {
            zone.Dispose();
            endZone.Dispose();
        }
    }

    public void OnNetworkLatencyUpdate(NetPeer peer, int latency)
    {
        // Optionally handle latency update
    }

    public void OnNetworkReceiveUnconnected(IPEndPoint remoteEndPoint, NetPacketReader reader, UnconnectedMessageType messageType)
    {
        throw new NotImplementedException();
    }
}
