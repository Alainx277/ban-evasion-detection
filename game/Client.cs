using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using LiteNetLib;
using LiteNetLib.Utils;

namespace game;

public class Client : INetEventListener
{
    private NetManager _client;
    private NetPeer _serverPeer;
    private string _serverAddress;
    private int _serverPort;
    private int _userId;

    public Client(string serverAddress, int serverPort, int userId)
    {
        _serverAddress = serverAddress;
        _serverPort = serverPort;
        _client = new NetManager(this);
        _userId = userId;
    }

    public void Run()
    {
        Console.WriteLine("Enter any key to connect");
        Console.ReadLine();
        Anticheat.Anticheat.init();
        _client.Start();
        _serverPeer = _client.Connect(_serverAddress, _serverPort, "example");
        Console.WriteLine("Client connecting to " + _serverAddress + ":" + _serverPort);

        while (true)
        {
            _client.PollEvents();
            System.Threading.Thread.Sleep(15);
        }
    }

    public static void Run(string serverAddress, int serverPort, int userId)
    {
        var client = new Client(serverAddress, serverPort, userId);
        client.Run();
    }

    public void OnPeerConnected(NetPeer peer)
    {
        Console.WriteLine("Connected to server: " + peer.Address);

        Console.WriteLine("Gathering fingerprint");
        nint fingerprintData = 0;
        uint fingerprintSize = 0;
        Anticheat.Anticheat.fingerprint(ref fingerprintData, ref fingerprintSize);

        var fingerprint = new byte[fingerprintSize];
        Marshal.Copy(fingerprintData, fingerprint, 0, (int)fingerprintSize);
        Marshal.FreeCoTaskMem(fingerprintData);

        Console.WriteLine("Sending client hello");

        var message = new ClientHello(_userId, fingerprint);
        string json = JsonSerializer.Serialize((Message)message);
        byte[] data = Encoding.UTF8.GetBytes(json);
        peer.Send(data, DeliveryMethod.ReliableOrdered);
    }

    public void OnNetworkReceive(NetPeer peer, NetPacketReader reader, byte channelNumber, DeliveryMethod deliveryMethod)
    {
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
                case MyMessage myMessage:
                    Console.WriteLine("Received message from server: " + myMessage.Text);
                    break;
                case ServerHello serverHello:
                    Console.WriteLine("Received fingerprint challenge from server");
                    byte[] proof;
                    unsafe
                    {
                        fixed (byte* challengePointer = serverHello.FingerprintChallenge)
                        {
                            nint proofData = 0;
                            uint proofSize = 0;
                            Anticheat.Anticheat.proof((nint)challengePointer, (uint)serverHello.FingerprintChallenge.Length, ref proofData, ref proofSize, (uint)_userId);
                            proof = new byte[proofSize];
                            Marshal.Copy(proofData, proof, 0, (int)proofSize);
                            Marshal.FreeCoTaskMem(proofData);
                        }
                    }
                    Console.WriteLine("Sending fingerprint proof to server");
                    var proofMessage = new ClientConfirm(_userId, proof);
                    string proofJson = JsonSerializer.Serialize((Message)proofMessage);
                    byte[] data = Encoding.UTF8.GetBytes(proofJson);
                    peer.Send(data, DeliveryMethod.ReliableOrdered);
                    break;
                case ServerConfirm serverConfirm:
                    if (serverConfirm.DisconnectReason is string reason)
                    {
                        Console.WriteLine($"Rejected by server: {reason}");
                    }
                    else
                    {
                        Console.WriteLine("Successfully connected with server");
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to deserialize message: " + ex.Message);
        }
        reader.Recycle();
    }

    public void OnPeerDisconnected(NetPeer peer, DisconnectInfo disconnectInfo)
    {
        Console.WriteLine("Disconnected from server: " + disconnectInfo.Reason);
        if (disconnectInfo.AdditionalData is not null)
        {
            string json = Encoding.UTF8.GetString(disconnectInfo.AdditionalData.GetRemainingBytes());
            var message = JsonSerializer.Deserialize<Message>(json);
            if (message == null)
            {
                throw new Exception("Cannot be null");
            }
            switch (message)
            {
                case ServerConfirm { DisconnectReason: string reason }:
                    Console.WriteLine($"Rejected by server: {reason}");
                    break;
                default:
                    Console.WriteLine("Unknown disconnect message");
                    break;
            }
        }
    }

    public void OnNetworkError(System.Net.IPEndPoint endPoint, System.Net.Sockets.SocketError socketError)
    {
        Console.WriteLine("Network error: " + socketError);
    }

    public void OnConnectionRequest(ConnectionRequest request)
    {
        // Not used on client
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
