using System.Text.Json.Serialization;

namespace game;

[JsonPolymorphic()]
[JsonDerivedType(typeof(ClientHello), typeDiscriminator: "clientHello")]
[JsonDerivedType(typeof(ServerHello), typeDiscriminator: "serverHello")]
[JsonDerivedType(typeof(ClientConfirm), typeDiscriminator: "clientConfirm")]
[JsonDerivedType(typeof(ServerConfirm), typeDiscriminator: "serverConfirm")]
[JsonDerivedType(typeof(MyMessage), typeDiscriminator: "myMessage")]
public abstract record Message { }
