using System.Runtime.Serialization;

namespace Authentication.Models.AuthModel;

public enum Provider
{
    [EnumMember(Value = "google")]
    Google,
    [EnumMember(Value = "github")]
    Github,
    [EnumMember(Value = "facebook")]
    Facebook
}