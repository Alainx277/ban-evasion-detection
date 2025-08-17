
using System.Runtime.InteropServices;

namespace Anticheat;

class Anticheat {
    [DllImport(
        "anticheat_user.dll",
        CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool init();

    [DllImport(
        "anticheat_user.dll",
        CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.StdCall)]
    public static extern void fingerprint(ref IntPtr pFingerprint, ref uint size);

    [DllImport(
        "anticheat_user.dll",
        CharSet = CharSet.Ansi,
        CallingConvention = CallingConvention.StdCall)]
    public static extern void proof(IntPtr challengeData, uint challengeSize, ref IntPtr pProof, ref uint pSize, uint userId);
}
