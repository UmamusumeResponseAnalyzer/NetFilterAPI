using System.Runtime.InteropServices;

namespace NetFilterAPI;

public static class Redirector
{
    public enum NameList
    {
        AIO_FILTERLOOPBACK,
        AIO_FILTERINTRANET, // LAN
        AIO_FILTERSELF,
        AIO_FILTERPARENT,
        AIO_FILTERICMP,
        AIO_FILTERTCP,
        AIO_FILTERUDP,
        AIO_FILTERDNS,

        AIO_ICMPING,

        AIO_DNSONLY,
        AIO_DNSPROX,
        AIO_DNSHOST,
        AIO_DNSPORT,

        AIO_TGTHOST,
        AIO_TGTPORT,
        AIO_TGTUSER,
        AIO_TGTPASS,
        HT_PROXYPID,

        AIO_CLRNAME,
        AIO_ADDNAME,
        AIO_BYPNAME,

        AIO_PRINTLOG
    }

    public static void SetBinaryDirectory(string path) => SetDllDirectory(path);
    public static bool Dial(NameList name, bool value)
    {
        return aio_dial(name, value.ToString().ToLower());
    }

    public static bool Dial(NameList name, string value)
    {
        return aio_dial(name, value);
    }

    public static Task<bool> InitAsync(bool isHttpProxy)
    {
        if (isHttpProxy)
        {
            var p = new System.Diagnostics.Process();
            p.StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardOutput = true
            };
            p.Start();
            var line = p.StandardOutput.ReadToEnd().Split(Environment.NewLine).Where(x => x.Contains("LISTENING") && x.Contains(NFAPI.Port.ToString())).First();
            var pid = line[(line.LastIndexOf("LISTENING") + 9)..].Trim();
            Dial(NameList.HT_PROXYPID, pid);
            return Task.Run(ht_start);
        }
        return Task.Run(aio_init);
    }

    public static Task<bool> FreeAsync()
    {
        return Task.Run(aio_free);
    }

    private const string Redirector_bin = "Redirector.dll";

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool SetDllDirectory(string lpPathName);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool aio_register([MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool aio_unregister([MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aio_dial(NameList name, [MarshalAs(UnmanagedType.LPWStr)] string value);

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aio_init();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aio_free();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong aio_getUP();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong aio_getDL();

    [DllImport(Redirector_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool ht_start();
}