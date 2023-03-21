using System.Diagnostics;
using System.ServiceProcess;
using static NetFilterAPI.Redirector;

namespace NetFilterAPI;

public static class NFAPI
{
    private static readonly ServiceController nfService = new("netfilter2");
    private static readonly string systemDriver = $"{Environment.SystemDirectory}\\drivers\\netfilter2.sys";
    private static string nfDriver = "nfdriver.sys";

    public static List<string> HandleList = new();
    public static List<string> BypassList = new();
    public static string Host = string.Empty;
    public static int Port = 0;

    public static void EnableLog(bool enabled) => Dial(NameList.AIO_PRINTLOG, enabled);
    public static async Task StartAsync(bool isHttpProxy = false, string username = null!, string password = null!)
    {
        CheckDriver();
        Dial(NameList.AIO_FILTERLOOPBACK, false);
        Dial(NameList.AIO_FILTERINTRANET, false);
        Dial(NameList.AIO_FILTERSELF, false);
        Dial(NameList.AIO_FILTERPARENT, false);
        Dial(NameList.AIO_FILTERICMP, false);

        Dial(NameList.AIO_FILTERTCP, true);
        Dial(NameList.AIO_FILTERUDP, true);

        // DNS
        Dial(NameList.AIO_FILTERDNS, true);
        Dial(NameList.AIO_DNSONLY, true);
        Dial(NameList.AIO_DNSPROX, true);
        Dial(NameList.AIO_DNSHOST, "8.8.8.8");
        Dial(NameList.AIO_DNSPORT, "53");

        // Server
        Dial(NameList.AIO_TGTHOST, Host);
        Dial(NameList.AIO_TGTPORT, Port.ToString());

        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
        {
            Dial(NameList.AIO_TGTUSER, username);
            Dial(NameList.AIO_TGTPASS, password);
        }

        // Mode Rule
        DialRule(HandleList, BypassList);

        if (!await InitAsync(isHttpProxy))
            throw new Exception("Redirector start failed.");
    }

    public static Task StopAsync()
    {
        return FreeAsync();
    }

    public static string GenerateInvalidRulesMessage(IEnumerable<string> rules)
    {
        return $"{string.Join("\n", rules)}\n" + "Above rules does not conform to C++ regular expression syntax";
    }

    private static void DialRule(IEnumerable<string> handle, IEnumerable<string> bypass)
    {
        Dial(NameList.AIO_CLRNAME, "");
        var invalidList = new List<string>();

        if (handle.Any())
        {
            foreach (var s in handle)
            {
                if (!Dial(NameList.AIO_ADDNAME, s))
                    invalidList.Add(s);
            }
        }

        if (bypass != default && bypass.Any())
        {
            foreach (var s in bypass)
            {
                if (!Dial(NameList.AIO_BYPNAME, s))
                    invalidList.Add(s);
            }
        }

        if (invalidList.Any())
            throw new Exception(GenerateInvalidRulesMessage(invalidList));
    }

    #region DriverUtil
    public static void SetDriverPath(string path) => nfDriver = path;
    internal static void CheckDriver()
    {
        var binFileVersion = FileVersionInfo.GetVersionInfo(nfDriver).FileVersion;
        var systemFileVersion = FileVersionInfo.GetVersionInfo(systemDriver).FileVersion;

        if (binFileVersion == null || systemFileVersion == null) throw new Exception("DRIVER NOT FOUND");

        if (!File.Exists(systemDriver))
        {
            // Install
            InstallDriver();
            return;
        }

        var reinstall = false;
        if (Version.TryParse(binFileVersion, out var binResult) && Version.TryParse(systemFileVersion, out var systemResult))
        {
            if (binResult.CompareTo(systemResult) > 0)
                // Update
                reinstall = true;
            else if (systemResult.Major != binResult.Major)
                // Downgrade when Major version different (may have breaking changes)
                reinstall = true;
        }
        else
        {
            // Parse File versionName to Version failed
            if (!systemFileVersion.Equals(binFileVersion))
                // versionNames are different, Reinstall
                reinstall = true;
        }

        if (!reinstall)
            return;

        UninstallDriver();
        InstallDriver();
    }

    /// <summary>
    ///     安装 NF 驱动
    /// </summary>
    /// <returns>驱动是否安装成功</returns>
    public static void InstallDriver()
    {
        if (!File.Exists(nfDriver))
            throw new Exception("builtin driver files missing, can't install NF driver");

        try
        {
            File.Copy(nfDriver, systemDriver);
        }
        catch (Exception e)
        {
            throw new Exception($"Copy netfilter2.sys failed\n{e.Message}");
        }

        // 注册驱动文件
        if (!aio_register("netfilter2"))
        {
            throw new Exception("Register netfilter2 failed");
        }
    }

    /// <summary>
    ///     卸载 NF 驱动
    /// </summary>
    /// <returns>是否成功卸载</returns>
    public static bool UninstallDriver()
    {
        try
        {
            if (nfService.Status == ServiceControllerStatus.Running)
            {
                nfService.Stop();
                nfService.WaitForStatus(ServiceControllerStatus.Stopped);
            }
        }
        catch (Exception)
        {
            // ignored
        }

        if (!File.Exists(systemDriver))
            return true;

        aio_unregister("netfilter2");
        File.Delete(systemDriver);

        return true;
    }
    #endregion
}