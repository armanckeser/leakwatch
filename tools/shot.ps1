# Saves a screenshot of a process's main window, even when covered. Usage: shot.ps1 <process> <out.png>
param([string]$Name = 'leakwatch', [string]$Out = "$env:TEMP\leakwatch.png")
Add-Type -ReferencedAssemblies System.Drawing @'
using System; using System.Drawing; using System.Runtime.InteropServices;
public static class Cap {
  [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  struct RECT { public int L,T,R,B; }
  public static string Shot(IntPtr h, string path) {
    SetProcessDPIAware(); RECT r; GetWindowRect(h, out r);
    var bmp = new Bitmap(r.R-r.L, r.B-r.T); using (var g = Graphics.FromImage(bmp)) { var dc = g.GetHdc(); PrintWindow(h, dc, 2); g.ReleaseHdc(dc); }
    bmp.Save(path); return (r.R-r.L) + "x" + (r.B-r.T);
  }
}
'@
[Cap]::Shot((Get-Process $Name | ? MainWindowHandle -ne 0 | select -First 1).MainWindowHandle, $Out)
