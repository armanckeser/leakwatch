# Clicks at window-image pixel coordinates (as seen in shot.ps1 output). Usage: click.ps1 <process> <x> <y>
param([string]$Name = 'leakwatch', [int]$X, [int]$Y)
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class Clk {
  [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] static extern bool ScreenToClient(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  struct RECT { public int L,T,R,B; } struct POINT { public int X,Y; }
  public static void At(IntPtr h, int x, int y) {
    SetProcessDPIAware(); RECT r; GetWindowRect(h, out r);
    var p = new POINT { X = r.L + x, Y = r.T + y }; ScreenToClient(h, ref p);
    var l = (IntPtr)((p.Y << 16) | (p.X & 0xFFFF));
    PostMessage(h, 0x0200, IntPtr.Zero, l); PostMessage(h, 0x0201, (IntPtr)1, l); PostMessage(h, 0x0202, IntPtr.Zero, l);
  }
}
'@
[Clk]::At((Get-Process $Name | ? MainWindowHandle -ne 0 | select -First 1).MainWindowHandle, $X, $Y)
