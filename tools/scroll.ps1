# Scrolls a process's main window down by sending wheel events to its centre. Usage: scroll.ps1 <process> <notches>
param([string]$Name = 'leakwatch', [int]$Notches = 10)
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class Wheel {
  [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  struct RECT { public int L,T,R,B; }
  public static void Down(IntPtr h, int n) {
    SetProcessDPIAware(); RECT r; GetWindowRect(h, out r);
    int x = (r.L + r.R) / 2 - 300, y = (r.T + r.B) / 2;
    for (int i = 0; i < n; i++) PostMessage(h, 0x020A, (IntPtr)((-120) << 16), (IntPtr)((y << 16) | (x & 0xFFFF)));
  }
}
'@
[Wheel]::Down((Get-Process $Name | ? MainWindowHandle -ne 0 | select -First 1).MainWindowHandle, $Notches)
