# Records a window to numbered PNG frames, optionally clicking a point partway through.
# Usage: record.ps1 -Name leakwatch -Out frames -Seconds 10 -Fps 15 [-ClickAt 3 -X 300 -Y 745]
# X/Y are window-image pixels, the same coordinates shot.ps1 screenshots use.
param(
    [string]$Name = 'leakwatch',
    [string]$Out = "$env:TEMP\leakwatch-frames",
    [double]$Seconds = 10,
    [int]$Fps = 15,
    [double]$ClickAt = -1,
    [int]$X = 0,
    [int]$Y = 0
)
Add-Type -ReferencedAssemblies System.Drawing @'
using System; using System.Drawing; using System.Drawing.Imaging; using System.Runtime.InteropServices;
public static class Rec {
  [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  [DllImport("user32.dll")] static extern bool ScreenToClient(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] static extern IntPtr PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  struct RECT { public int L,T,R,B; } struct POINT { public int X,Y; }
  public static void Init() { SetProcessDPIAware(); }
  public static void Frame(IntPtr h, string path) {
    RECT r; GetWindowRect(h, out r);
    using (var bmp = new Bitmap(r.R-r.L, r.B-r.T)) {
      using (var g = Graphics.FromImage(bmp)) { var dc = g.GetHdc(); PrintWindow(h, dc, 2); g.ReleaseHdc(dc); }
      bmp.Save(path, ImageFormat.Png);
    }
  }
  public static void Click(IntPtr h, int x, int y) {
    RECT r; GetWindowRect(h, out r);
    var p = new POINT { X = r.L + x, Y = r.T + y }; ScreenToClient(h, ref p);
    var l = (IntPtr)((p.Y << 16) | (p.X & 0xFFFF));
    PostMessage(h, 0x0200, IntPtr.Zero, l); PostMessage(h, 0x0201, (IntPtr)1, l); PostMessage(h, 0x0202, IntPtr.Zero, l);
    // Move the pointer off the button so its tooltip does not cover the recording.
    var away = new POINT { X = r.R - 60, Y = r.B - 60 }; ScreenToClient(h, ref away);
    PostMessage(h, 0x0200, IntPtr.Zero, (IntPtr)((away.Y << 16) | (away.X & 0xFFFF)));
  }
}
'@
[Rec]::Init()
New-Item -ItemType Directory -Force $Out | Out-Null
Get-ChildItem $Out -Filter *.png | Remove-Item
$h = (Get-Process $Name | Where-Object MainWindowHandle -ne 0 | Select-Object -First 1).MainWindowHandle
$sw = [Diagnostics.Stopwatch]::StartNew()
$i = 0; $clicked = $false
while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    if ($ClickAt -ge 0 -and -not $clicked -and $sw.Elapsed.TotalSeconds -ge $ClickAt) { [Rec]::Click($h, $X, $Y); $clicked = $true }
    [Rec]::Frame($h, ("{0}\f{1:D4}.png" -f $Out, $i)); $i++
    $next = $i / $Fps
    $wait = $next - $sw.Elapsed.TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
}
"$i frames in $([math]::Round($sw.Elapsed.TotalSeconds,1)) s"
