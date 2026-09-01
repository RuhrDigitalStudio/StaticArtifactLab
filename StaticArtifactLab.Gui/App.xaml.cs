using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace StaticArtifactLab.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Software mode keeps the workbench usable in restricted VMs and RDP sessions.
        if (e.Args.Contains("--software-rendering", StringComparer.Ordinal))
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        base.OnStartup(e);
    }
}
