<#
.SYNOPSIS
    DDS Console — WPF wizard for domain bootstrap + service health view.

.DESCRIPTION
    Two tabs:
      Bootstrap  — form (Name, OrgHash, FIDO2 yes/no), step-by-step
                   progress mirror of Bootstrap-DdsDomain.ps1, live log
                   pane that survives the run, "Copy log" button. The
                   underlying script is launched as a child process so
                   the UI shows real progress without re-implementing
                   the nine bootstrap steps.

      Health     — service status grid (refreshes every 2s), named-pipe
                   state, last 30 lines from authbridge.log, "Open Tray
                   Agent", "Refresh now" buttons.

    Self-elevates on launch.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Self-elevate ─────────────────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ── Paths ─────────────────────────────────────────────────────────
$BootstrapScript = Join-Path $InstallRoot "bin\Bootstrap-DdsDomain.ps1"
$TrayAgent       = Join-Path $InstallRoot "bin\DdsTrayAgent.exe"
$AuthBridgeLog   = Join-Path $DataRoot    "authbridge.log"

# ── XAML ──────────────────────────────────────────────────────────
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DDS Console" Height="640" Width="780"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="12">
  <TabControl>

    <!-- ============== BOOTSTRAP TAB ============== -->
    <TabItem Header="Bootstrap">
      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Form -->
        <Grid Grid.Row="0" Margin="0,0,0,10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="120"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <Label Grid.Row="0" Grid.Column="0" Content="Domain name:" VerticalAlignment="Center"/>
          <TextBox Grid.Row="0" Grid.Column="1" x:Name="TbName" Text="local.test" Margin="0,3" Padding="4,3"/>

          <Label Grid.Row="1" Grid.Column="0" Content="Org hash:" VerticalAlignment="Center"/>
          <TextBox Grid.Row="1" Grid.Column="1" x:Name="TbOrg" Text="local" Margin="0,3" Padding="4,3"/>

          <Label Grid.Row="2" Grid.Column="0" Content="Auth method:" VerticalAlignment="Center"/>
          <StackPanel Grid.Row="2" Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
            <RadioButton x:Name="RbFido2" Content="FIDO2 (touch your security key)" IsChecked="True" Margin="0,0,15,0"/>
            <RadioButton x:Name="RbPass"  Content="Passphrase"/>
          </StackPanel>

          <Label Grid.Row="3" Grid.Column="0" Content="Existing state:" VerticalAlignment="Center"/>
          <CheckBox Grid.Row="3" Grid.Column="1" x:Name="CbForce" Content="Wipe existing domain state if present (required for re-bootstrap)" VerticalAlignment="Center"/>
        </Grid>

        <!-- Step list -->
        <Border Grid.Row="1" BorderBrush="#cccccc" BorderThickness="1" Padding="6" Margin="0,0,0,8">
          <ItemsControl x:Name="Steps">
            <ItemsControl.ItemTemplate>
              <DataTemplate>
                <StackPanel Orientation="Horizontal" Margin="0,1">
                  <TextBlock Text="{Binding Icon}" FontSize="14" Width="22"/>
                  <TextBlock Text="{Binding Label}" Foreground="{Binding Color}"/>
                </StackPanel>
              </DataTemplate>
            </ItemsControl.ItemTemplate>
          </ItemsControl>
        </Border>

        <!-- Status line -->
        <TextBlock Grid.Row="2" x:Name="TbStatus" Text="Ready." Margin="0,0,0,4" FontWeight="SemiBold"/>

        <!-- Log -->
        <TextBox Grid.Row="3" x:Name="TbLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>

        <!-- Buttons -->
        <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
          <Button x:Name="BtnRun"  Content="Run Bootstrap"  Padding="14,4" Margin="4"/>
          <Button x:Name="BtnCopy" Content="Copy Log"        Padding="14,4" Margin="4"/>
          <Button x:Name="BtnOpenLog" Content="Open Transcript Folder" Padding="14,4" Margin="4"/>
        </StackPanel>
      </Grid>
    </TabItem>

    <!-- ============== HEALTH TAB ============== -->
    <TabItem Header="Health">
      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <DataGrid Grid.Row="0" x:Name="DgServices" AutoGenerateColumns="False" CanUserAddRows="False"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal" Margin="0,0,0,8" Height="120"
                  IsReadOnly="True">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Service"   Binding="{Binding Name}"      Width="160"/>
            <DataGridTextColumn Header="Status"    Binding="{Binding Status}"    Width="120"/>
            <DataGridTextColumn Header="StartType" Binding="{Binding StartType}" Width="100"/>
            <DataGridTextColumn Header="Bin path"  Binding="{Binding BinPath}"   Width="*"/>
          </DataGrid.Columns>
        </DataGrid>

        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,8">
          <TextBlock x:Name="TbPipe" Text="" Margin="0,0,15,0" VerticalAlignment="Center"/>
          <TextBlock x:Name="TbStateInv" Text="" Margin="0,0,15,0" VerticalAlignment="Center" FontFamily="Consolas"/>
        </StackPanel>

        <!-- Log tail -->
        <GroupBox Grid.Row="2" Header="authbridge.log (tail)">
          <TextBox x:Name="TbLogTail" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
        </GroupBox>

        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
          <Button x:Name="BtnRefresh" Content="Refresh now" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnTray"    Content="Open Tray Agent" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStartAll" Content="Start all services" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStopAll"  Content="Stop all services"  Padding="14,4" Margin="4"/>
        </StackPanel>
      </Grid>
    </TabItem>

  </TabControl>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Resolve named elements
$el = @{}
foreach ($n in 'TbName','TbOrg','RbFido2','RbPass','CbForce','Steps','TbStatus','TbLog',
                'BtnRun','BtnCopy','BtnOpenLog',
                'DgServices','TbPipe','TbStateInv','TbLogTail',
                'BtnRefresh','BtnTray','BtnStartAll','BtnStopAll') {
    $el[$n] = $window.FindName($n)
}

# ── Bootstrap step model ──────────────────────────────────────────
$stepDefs = @(
    @{ Idx=1; Label="Create domain (init-domain --fido2)" }
    @{ Idx=2; Label="Generate provision bundle" }
    @{ Idx=3; Label="Generate node libp2p identity" }
    @{ Idx=4; Label="Self-admit this node" }
    @{ Idx=5; Label="Write node configuration" }
    @{ Idx=6; Label="Start DdsNode service + wait for pipe" }
    @{ Idx=7; Label="Enroll device via /v1/enroll/device" }
    @{ Idx=8; Label="Stamp DeviceUrn into appsettings.json" }
    @{ Idx=9; Label="Start DdsAuthBridge + DdsPolicyAgent" }
)
$stepItems = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
function Reset-Steps {
    $stepItems.Clear()
    foreach ($s in $stepDefs) {
        $stepItems.Add([pscustomobject]@{
            Idx   = $s.Idx
            Label = ("[{0}/9] {1}" -f $s.Idx, $s.Label)
            Icon  = [char]0x25CB   # ○ open circle
            Color = '#666666'
        })
    }
}
function Mark-Step {
    param([int]$Idx, [string]$State)  # 'running' | 'ok' | 'fail'
    for ($i = 0; $i -lt $stepItems.Count; $i++) {
        if ($stepItems[$i].Idx -eq $Idx) {
            switch ($State) {
                'running' { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x25B6; Color='#0078d4' } }  # ▶ blue
                'ok'      { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x2714; Color='#107C10' } }  # ✔ green
                'fail'    { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x2716; Color='#D13438' } }  # ✖ red
            }
            return
        }
    }
}
$el.Steps.ItemsSource = $stepItems
Reset-Steps

# ── Helpers ───────────────────────────────────────────────────────
function Append-Log { param([string]$line)
    $el.TbLog.AppendText($line + "`r`n")
    $el.TbLog.ScrollToEnd()
}
function Set-Status { param([string]$msg, [string]$color='#000000')
    $el.TbStatus.Text = $msg
    $el.TbStatus.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($color)
}

function Refresh-Health {
    $rows = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
    foreach ($svc in @('DdsNode','DdsAuthBridge','DdsPolicyAgent')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        $bin = ''
        if ($s) {
            try { $bin = (Get-CimInstance Win32_Service -Filter "Name='$svc'").PathName } catch { $bin = '' }
        }
        $rows.Add([pscustomobject]@{
            Name      = $svc
            Status    = if ($s) { $s.Status } else { 'not registered' }
            StartType = if ($s) { $s.StartType } else { '-' }
            BinPath   = $bin
        })
    }
    $el.DgServices.ItemsSource = $rows

    $pipe = Test-Path '\\.\pipe\dds-api'
    if ($pipe) {
        $el.TbPipe.Text = "DdsNode pipe: OPEN (\\.\pipe\dds-api)"
        $el.TbPipe.Foreground = [Windows.Media.Brushes]::Green
    } else {
        $el.TbPipe.Text = "DdsNode pipe: closed"
        $el.TbPipe.Foreground = [Windows.Media.Brushes]::DarkOrange
    }

    $found = @()
    foreach ($p in @(
        @{ P='C:\ProgramData\DDS\node-data\domain.toml';     L='domain.toml' }
        @{ P='C:\ProgramData\DDS\node-data\domain_key.bin';  L='domain_key.bin' }
        @{ P='C:\ProgramData\DDS\node-data\admission.cbor';  L='admission.cbor' }
        @{ P='C:\Program Files\DDS\config\node.toml';        L='config\node.toml' }
        @{ P='C:\ProgramData\DDS\provision.dds';             L='provision.dds' }
    )) {
        if (Test-Path $p.P) { $found += $p.L }
    }
    $el.TbStateInv.Text = if ($found.Count -gt 0) { "State: " + ($found -join ', ') } else { "State: (none)" }

    if (Test-Path $AuthBridgeLog) {
        try {
            $tail = Get-Content $AuthBridgeLog -Tail 30 -ErrorAction Stop
            $el.TbLogTail.Text = $tail -join "`r`n"
            $el.TbLogTail.ScrollToEnd()
        } catch {
            $el.TbLogTail.Text = "(unable to read $AuthBridgeLog: $($_.Exception.Message))"
        }
    } else {
        $el.TbLogTail.Text = "(authbridge.log not present yet)"
    }
}

# Auto-refresh timer (every 2s)
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)
$timer.Add_Tick({ Refresh-Health })
$timer.Start()

# ── Bootstrap orchestration ───────────────────────────────────────
$bootstrapProcess = $null
function Run-Bootstrap {
    if (-not (Test-Path $BootstrapScript)) {
        Append-Log "ERROR: Bootstrap-DdsDomain.ps1 not found at $BootstrapScript"
        Set-Status "Bootstrap script missing — reinstall the MSI." '#D13438'
        return
    }
    if ([string]::IsNullOrWhiteSpace($el.TbName.Text))    { Set-Status "Domain name is required."     '#D13438'; return }
    if ([string]::IsNullOrWhiteSpace($el.TbOrg.Text))     { Set-Status "Org hash is required."        '#D13438'; return }

    $el.BtnRun.IsEnabled = $false
    $el.TbLog.Clear()
    Reset-Steps
    Set-Status "Bootstrap starting…" '#0078d4'

    $args = @(
        '-NoProfile','-ExecutionPolicy','Bypass',
        '-File', "`"$BootstrapScript`"",
        '-Name',     "`"$($el.TbName.Text.Trim())`"",
        '-OrgHash',  "`"$($el.TbOrg.Text.Trim())`""
    )
    if ($el.RbPass.IsChecked) { $args += '-NoFido2' }
    if ($el.CbForce.IsChecked) { $args += '-Force' }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $script:bootstrapProcess = New-Object System.Diagnostics.Process
    $script:bootstrapProcess.StartInfo = $psi
    $script:bootstrapProcess.EnableRaisingEvents = $true

    $rxStep = [regex]'\[(\d)/9\]'
    $rxFail = [regex](?i)'(error|exception|failed|throw)'

    $handler = {
        param($s, $e)
        if ($null -eq $e.Data) { return }
        $line = $e.Data
        $window.Dispatcher.Invoke([action]{
            Append-Log $line
            $m = $rxStep.Match($line)
            if ($m.Success) {
                $idx = [int]$m.Groups[1].Value
                # Mark previous step as ok, current as running
                if ($idx -gt 1) { Mark-Step -Idx ($idx - 1) -State 'ok' }
                Mark-Step -Idx $idx -State 'running'
            }
            if ($line -like '*Bootstrap Complete*') {
                Mark-Step -Idx 9 -State 'ok'
            }
            if ($line -like 'Bootstrap FAILED*' -or $line -like 'Error*') {
                # mark the running step (if any) as failed
                for ($i = $stepItems.Count - 1; $i -ge 0; $i--) {
                    if ($stepItems[$i].Color -eq '#0078d4') { Mark-Step -Idx $stepItems[$i].Idx -State 'fail'; break }
                }
            }
        })
    }
    $script:bootstrapProcess.add_OutputDataReceived($handler)
    $script:bootstrapProcess.add_ErrorDataReceived($handler)

    $exitHandler = {
        $window.Dispatcher.Invoke([action]{
            $code = $script:bootstrapProcess.ExitCode
            if ($code -eq 0) {
                Set-Status "Bootstrap completed successfully." '#107C10'
                # Mark any leftover running step as ok
                for ($i = 0; $i -lt $stepItems.Count; $i++) {
                    if ($stepItems[$i].Color -eq '#0078d4') { Mark-Step -Idx $stepItems[$i].Idx -State 'ok' }
                }
            } else {
                Set-Status "Bootstrap failed (exit $code). See log + transcript." '#D13438'
            }
            $el.BtnRun.IsEnabled = $true
            Refresh-Health
        })
    }
    $script:bootstrapProcess.add_Exited($exitHandler)

    $script:bootstrapProcess.Start() | Out-Null
    $script:bootstrapProcess.BeginOutputReadLine()
    $script:bootstrapProcess.BeginErrorReadLine()
}

# ── Wire up ───────────────────────────────────────────────────────
$el.BtnRun.add_Click({ Run-Bootstrap })
$el.BtnCopy.add_Click({
    [Windows.Clipboard]::SetText($el.TbLog.Text)
    Set-Status "Log copied to clipboard." '#107C10'
})
$el.BtnOpenLog.add_Click({ Start-Process $env:TEMP })
$el.BtnRefresh.add_Click({ Refresh-Health })
$el.BtnTray.add_Click({
    if (Test-Path $TrayAgent) { Start-Process $TrayAgent }
    else { Set-Status "DdsTrayAgent.exe not found at $TrayAgent" '#D13438' }
})
$el.BtnStartAll.add_Click({
    foreach ($svc in @('DdsNode','DdsAuthBridge','DdsPolicyAgent')) {
        try { Start-Service -Name $svc -ErrorAction Stop } catch { }
    }
    Refresh-Health
})
$el.BtnStopAll.add_Click({
    foreach ($svc in @('DdsPolicyAgent','DdsAuthBridge','DdsNode')) {
        try { Stop-Service -Name $svc -Force -ErrorAction Stop } catch { }
    }
    Refresh-Health
})

$window.add_Closed({ $timer.Stop() })

Refresh-Health
$window.ShowDialog() | Out-Null
