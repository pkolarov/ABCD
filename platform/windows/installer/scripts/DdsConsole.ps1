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

# Transcript so a crash before ShowDialog() leaves a forensic trail.
$logPath = Join-Path $env:TEMP ("dds-console-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $logPath -Force | Out-Null } catch { }

# Catch-all trap — pops a MessageBox so an instant-close window still
# tells the operator what happened, then waits for an Enter so the
# console window stays up too.
trap {
    $msg = "DdsConsole.ps1 crashed:`r`n`r`n$($_.Exception.Message)"
    if ($_.InvocationInfo) {
        $msg += "`r`n`r`nat $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
        $msg += "`r`n  $($_.InvocationInfo.Line.Trim())"
    }
    $msg += "`r`n`r`nTranscript: $logPath"
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction SilentlyContinue
        [Windows.MessageBox]::Show($msg, "DDS Console - Error", 'OK', 'Error') | Out-Null
    } catch {
        Write-Host $msg -ForegroundColor Red
    }
    Write-Host $msg -ForegroundColor Red
    try { Stop-Transcript | Out-Null } catch { }
    Read-Host "Press Enter to close"
    exit 1
}

# ── Self-elevate ─────────────────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ── Installed product version ─────────────────────────────────────
# Stamped by the MSI at HKLM\SOFTWARE\DDS\Version. Falls back to a
# development placeholder when run from a source tree before install.
function Get-DdsInstalledVersion {
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\DDS' -Name 'Version' -ErrorAction Stop).Version
        if ($v) { return $v }
    } catch { }
    return 'dev'
}
$DdsVersion = Get-DdsInstalledVersion

# ── Paths ─────────────────────────────────────────────────────────
$BootstrapScript = Join-Path $InstallRoot "bin\Bootstrap-DdsDomain.ps1"
$TrayAgent       = Join-Path $InstallRoot "bin\DdsTrayAgent.exe"
$NodeBin         = Join-Path $InstallRoot "bin\dds-node.exe"
$AuthBridgeLog   = Join-Path $DataRoot    "authbridge.log"
$ProvisionBundle = Join-Path $DataRoot    "provision.dds"
$NodeData        = Join-Path $DataRoot    "node-data"
$AdmissionCert   = Join-Path $NodeData    "admission.cbor"
$NodeConfigFile  = Join-Path $InstallRoot "config\node.toml"

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

    <!-- ============== PROVISION TAB ============== -->
    <TabItem Header="Provision">
      <Grid Margin="10">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Status block -->
        <Border Grid.Row="0" BorderBrush="#cccccc" BorderThickness="1" Padding="8" Margin="0,0,0,8">
          <StackPanel>
            <TextBlock x:Name="TbProvJoinState" FontWeight="SemiBold" Text="Checking domain state..."/>
            <TextBlock x:Name="TbProvJoinDetail" Foreground="#555555" Margin="0,2,0,0" TextWrapping="Wrap"/>
          </StackPanel>
        </Border>

        <!-- Export -->
        <GroupBox Grid.Row="1" Header="Export provision bundle (use to onboard new machines)" Margin="0,0,0,8">
          <StackPanel Margin="6">
            <TextBlock TextWrapping="Wrap" Margin="0,0,0,6">
              The bundle is FIDO2-sealed at rest. The recipient machine still needs the admin's hardware key to unseal it during import. Keep it on encrypted media or a controlled share.
            </TextBlock>
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnProvExport" Content="Export provision.dds..." Padding="14,4" Margin="0,0,8,0"/>
              <TextBlock x:Name="TbProvExportStatus" VerticalAlignment="Center" Foreground="#555555"/>
            </StackPanel>
          </StackPanel>
        </GroupBox>

        <!-- Import -->
        <GroupBox Grid.Row="2" Header="Import provision bundle (join an existing domain)" Margin="0,0,0,8">
          <StackPanel Margin="6">
            <TextBlock x:Name="TbProvImportHint" TextWrapping="Wrap" Margin="0,0,0,6"
                       Text="Pick a provision.dds copied from another machine in the domain. The admin's FIDO2 key must be present to unseal it."/>
            <StackPanel Orientation="Horizontal">
              <Button x:Name="BtnProvImport" Content="Import provision.dds..." Padding="14,4" Margin="0,0,8,0"/>
              <TextBlock x:Name="TbProvImportStatus" VerticalAlignment="Center" Foreground="#555555"/>
            </StackPanel>
          </StackPanel>
        </GroupBox>

        <!-- Output -->
        <GroupBox Grid.Row="3" Header="Output">
          <TextBox x:Name="TbProvLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
        </GroupBox>
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
$window.Title = "DDS Console  -  v$DdsVersion"

# Resolve named elements
$el = @{}
foreach ($n in 'TbName','TbOrg','RbFido2','RbPass','CbForce','Steps','TbStatus','TbLog',
                'BtnRun','BtnCopy','BtnOpenLog',
                'TbProvJoinState','TbProvJoinDetail',
                'BtnProvExport','TbProvExportStatus',
                'BtnProvImport','TbProvImportStatus','TbProvImportHint',
                'TbProvLog',
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
            $el.TbLogTail.Text = "(unable to read ${AuthBridgeLog}: $($_.Exception.Message))"
        }
    } else {
        $el.TbLogTail.Text = "(authbridge.log not present yet)"
    }
}

# ── Provision tab ─────────────────────────────────────────────────
#
# Detection of "already part of a domain":
#   - admission.cbor present in node-data  (this peer was admitted), OR
#   - $InstallRoot\config\node.toml exists (running node config wired up)
# Either signal means `dds-node provision` would refuse, so we hide
# Import behind a disabled state.
function Test-DomainJoined {
    return (Test-Path $AdmissionCert) -or (Test-Path $NodeConfigFile)
}

function Append-ProvLog { param([string]$line)
    $el.TbProvLog.AppendText($line + "`r`n")
    $el.TbProvLog.ScrollToEnd()
}

function Refresh-Provision {
    $joined = Test-DomainJoined
    if ($joined) {
        $el.TbProvJoinState.Text = "This machine: domain member"
        $el.TbProvJoinState.Foreground = [Windows.Media.Brushes]::DarkGreen
        $detail = @()
        if (Test-Path $AdmissionCert)  { $detail += "admission.cbor present" }
        if (Test-Path $NodeConfigFile) { $detail += "node.toml configured" }
        $el.TbProvJoinDetail.Text = ($detail -join '; ')
    } else {
        $el.TbProvJoinState.Text = "This machine: not part of any domain"
        $el.TbProvJoinState.Foreground = [Windows.Media.Brushes]::DarkOrange
        $el.TbProvJoinDetail.Text = "Bootstrap a new domain or import a provision bundle from an existing one."
    }

    # Export: enabled iff the bundle file actually exists.
    if (Test-Path $ProvisionBundle) {
        $el.BtnProvExport.IsEnabled = $true
        $el.TbProvExportStatus.Text = "Source: $ProvisionBundle"
    } else {
        $el.BtnProvExport.IsEnabled = $false
        $el.TbProvExportStatus.Text = "No provision bundle on this machine ($ProvisionBundle missing)."
    }

    # Import: disabled if already joined (and explain why).
    if ($joined) {
        $el.BtnProvImport.IsEnabled = $false
        $el.TbProvImportHint.Text =
            "Import is disabled because this machine is already part of a domain. " +
            "To re-provision, first wipe the existing state via the Bootstrap tab " +
            "(check 'Wipe existing domain state') or remove " +
            "$NodeData and $NodeConfigFile manually."
        $el.TbProvImportStatus.Text = "(disabled — already joined)"
    } else {
        $el.BtnProvImport.IsEnabled = $true
        $el.TbProvImportHint.Text =
            "Pick a provision.dds copied from another machine in the domain. " +
            "The admin's FIDO2 key must be present to unseal it."
        $el.TbProvImportStatus.Text = ""
    }
}

# Auto-refresh timer (every 2s)
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(2)
$timer.Add_Tick({ Refresh-Health; Refresh-Provision })
$timer.Start()

# ── Bootstrap orchestration ───────────────────────────────────────
#
# Spawn the bootstrap script in its OWN visible PowerShell console
# (not redirected) so:
#   - dds-node init-domain --fido2 has a real stdin for FIDO2 PIN
#     prompts (a redirected child is treated as non-interactive by
#     libfido2 and times out with CTAP2_ERR_USER_ACTION_TIMEOUT).
#   - The user can see the FIDO2 "touch your key" instruction.
#
# Console watches the bootstrap's transcript file (Start-Transcript in
# Bootstrap-DdsDomain.ps1 already writes one) and tails it into the
# log pane + step list. When the child process exits, refresh Health.
$script:bootstrapProcess  = $null
$script:bootstrapLogPath  = $null
$script:bootstrapTailPos  = 0
$script:bootstrapTimer    = $null
$rxStepGlobal = [regex]'\[(\d)/9\]'

function Stop-BootstrapTail {
    if ($script:bootstrapTimer) { $script:bootstrapTimer.Stop(); $script:bootstrapTimer = $null }
}

function Tick-BootstrapTail {
    if (-not $script:bootstrapLogPath -or -not (Test-Path $script:bootstrapLogPath)) { return }
    try {
        $fs = [IO.File]::Open($script:bootstrapLogPath, 'Open', 'Read', 'ReadWrite')
        try {
            if ($fs.Length -le $script:bootstrapTailPos) { return }
            $fs.Seek($script:bootstrapTailPos, 'Begin') | Out-Null
            $reader = New-Object IO.StreamReader $fs
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($null -eq $line) { break }
                Append-Log $line
                $m = $rxStepGlobal.Match($line)
                if ($m.Success) {
                    $idx = [int]$m.Groups[1].Value
                    if ($idx -gt 1) { Mark-Step -Idx ($idx - 1) -State 'ok' }
                    Mark-Step -Idx $idx -State 'running'
                }
                if ($line -like '*Bootstrap Complete*') { Mark-Step -Idx 9 -State 'ok' }
                if ($line -like '*Bootstrap FAILED*' -or $line -like 'Error:*') {
                    for ($i = $stepItems.Count - 1; $i -ge 0; $i--) {
                        if ($stepItems[$i].Color -eq '#0078d4') {
                            Mark-Step -Idx $stepItems[$i].Idx -State 'fail'
                            break
                        }
                    }
                }
            }
            $script:bootstrapTailPos = $fs.Position
        } finally { $fs.Dispose() }
    } catch { }
    # If the process exited and we've drained the log, finalize.
    if ($script:bootstrapProcess -and $script:bootstrapProcess.HasExited) {
        Stop-BootstrapTail
        $code = $script:bootstrapProcess.ExitCode
        if ($code -eq 0) {
            Set-Status "Bootstrap completed successfully." '#107C10'
            for ($i = 0; $i -lt $stepItems.Count; $i++) {
                if ($stepItems[$i].Color -eq '#0078d4') { Mark-Step -Idx $stepItems[$i].Idx -State 'ok' }
            }
        } else {
            Set-Status "Bootstrap failed (exit $code). See log pane + transcript." '#D13438'
        }
        $el.BtnRun.IsEnabled = $true
        Refresh-Health
    }
}

function Run-Bootstrap {
    if (-not (Test-Path $BootstrapScript)) {
        Append-Log "ERROR: Bootstrap-DdsDomain.ps1 not found at $BootstrapScript"
        Set-Status "Bootstrap script missing - reinstall the MSI." '#D13438'
        return
    }
    if ([string]::IsNullOrWhiteSpace($el.TbName.Text)) { Set-Status "Domain name is required." '#D13438'; return }
    if ([string]::IsNullOrWhiteSpace($el.TbOrg.Text))  { Set-Status "Org hash is required."   '#D13438'; return }

    $el.BtnRun.IsEnabled = $false
    $el.TbLog.Clear()
    Reset-Steps
    Set-Status "Bootstrap window launched - touch your FIDO2 key when prompted there." '#0078d4'

    # Pre-compute the transcript path the bootstrap script will write,
    # then pass it down so we know where to tail. Bootstrap-DdsDomain.ps1
    # uses Get-Date inside Start-Transcript so we'd race against it; pin
    # the path here with a unique tag and override via env var.
    $script:bootstrapLogPath = Join-Path $env:TEMP ("dds-bootstrap-console-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:bootstrapTailPos = 0
    $env:DDS_BOOTSTRAP_TRANSCRIPT = $script:bootstrapLogPath

    $args = @(
        '-NoProfile','-ExecutionPolicy','Bypass',
        '-File', "`"$BootstrapScript`"",
        '-Name',     "`"$($el.TbName.Text.Trim())`"",
        '-OrgHash',  "`"$($el.TbOrg.Text.Trim())`""
    )
    if ($el.RbPass.IsChecked)  { $args += '-NoFido2' }
    if ($el.CbForce.IsChecked) { $args += '-Force' }

    # Visible window (no -WindowStyle Hidden, no CreateNoWindow). The
    # bootstrap script's existing trap+pause keeps the window open on
    # both success and failure so the user can read the result.
    $script:bootstrapProcess = Start-Process `
        -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList $args `
        -PassThru

    # Tail the transcript for live progress in the Console UI.
    Append-Log "[Console] Bootstrap window launched (PID $($script:bootstrapProcess.Id))."
    Append-Log "[Console] Transcript: $script:bootstrapLogPath"
    Append-Log "[Console] Tailing for progress..."

    $script:bootstrapTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:bootstrapTimer.Interval = [TimeSpan]::FromMilliseconds(700)
    $script:bootstrapTimer.Add_Tick({ Tick-BootstrapTail })
    $script:bootstrapTimer.Start()
}

# ── Provision: export + import handlers ───────────────────────────
function Run-ProvisionExport {
    if (-not (Test-Path $ProvisionBundle)) {
        $el.TbProvExportStatus.Text = "Bundle missing — bootstrap a domain first."
        return
    }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = "Export DDS provision bundle"
    $dlg.FileName = "provision.dds"
    $dlg.Filter = "DDS Provision Bundle (*.dds)|*.dds|All files (*.*)|*.*"
    $dlg.OverwritePrompt = $true
    if (-not $dlg.ShowDialog($window)) { return }
    $dst = $dlg.FileName

    # Stream copy via a temp file in the destination folder, then rename
    # into place. Open the source with FileShare.ReadWrite so we don't
    # collide with dds-node briefly reading the bundle during service
    # start. Retry up to 3x on sharing violations (common cause: AV /
    # OneDrive / Defender holding the destination just after creation).
    $maxAttempts = 3
    $attempt = 0
    while ($true) {
        $attempt++
        $tmp = "$dst.tmp-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        try {
            $src = [System.IO.File]::Open($ProvisionBundle, 'Open', 'Read', 'ReadWrite')
            try {
                $out = [System.IO.File]::Open($tmp, 'Create', 'Write', 'None')
                try { $src.CopyTo($out) } finally { $out.Close() }
            } finally { $src.Close() }
            if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Force }
            Move-Item -LiteralPath $tmp -Destination $dst -Force
            $el.TbProvExportStatus.Text = "Copied to $dst"
            $el.TbProvExportStatus.Foreground = [Windows.Media.Brushes]::DarkGreen
            Append-ProvLog "[Export] $ProvisionBundle -> $dst"
            return
        } catch [System.IO.IOException] {
            if (Test-Path -LiteralPath $tmp) { try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { } }
            # IOException covers sharing violations and "in use" errors.
            # Retry only those; surface the rest immediately.
            $hresult = $_.Exception.HResult
            $isSharing = (($hresult -band 0xFFFF) -eq 32) -or (($hresult -band 0xFFFF) -eq 33)  # ERROR_SHARING_VIOLATION / LOCK_VIOLATION
            if ($isSharing -and $attempt -lt $maxAttempts) {
                Append-ProvLog "[Export] sharing violation on attempt $attempt; retrying..."
                Start-Sleep -Milliseconds 400
                continue
            }
            $msg = "$($_.Exception.Message) (source=$ProvisionBundle, dest=$dst)"
            $el.TbProvExportStatus.Text = "Export failed: $msg"
            $el.TbProvExportStatus.Foreground = [Windows.Media.Brushes]::DarkRed
            Append-ProvLog "[Export] FAILED after $attempt attempt(s): $msg"
            return
        } catch {
            if (Test-Path -LiteralPath $tmp) { try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { } }
            $msg = "$($_.Exception.Message) (source=$ProvisionBundle, dest=$dst)"
            $el.TbProvExportStatus.Text = "Export failed: $msg"
            $el.TbProvExportStatus.Foreground = [Windows.Media.Brushes]::DarkRed
            Append-ProvLog "[Export] FAILED: $msg"
            return
        }
    }
}

function Run-ProvisionImport {
    # Re-check at click time to avoid TOCTOU between the timer refresh
    # and the user actually clicking.
    if (Test-DomainJoined) {
        $el.TbProvImportStatus.Text = "Already joined — import refused."
        return
    }
    if (-not (Test-Path $NodeBin)) {
        $el.TbProvImportStatus.Text = "dds-node.exe not found at $NodeBin."
        $el.TbProvImportStatus.Foreground = [Windows.Media.Brushes]::DarkRed
        return
    }
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = "Import DDS provision bundle"
    $dlg.Filter = "DDS Provision Bundle (*.dds)|*.dds|All files (*.*)|*.*"
    $dlg.CheckFileExists = $true
    if (-not $dlg.ShowDialog($window)) { return }
    $bundle = $dlg.FileName

    Append-ProvLog "[Import] Starting: $bundle"
    Append-ProvLog "[Import] A new window will open. Touch the admin's FIDO2 key when prompted."

    # Spawn a visible PowerShell window so dds-node provision has a real
    # console for the FIDO2 PIN/touch prompt (libfido2 treats redirected
    # children as non-interactive). Pause at the end so the operator can
    # read the result before the window closes.
    $cmd = @"
& '$NodeBin' provision '$bundle'
`$code = `$LASTEXITCODE
Write-Host ''
if (`$code -eq 0) {
    Write-Host '=== Provision Complete ===' -ForegroundColor Green
} else {
    Write-Host "=== Provision FAILED (exit `$code) ===" -ForegroundColor Red
}
Read-Host 'Press Enter to close'
exit `$code
"@
    $proc = Start-Process `
        -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command', $cmd) `
        -PassThru

    $el.BtnProvImport.IsEnabled = $false
    $el.TbProvImportStatus.Text = "Provisioning (PID $($proc.Id))..."
    $el.TbProvImportStatus.Foreground = [Windows.Media.Brushes]::Blue

    # Watch for exit and update UI; the timer-driven Refresh-Provision
    # will then notice the new admission.cbor / node.toml and flip into
    # the joined state.
    $watcher = New-Object System.Windows.Threading.DispatcherTimer
    $watcher.Interval = [TimeSpan]::FromMilliseconds(700)
    $watcher.Add_Tick({
        if ($proc.HasExited) {
            $watcher.Stop()
            $code = $proc.ExitCode
            if ($code -eq 0) {
                Append-ProvLog "[Import] Provision succeeded."
                $el.TbProvImportStatus.Text = "Provision succeeded."
                $el.TbProvImportStatus.Foreground = [Windows.Media.Brushes]::DarkGreen
            } else {
                Append-ProvLog "[Import] Provision failed (exit $code)."
                $el.TbProvImportStatus.Text = "Provision failed (exit $code)."
                $el.TbProvImportStatus.Foreground = [Windows.Media.Brushes]::DarkRed
            }
            Refresh-Provision
            Refresh-Health
        }
    })
    $watcher.Start()
}

# ── Wire up ───────────────────────────────────────────────────────
$el.BtnRun.add_Click({ Run-Bootstrap })
$el.BtnProvExport.add_Click({ Run-ProvisionExport })
$el.BtnProvImport.add_Click({ Run-ProvisionImport })
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
Refresh-Provision
$window.ShowDialog() | Out-Null
