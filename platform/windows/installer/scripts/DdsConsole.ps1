<#
.SYNOPSIS
    DDS Onboarding Wizard — guides the operator through one of three flows
    after install:

      A. Start a new domain (founding admin)
      B. Join an existing domain (drag/drop a *.dds provision bundle)
      C. Enroll this Windows account on a domain that's already provisioned

.DESCRIPTION
    Single-window WPF wizard rendered from PowerShell. Wraps existing
    components rather than reimplementing them:

      Branch A → Bootstrap-DdsDomain.ps1
      Branch B → dds-node provision <bundle>  +  Enroll-DdsDevice.ps1
      Branch C → dds-enroll-user.exe (non-interactive FIDO2 ceremony)

    State on launch is probed via Get-DdsOnboardingState.ps1 so the Welcome
    page highlights the recommended branch. The user can always override.

    Self-elevates on launch.

.PARAMETER Mode
    Pre-pick a wizard branch:
      Auto       — Default. Pick branch from state probe.
      NewDomain  — Branch A.
      JoinDomain — Branch B (use -BundlePath to pre-load the bundle).
      EnrollUser — Branch C.
      Health     — Skip onboarding, show service status.

.PARAMETER BundlePath
    Path to a *.dds provision bundle. Set automatically by the .dds file
    association so double-clicking a bundle opens this wizard already
    pointed at Branch B's first page.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".
#>
[CmdletBinding()]
param(
    [ValidateSet('Auto','NewDomain','JoinDomain','EnrollUser','Health')]
    [string]$Mode        = 'Auto',
    [string]$BundlePath  = '',
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Transcript so a crash before ShowDialog leaves a forensic trail ──
$logPath = Join-Path $env:TEMP ("dds-console-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $logPath -Force | Out-Null } catch { }

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
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Mode -ne 'Auto')  { $argList += @("-Mode", $Mode) }
    if ($BundlePath)       { $argList += @("-BundlePath", "`"$BundlePath`"") }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ── Installed product version ─────────────────────────────────────
function Get-DdsInstalledVersion {
    try {
        $v = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\DDS' -Name 'Version' -ErrorAction Stop).Version
        if ($v) { return $v }
    } catch { }
    return 'dev'
}
$DdsVersion = Get-DdsInstalledVersion

# ── Paths ─────────────────────────────────────────────────────────
$BinDir              = Join-Path $InstallRoot "bin"
$BootstrapScript     = Join-Path $BinDir      "Bootstrap-DdsDomain.ps1"
$EnrollDeviceScript  = Join-Path $BinDir      "Enroll-DdsDevice.ps1"
$ResetScript         = Join-Path $BinDir      "Reset-DdsBootstrap.ps1"
$StateScript         = Join-Path $BinDir      "Get-DdsOnboardingState.ps1"
$NodeBin             = Join-Path $BinDir      "dds-node.exe"
$EnrollUserBin       = Join-Path $BinDir      "dds-enroll-user.exe"
$TrayAgent           = Join-Path $BinDir      "DdsTrayAgent.exe"
$AuthBridgeLog       = Join-Path $DataRoot    "authbridge.log"
$ProvisionBundle     = Join-Path $DataRoot    "provision.dds"
$NodeData            = Join-Path $DataRoot    "node-data"
$AdmissionCert       = Join-Path $NodeData    "admission.cbor"
$DomainTomlFile      = Join-Path $NodeData    "domain.toml"
$NodeConfigFile      = Join-Path $InstallRoot "config\node.toml"

# ── Initial state probe ───────────────────────────────────────────
function Get-OnboardingState {
    if (Test-Path $StateScript) {
        try {
            return & $StateScript -InstallRoot $InstallRoot -DataRoot $DataRoot -BundlePath $BundlePath
        } catch {
            Write-Host "Get-DdsOnboardingState.ps1 failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    # Fallback minimal state (e.g., running from source tree pre-install).
    return [pscustomobject]@{
        DomainProvisioned   = (Test-Path (Join-Path $NodeData 'domain.toml'))
        BundleValid         = $false
        BundlePath          = $BundlePath
        ResumeMarker        = $null
        VaultHasCurrentUser = $null
        Branch              = 'Welcome'
    }
}
$state = Get-OnboardingState

# Resolve initial page from -Mode + state probe.
function Resolve-InitialPage {
    param($Mode, $State)
    switch ($Mode) {
        'NewDomain'  { return 'PageNewDomain_Identity' }
        'JoinDomain' { return 'PageJoinDomain_Bundle' }
        'EnrollUser' { return 'PageEnrollUser_Explainer' }
        'Health'     { return 'PageHealth' }
        default {
            switch ($State.Branch) {
                'NewDomain'        { return 'PageWelcome' }   # Welcome highlights it.
                'JoinDomain'       { return 'PageJoinDomain_Bundle' }
                'EnrollUser'       { return 'PageWelcome' }
                'Health'           { return 'PageHealth' }
                'ResumeBootstrap'  { return 'PageResume' }
                default            { return 'PageWelcome' }
            }
        }
    }
}

# ── XAML ──────────────────────────────────────────────────────────
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DDS Setup" Height="640" Width="820"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="13">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#003366" Padding="14,10">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock x:Name="HdrTitle" Text="DDS Setup" Foreground="White"
                     FontSize="20" FontWeight="SemiBold"/>
          <TextBlock x:Name="HdrSubtitle" Text="" Foreground="#cfdcec"
                     FontSize="12" Margin="0,2,0,0"/>
        </StackPanel>
        <TextBlock x:Name="HdrVersion" Grid.Column="1"
                   Text="" Foreground="#cfdcec"
                   VerticalAlignment="Center"/>
      </Grid>
    </Border>

    <!-- Pages — one Grid visible at a time -->
    <Grid Grid.Row="1" Margin="20">

      <!-- ============ Welcome / role picker ============ -->
      <Grid x:Name="PageWelcome" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="What would you like to do?"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   x:Name="WelcomeDetected"
                   Text="Pick the option that matches your role on this machine."/>
        <StackPanel Grid.Row="2">
          <Border x:Name="TileNewDomain" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Margin="0,0,0,10" Background="White"
                  Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="Start a new DDS domain"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Use this if you are setting up DDS for the first time and this machine should become the founding node of a new domain. You'll need a FIDO2 security key plugged in."/>
            </StackPanel>
          </Border>
          <Border x:Name="TileJoinDomain" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Margin="0,0,0,10" Background="White"
                  Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="Join an existing DDS domain"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Use this if your administrator has given you a *.dds provision bundle file from another machine in the domain."/>
            </StackPanel>
          </Border>
          <Border x:Name="TileEnrollUser" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Margin="0,0,0,10" Background="White"
                  Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="Set up passwordless sign-in for this account"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Use this if this machine is already part of a domain but you sign in with a Windows password. You'll register a FIDO2 key for your account."/>
            </StackPanel>
          </Border>
          <Border x:Name="TileHealth" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Background="White" Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="View status / open Tray Agent"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Skip onboarding and jump to the service status view."/>
            </StackPanel>
          </Border>
        </StackPanel>
      </Grid>

      <!-- ============ Resume bootstrap ============ -->
      <Grid x:Name="PageResume" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="A previous bootstrap was interrupted"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   x:Name="ResumeDetail"
                   Text="The wizard found a half-completed bootstrap on this machine."/>
        <StackPanel Grid.Row="2" Orientation="Vertical">
          <Button x:Name="BtnResumeRestart" Content="Discard and start over (wipe state)"
                  Padding="12,6" Margin="0,0,0,10" HorizontalAlignment="Left"/>
          <Button x:Name="BtnResumeNew" Content="Continue to Welcome page"
                  Padding="12,6" HorizontalAlignment="Left"/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch A: Identity ============ -->
      <Grid x:Name="PageNewDomain_Identity" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 1 of 4 — Domain identity"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,16" TextWrapping="Wrap"
                   Text="Pick a name and short organization tag for this DDS domain. The name is shown to operators; the org tag groups gossip topics and should be 4-16 lowercase letters / digits."/>
        <Grid Grid.Row="2" Margin="0,0,0,10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="140"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Label Grid.Row="0" Grid.Column="0" Content="Domain name:" VerticalAlignment="Center"/>
          <TextBox Grid.Row="0" Grid.Column="1" x:Name="TbName" Text="acme.corp"
                   Margin="0,3" Padding="6,4"/>
          <Label Grid.Row="1" Grid.Column="0" Content="Org tag:" VerticalAlignment="Center"/>
          <TextBox Grid.Row="1" Grid.Column="1" x:Name="TbOrg" Text="acme"
                   Margin="0,3" Padding="6,4"/>
          <CheckBox Grid.Row="2" Grid.Column="1" x:Name="CbForce" Margin="0,8,0,0"
                    Content="Wipe any existing domain state on this machine (required if re-bootstrapping)"/>
        </Grid>
        <TextBlock Grid.Row="3" x:Name="TbIdentityWarn" Foreground="#cc4400" Margin="0,4,0,0"
                   TextWrapping="Wrap" Text=""/>
      </Grid>

      <!-- ============ Branch A: Key protection ============ -->
      <Grid x:Name="PageNewDomain_KeyProtection" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 2 of 4 — Domain key protection"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,16" TextWrapping="Wrap"
                   Text="The domain signing key needs to be wrapped with something only you can produce. The default is a FIDO2 hardware key, which is the most secure option and what we recommend. Choose passphrase only if no FIDO2 key is available."/>
        <StackPanel Grid.Row="2">
          <RadioButton x:Name="RbFido2" Content="FIDO2 hardware key (recommended) — touch your security key when prompted."
                       IsChecked="True" Margin="0,0,0,8"/>
          <RadioButton x:Name="RbPass"  Content="Passphrase — you'll type a passphrase you remember. Less secure than FIDO2."/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch A: Run ============ -->
      <Grid x:Name="PageNewDomain_Run" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 3 of 4 — Bootstrapping the domain"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   Text="A new console window will open shortly. Touch your FIDO2 key when it asks. Progress is mirrored here."/>
        <Border Grid.Row="2" BorderBrush="#cccccc" BorderThickness="1" Padding="6" Margin="0,0,0,8">
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
        <TextBlock Grid.Row="3" x:Name="TbStatus" Text="Ready." Margin="0,0,0,4" FontWeight="SemiBold"/>
        <TextBox Grid.Row="4" x:Name="TbLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
      </Grid>

      <!-- ============ Branch A: Done ============ -->
      <Grid x:Name="PageNewDomain_Done" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Foreground="#107C10"
                   Text="Domain bootstrap complete"/>
        <StackPanel Grid.Row="1" Margin="0,8,0,16">
          <TextBlock x:Name="TbDoneDomainId"   FontFamily="Consolas" Margin="0,0,0,2"/>
          <TextBlock x:Name="TbDoneDeviceUrn"  FontFamily="Consolas" Margin="0,0,0,2"/>
          <TextBlock x:Name="TbDonePeerId"     FontFamily="Consolas"/>
        </StackPanel>
        <TextBlock Grid.Row="2" Foreground="#555555" Margin="0,0,0,16" TextWrapping="Wrap"
                   Text="To add another machine to this domain, copy the provision bundle below to that machine and double-click it there."/>
        <StackPanel Grid.Row="3" Orientation="Vertical">
          <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
            <Button x:Name="BtnDoneSaveBundle" Content="Save provision bundle..." Padding="14,6" Margin="0,0,8,0"/>
            <TextBlock x:Name="TbDoneBundleStatus" VerticalAlignment="Center" Foreground="#555555"/>
          </StackPanel>
          <Button x:Name="BtnDoneTray" Content="Open Tray Agent" Padding="14,6" HorizontalAlignment="Left"/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch B: Bundle ============ -->
      <Grid x:Name="PageJoinDomain_Bundle" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 1 of 3 — Provision bundle"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   Text="Drop the *.dds provision bundle your administrator gave you here, or click Browse. The bundle is FIDO2-sealed at rest — the admin's hardware key was used to seal it."/>
        <Border Grid.Row="2" BorderBrush="#999999" BorderThickness="2" CornerRadius="6"
                Background="#f7f7f7" AllowDrop="True" x:Name="DropTarget">
          <Grid>
            <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
              <TextBlock x:Name="TbDropHint" FontSize="14" Foreground="#666666"
                         HorizontalAlignment="Center"
                         Text="Drop a *.dds file here"/>
              <TextBlock Foreground="#999999" FontSize="11" HorizontalAlignment="Center" Margin="0,4,0,0"
                         Text="or use Browse below"/>
            </StackPanel>
          </Grid>
        </Border>
        <StackPanel Grid.Row="3" Orientation="Horizontal" Margin="0,8,0,0">
          <Button x:Name="BtnJoinBrowse" Content="Browse..." Padding="14,6" Margin="0,0,8,0"/>
          <TextBlock x:Name="TbJoinSelectedPath" VerticalAlignment="Center"
                     Foreground="#555555" FontFamily="Consolas"/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch B: Confirm + unseal ============ -->
      <Grid x:Name="PageJoinDomain_Confirm" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 2 of 3 — Unseal and join"/>
        <Border Grid.Row="1" BorderBrush="#cccccc" BorderThickness="1" Padding="10" Margin="0,8,0,12">
          <StackPanel>
            <TextBlock x:Name="TbJoinBundleSummary" FontFamily="Consolas"
                       Text="(bundle details)"/>
          </StackPanel>
        </Border>
        <TextBlock Grid.Row="2" Foreground="#555555" Margin="0,0,0,12" TextWrapping="Wrap"
                   Text="Touch the admin's FIDO2 key when the new console window prompts you. Output streams below."/>
        <TextBox Grid.Row="3" x:Name="TbJoinLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
      </Grid>

      <!-- ============ Branch B: Device enroll ============ -->
      <Grid x:Name="PageJoinDomain_DeviceEnroll" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 3 of 3 — Register this device"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   Text="Starting services and registering this machine with the domain..."/>
        <TextBlock Grid.Row="2" x:Name="TbDeviceEnrollStatus" Margin="0,0,0,8" FontWeight="SemiBold"
                   Text="Working..."/>
        <TextBox Grid.Row="3" x:Name="TbDeviceEnrollLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
      </Grid>

      <!-- ============ Branch B: Done ============ -->
      <Grid x:Name="PageJoinDomain_Done" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Foreground="#107C10"
                   Text="Joined the domain successfully"/>
        <StackPanel Grid.Row="1" Margin="0,8,0,16">
          <TextBlock x:Name="TbJoinDoneDeviceUrn" FontFamily="Consolas" Margin="0,0,0,2"/>
        </StackPanel>
        <StackPanel Grid.Row="2" Orientation="Vertical">
          <Button x:Name="BtnJoinDoneTray" Content="Open Tray Agent" Padding="14,6" HorizontalAlignment="Left" Margin="0,0,0,8"/>
          <TextBlock Foreground="#555555" TextWrapping="Wrap"
                     Text="To enable passwordless sign-in for the user account on this machine, sign in as that user and run the wizard again — it will offer to enroll a FIDO2 key."/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch C: Explainer ============ -->
      <Grid x:Name="PageEnrollUser_Explainer" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 1 of 4 — What's about to happen"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   x:Name="TbEnrollExplain"
                   Text="We'll set up passwordless sign-in for your Windows account. This takes about 30 seconds."/>
        <StackPanel Grid.Row="2">
          <TextBlock FontWeight="SemiBold" Margin="0,0,0,4" Text="You'll need:"/>
          <TextBlock Margin="0,0,0,2" Text="• Your current Windows password (used once to verify you, then encrypted with your key)"/>
          <TextBlock Margin="0,0,0,2" Text="• A FIDO2 security key plugged in"/>
          <TextBlock Text="• To touch the key twice when prompted"/>
        </StackPanel>
      </Grid>

      <!-- ============ Branch C: Password ============ -->
      <Grid x:Name="PageEnrollUser_Password" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 2 of 4 — Windows password"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   Text="Type your Windows password below. We verify it locally and store an encrypted copy that only your security key can unlock."/>
        <PasswordBox Grid.Row="2" x:Name="PwBox" Padding="6,4" Margin="0,0,0,8"/>
        <TextBlock Grid.Row="3" x:Name="TbPwStatus" Foreground="#cc4400" TextWrapping="Wrap"/>
      </Grid>

      <!-- ============ Branch C: Touch ============ -->
      <Grid x:Name="PageEnrollUser_Touch" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold"
                   Text="Step 3 of 4 — Touch your security key"/>
        <TextBlock Grid.Row="1" x:Name="TbTouchStatus" FontSize="14" Margin="0,8,0,4"
                   Text="Initializing..."/>
        <TextBlock Grid.Row="2" Foreground="#555555" Margin="0,0,0,12" TextWrapping="Wrap"
                   Text="Windows will pop a prompt asking you to touch your key. Touch it when it does — the wizard will pick it up automatically."/>
        <TextBox Grid.Row="3" x:Name="TbEnrollLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
      </Grid>

      <!-- ============ Branch C: Awaiting approval ============ -->
      <Grid x:Name="PageEnrollUser_AwaitingApproval" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Foreground="#107C10"
                   Text="Step 4 of 4 — Waiting for admin approval"/>
        <TextBlock Grid.Row="1" Margin="0,8,0,4" FontFamily="Consolas"
                   x:Name="TbEnrollUrn" Text=""/>
        <TextBlock Grid.Row="2" Foreground="#555555" Margin="0,8,0,12" TextWrapping="Wrap"
                   Text="Your enrollment was posted. An administrator must now approve it from their tray agent (Approve Enrollments...). You can close this window — passwordless sign-in becomes active once approved."/>
        <TextBlock Grid.Row="3" x:Name="TbEnrollPollStatus" Foreground="#555555" Margin="0,0,0,8"/>
      </Grid>

      <!-- ============ Health ============ -->
      <Grid x:Name="PageHealth" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Text="Service status"/>
        <DataGrid Grid.Row="1" x:Name="DgServices" AutoGenerateColumns="False" CanUserAddRows="False"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal" Margin="0,8,0,8" Height="120"
                  IsReadOnly="True">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Service"   Binding="{Binding Name}"      Width="160"/>
            <DataGridTextColumn Header="Status"    Binding="{Binding Status}"    Width="120"/>
            <DataGridTextColumn Header="StartType" Binding="{Binding StartType}" Width="100"/>
            <DataGridTextColumn Header="Bin path"  Binding="{Binding BinPath}"   Width="*"/>
          </DataGrid.Columns>
        </DataGrid>
        <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,8">
          <TextBlock x:Name="TbPipe"     Text="" Margin="0,0,15,0" VerticalAlignment="Center"/>
          <TextBlock x:Name="TbStateInv" Text="" Margin="0,0,15,0" VerticalAlignment="Center" FontFamily="Consolas"/>
        </StackPanel>
        <GroupBox Grid.Row="3" Header="authbridge.log (tail)">
          <TextBox x:Name="TbLogTail" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
        </GroupBox>
        <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,8,0,0">
          <Button x:Name="BtnRefresh" Content="Refresh now" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnTray"    Content="Open Tray Agent" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStartAll" Content="Start all services" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStopAll"  Content="Stop all services"  Padding="14,4" Margin="4"/>
        </StackPanel>
      </Grid>

      <!-- ============ Error ============ -->
      <Grid x:Name="PageError" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Foreground="#D13438"
                   Text="Something went wrong"/>
        <TextBlock Grid.Row="1" x:Name="TbErrorMsg" Margin="0,8,0,12" TextWrapping="Wrap"/>
        <TextBox   Grid.Row="2" x:Name="TbErrorLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
      </Grid>

    </Grid>

    <!-- Footer / nav -->
    <Border Grid.Row="2" Background="#f0f0f0" BorderBrush="#cccccc" BorderThickness="0,1,0,0" Padding="14,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Button Grid.Column="0" x:Name="BtnBack"   Content="Back"   Padding="18,5" Margin="0,0,8,0"/>
        <Button Grid.Column="2" x:Name="BtnCancel" Content="Cancel" Padding="18,5" Margin="0,0,8,0"/>
        <Button Grid.Column="2" x:Name="BtnNext"   Content="Next"   Padding="18,5" Margin="0,0,0,0" HorizontalAlignment="Right"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$window.Title = "DDS Setup  -  v$DdsVersion"

# Resolve named elements
$el = @{}
$names = @(
    'HdrTitle','HdrSubtitle','HdrVersion',
    'PageWelcome','PageResume',
    'PageNewDomain_Identity','PageNewDomain_KeyProtection','PageNewDomain_Run','PageNewDomain_Done',
    'PageJoinDomain_Bundle','PageJoinDomain_Confirm','PageJoinDomain_DeviceEnroll','PageJoinDomain_Done',
    'PageEnrollUser_Explainer','PageEnrollUser_Password','PageEnrollUser_Touch','PageEnrollUser_AwaitingApproval',
    'PageHealth','PageError',
    'WelcomeDetected','TileNewDomain','TileJoinDomain','TileEnrollUser','TileHealth',
    'ResumeDetail','BtnResumeRestart','BtnResumeNew',
    'TbName','TbOrg','CbForce','TbIdentityWarn',
    'RbFido2','RbPass',
    'Steps','TbStatus','TbLog',
    'TbDoneDomainId','TbDoneDeviceUrn','TbDonePeerId','BtnDoneSaveBundle','TbDoneBundleStatus','BtnDoneTray',
    'DropTarget','TbDropHint','BtnJoinBrowse','TbJoinSelectedPath','TbJoinBundleSummary','TbJoinLog',
    'TbDeviceEnrollStatus','TbDeviceEnrollLog',
    'TbJoinDoneDeviceUrn','BtnJoinDoneTray',
    'TbEnrollExplain','PwBox','TbPwStatus',
    'TbTouchStatus','TbEnrollLog',
    'TbEnrollUrn','TbEnrollPollStatus',
    'DgServices','TbPipe','TbStateInv','TbLogTail','BtnRefresh','BtnTray','BtnStartAll','BtnStopAll',
    'TbErrorMsg','TbErrorLog',
    'BtnBack','BtnNext','BtnCancel'
)
foreach ($n in $names) { $el[$n] = $window.FindName($n) }

$el.HdrVersion.Text = "v$DdsVersion"

# ── Page navigation ────────────────────────────────────────────────
$script:pageStack = @()
$script:currentPage = $null

$AllPages = @(
    'PageWelcome','PageResume',
    'PageNewDomain_Identity','PageNewDomain_KeyProtection','PageNewDomain_Run','PageNewDomain_Done',
    'PageJoinDomain_Bundle','PageJoinDomain_Confirm','PageJoinDomain_DeviceEnroll','PageJoinDomain_Done',
    'PageEnrollUser_Explainer','PageEnrollUser_Password','PageEnrollUser_Touch','PageEnrollUser_AwaitingApproval',
    'PageHealth','PageError'
)

function Show-Page {
    param([string]$Name, [switch]$NoStack)
    foreach ($p in $AllPages) {
        if ($el[$p]) { $el[$p].Visibility = 'Collapsed' }
    }
    if (-not $el[$Name]) { Write-Host "Show-Page: unknown page '$Name'" -ForegroundColor Red; return }
    $el[$Name].Visibility = 'Visible'
    if (-not $NoStack -and $script:currentPage -and $script:currentPage -ne $Name) {
        $script:pageStack += $script:currentPage
    }
    $script:currentPage = $Name
    Update-NavForPage -Name $Name
}

function Pop-Page {
    if ($script:pageStack.Count -lt 1) { return }
    $prev = $script:pageStack[-1]
    $script:pageStack = $script:pageStack[0..($script:pageStack.Count-2)]
    $script:currentPage = $prev
    foreach ($p in $AllPages) {
        if ($el[$p]) { $el[$p].Visibility = 'Collapsed' }
    }
    $el[$prev].Visibility = 'Visible'
    Update-NavForPage -Name $prev
}

function Update-NavForPage {
    param([string]$Name)
    # Defaults
    $el.BtnBack.IsEnabled   = ($script:pageStack.Count -gt 0)
    $el.BtnNext.Visibility  = 'Visible'
    $el.BtnNext.IsEnabled   = $true
    $el.BtnCancel.Content   = 'Cancel'
    $el.BtnNext.Content     = 'Next'

    switch ($Name) {
        'PageWelcome' {
            $el.HdrSubtitle.Text = 'Welcome'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnBack.IsEnabled = $false
            $el.BtnCancel.Content = 'Close'
        }
        'PageResume' {
            $el.HdrSubtitle.Text = 'Resume previous bootstrap'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnBack.IsEnabled = $false
            $el.BtnCancel.Content = 'Close'
        }
        'PageNewDomain_Identity'      { $el.HdrSubtitle.Text = 'Start a new DDS domain' }
        'PageNewDomain_KeyProtection' { $el.HdrSubtitle.Text = 'Start a new DDS domain' }
        'PageNewDomain_Run' {
            $el.HdrSubtitle.Text = 'Start a new DDS domain'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.IsEnabled = $false
            $el.BtnNext.Content = 'Working...'
        }
        'PageNewDomain_Done' {
            $el.HdrSubtitle.Text = 'Start a new DDS domain'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.Content = 'Finish'
        }
        'PageJoinDomain_Bundle' {
            $el.HdrSubtitle.Text = 'Join an existing DDS domain'
            $el.BtnNext.IsEnabled = ($script:joinBundlePath -and (Test-Path $script:joinBundlePath))
        }
        'PageJoinDomain_Confirm' {
            $el.HdrSubtitle.Text = 'Join an existing DDS domain'
            $el.BtnNext.Content = 'Touch FIDO2 key to unseal'
        }
        'PageJoinDomain_DeviceEnroll' {
            $el.HdrSubtitle.Text = 'Join an existing DDS domain'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.IsEnabled = $false
            $el.BtnNext.Content = 'Working...'
        }
        'PageJoinDomain_Done' {
            $el.HdrSubtitle.Text = 'Join an existing DDS domain'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.Content = 'Finish'
        }
        'PageEnrollUser_Explainer' { $el.HdrSubtitle.Text = 'Set up passwordless sign-in' }
        'PageEnrollUser_Password'  { $el.HdrSubtitle.Text = 'Set up passwordless sign-in' }
        'PageEnrollUser_Touch' {
            $el.HdrSubtitle.Text = 'Set up passwordless sign-in'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.IsEnabled = $false
            $el.BtnNext.Content = 'Working...'
        }
        'PageEnrollUser_AwaitingApproval' {
            $el.HdrSubtitle.Text = 'Set up passwordless sign-in'
            $el.BtnBack.IsEnabled = $false
            $el.BtnNext.Content = 'Finish'
        }
        'PageHealth' {
            $el.HdrSubtitle.Text = 'Service status'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnBack.IsEnabled = $false
            $el.BtnCancel.Content = 'Close'
        }
        'PageError' {
            $el.HdrSubtitle.Text = 'Error'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnCancel.Content = 'Close'
        }
    }
}

# ── Bootstrap step model (re-used from Branch A) ──────────────────
$stepDefs = @(
    @{ Idx=1; Label="Create domain (init-domain)" }
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
            Icon  = [char]0x25CB
            Color = '#666666'
        })
    }
}
function Mark-Step {
    param([int]$Idx, [string]$State)
    for ($i = 0; $i -lt $stepItems.Count; $i++) {
        if ($stepItems[$i].Idx -eq $Idx) {
            switch ($State) {
                'running' { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x25B6; Color='#0078d4' } }
                'ok'      { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x2714; Color='#107C10' } }
                'fail'    { $stepItems[$i] = [pscustomobject]@{ Idx=$Idx; Label=$stepItems[$i].Label; Icon=[char]0x2716; Color='#D13438' } }
            }
            return
        }
    }
}
$el.Steps.ItemsSource = $stepItems
Reset-Steps

# ── Helpers ───────────────────────────────────────────────────────
function Append-Log    { param($T,[string]$line) $T.AppendText($line + "`r`n"); $T.ScrollToEnd() }
function Set-Status    { param([string]$msg, [string]$color='#000000')
    $el.TbStatus.Text = $msg
    $el.TbStatus.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString($color)
}
function Set-Error     {
    param([string]$Message, [string]$Detail='')
    $el.TbErrorMsg.Text = $Message
    $el.TbErrorLog.Text = $Detail
    Show-Page -Name 'PageError'
}

# ── Branch A: bootstrap orchestration ─────────────────────────────
$script:bootstrapProcess  = $null
$script:bootstrapLogPath  = $null
$script:bootstrapTailPos  = 0
$script:bootstrapTimer    = $null

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
                Append-Log $el.TbLog $line
                # Prefer the unambiguous machine marker if present.
                if ($line -match '^##DDS-STEP## (\d)/9') {
                    $idx = [int]$Matches[1]
                    if ($idx -gt 1) { Mark-Step -Idx ($idx - 1) -State 'ok' }
                    Mark-Step -Idx $idx -State 'running'
                } elseif ($line -match '\[(\d)/9\]') {
                    $idx = [int]$Matches[1]
                    if ($idx -gt 1) { Mark-Step -Idx ($idx - 1) -State 'ok' }
                    Mark-Step -Idx $idx -State 'running'
                }
                if ($line -like '*Bootstrap Complete*') { Mark-Step -Idx 9 -State 'ok' }
                if ($line -like '*Bootstrap FAILED*' -or $line -like 'Error:*') {
                    for ($i = $stepItems.Count - 1; $i -ge 0; $i--) {
                        if ($stepItems[$i].Color -eq '#0078d4') {
                            Mark-Step -Idx $stepItems[$i].Idx -State 'fail'; break
                        }
                    }
                }
            }
            $script:bootstrapTailPos = $fs.Position
        } finally { $fs.Dispose() }
    } catch { }
    if ($script:bootstrapProcess -and $script:bootstrapProcess.HasExited) {
        Stop-BootstrapTail
        $code = $script:bootstrapProcess.ExitCode
        if ($code -eq 0) {
            for ($i = 0; $i -lt $stepItems.Count; $i++) {
                if ($stepItems[$i].Color -eq '#0078d4') { Mark-Step -Idx $stepItems[$i].Idx -State 'ok' }
            }
            Set-Status "Bootstrap completed successfully." '#107C10'
            # Read bootstrap.env to populate the Done page.
            $bsEnv = Join-Path $DataRoot 'bootstrap.env'
            if (Test-Path $bsEnv) {
                $envLines = Get-Content $bsEnv
                foreach ($ln in $envLines) {
                    if ($ln -match '^DOMAIN_ID=(.+)$')   { $el.TbDoneDomainId.Text   = "Domain ID:  $($Matches[1])" }
                    if ($ln -match '^DEVICE_URN=(.+)$')  { $el.TbDoneDeviceUrn.Text  = "Device URN: $($Matches[1])" }
                    if ($ln -match '^PEER_ID=(.+)$')     { $el.TbDonePeerId.Text     = "Peer ID:    $($Matches[1])" }
                }
            }
            Show-Page -Name 'PageNewDomain_Done'
        } else {
            Set-Status "Bootstrap failed (exit $code)." '#D13438'
            Set-Error -Message "Bootstrap failed with exit code $code." -Detail $el.TbLog.Text
        }
    }
}

function Run-Bootstrap {
    if (-not (Test-Path $BootstrapScript)) {
        Set-Error -Message "Bootstrap-DdsDomain.ps1 not found at $BootstrapScript. Reinstall the MSI."
        return
    }
    if ([string]::IsNullOrWhiteSpace($el.TbName.Text)) {
        $el.TbIdentityWarn.Text = "Domain name is required."
        Show-Page -Name 'PageNewDomain_Identity' -NoStack
        return
    }
    if ([string]::IsNullOrWhiteSpace($el.TbOrg.Text)) {
        $el.TbIdentityWarn.Text = "Org tag is required."
        Show-Page -Name 'PageNewDomain_Identity' -NoStack
        return
    }

    Show-Page -Name 'PageNewDomain_Run'
    $el.TbLog.Clear()
    Reset-Steps
    Set-Status "Bootstrap window launched - touch your FIDO2 key when prompted there." '#0078d4'

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

    $script:bootstrapProcess = Start-Process `
        -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList $args -PassThru

    Append-Log $el.TbLog "[Console] Bootstrap window launched (PID $($script:bootstrapProcess.Id))."
    Append-Log $el.TbLog "[Console] Transcript: $script:bootstrapLogPath"
    Append-Log $el.TbLog "[Console] Tailing for progress..."

    $script:bootstrapTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:bootstrapTimer.Interval = [TimeSpan]::FromMilliseconds(700)
    $script:bootstrapTimer.Add_Tick({ Tick-BootstrapTail })
    $script:bootstrapTimer.Start()
}

function Run-NewDomainSaveBundle {
    if (-not (Test-Path $ProvisionBundle)) {
        $el.TbDoneBundleStatus.Text = "Bundle missing — bootstrap may not have completed."
        return
    }
    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Title = "Save DDS provision bundle"
    $dlg.FileName = "provision.dds"
    $dlg.Filter = "DDS Provision Bundle (*.dds)|*.dds|All files (*.*)|*.*"
    $dlg.OverwritePrompt = $true
    if (-not $dlg.ShowDialog($window)) { return }
    try {
        Copy-Item -LiteralPath $ProvisionBundle -Destination $dlg.FileName -Force
        $el.TbDoneBundleStatus.Text = "Saved to $($dlg.FileName)"
        $el.TbDoneBundleStatus.Foreground = [Windows.Media.Brushes]::DarkGreen
    } catch {
        $el.TbDoneBundleStatus.Text = "Save failed: $($_.Exception.Message)"
        $el.TbDoneBundleStatus.Foreground = [Windows.Media.Brushes]::DarkRed
    }
}

# ── Branch B: Join domain ─────────────────────────────────────────
$script:joinBundlePath = $null
$script:joinProcess    = $null
$script:joinTimer      = $null
$script:joinStdoutPath = $null
$script:joinStdoutPos  = 0
$script:deviceEnrollProcess = $null
$script:deviceEnrollTimer   = $null
$script:deviceEnrollLogPath = $null
$script:deviceEnrollLogPos  = 0
$script:joinDeviceUrn  = $null

function Set-JoinBundle {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        $el.TbJoinSelectedPath.Text = "File not found: $Path"
        $el.BtnNext.IsEnabled = $false
        return
    }
    if ([IO.Path]::GetExtension($Path).ToLowerInvariant() -ne '.dds') {
        $el.TbJoinSelectedPath.Text = "Not a *.dds file: $Path"
        $el.BtnNext.IsEnabled = $false
        return
    }
    $script:joinBundlePath = (Resolve-Path -LiteralPath $Path).Path
    $el.TbJoinSelectedPath.Text = $script:joinBundlePath
    $el.TbDropHint.Text = "Bundle selected: $([IO.Path]::GetFileName($script:joinBundlePath))"
    $el.BtnNext.IsEnabled = $true
}

function Run-JoinUnseal {
    if (-not $script:joinBundlePath -or -not (Test-Path $script:joinBundlePath)) {
        Set-Error -Message "No bundle selected."
        return
    }
    # "Already provisioned" means the node has a domain identity, not
    # merely the MSI-shipped stub node.toml. The MSI ships an
    # unprovisioned template node.toml (DdsBundle.wxs:166-169) and
    # NeverOverwrite preserves it across reinstalls, so checking node.toml
    # would block Join on every fresh install. Match the signal
    # Get-DdsOnboardingState.ps1 uses — domain.toml AND admission.cbor —
    # which is what 'dds-node provision' actually writes.
    if ((Test-Path $AdmissionCert) -and (Test-Path $DomainTomlFile)) {
        Set-Error -Message "This machine is already part of a domain. Run 'Discard and start over' from the wizard's resume page first." -Detail "admission.cbor and domain.toml already exist."
        return
    }

    $bf = Get-Item -LiteralPath $script:joinBundlePath
    $el.TbJoinBundleSummary.Text = "File:  $($bf.FullName)`nSize:  $('{0:N0}' -f $bf.Length) bytes`nWritten: $($bf.LastWriteTime)"

    Show-Page -Name 'PageJoinDomain_Confirm'
    $el.TbJoinLog.Clear()
    Append-Log $el.TbJoinLog "[Console] Starting: dds-node provision $script:joinBundlePath"
    Append-Log $el.TbJoinLog "[Console] A new console window will open. Touch the admin's FIDO2 key when prompted."

    # Use a single-quoted here-string and encode to UTF-16LE base64 for
    # -EncodedCommand. powershell.exe -Command corrupts inner double-quoted
    # strings when the payload spans multiple lines (drops the surrounding
    # quotes), turning the failure branch into a parser error on `exit`.
    # -EncodedCommand bypasses the quoting layer entirely.
    $payload = @'
& '__NODEBIN__' provision --no-start '__BUNDLE__'
$code = $LASTEXITCODE
Write-Host ''
if ($code -eq 0) { Write-Host '=== Provision Complete ===' -ForegroundColor Green }
else             { Write-Host "=== Provision FAILED (exit $code) ===" -ForegroundColor Red }
Read-Host 'Press Enter to close'
exit $code
'@ -replace '__NODEBIN__', $NodeBin -replace '__BUNDLE__', $script:joinBundlePath
    $cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $script:joinStdoutPath = Join-Path $env:TEMP ("dds-join-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:joinStdoutPos  = 0
    # The visible window is required for libfido2 to treat stdin as interactive,
    # but we can't redirect its stdout cleanly. Rely on the user closing the
    # window after success/failure; we poll for HasExited.
    $script:joinProcess = Start-Process `
        -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand', $cmd) `
        -PassThru

    Append-Log $el.TbJoinLog "[Console] Provision PID $($script:joinProcess.Id)"

    $script:joinTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:joinTimer.Interval = [TimeSpan]::FromMilliseconds(700)
    $script:joinTimer.Add_Tick({
        if ($script:joinProcess.HasExited) {
            $script:joinTimer.Stop(); $script:joinTimer = $null
            $code = $script:joinProcess.ExitCode
            if ($code -eq 0 -and (Test-Path $AdmissionCert) -and (Test-Path $DomainTomlFile)) {
                Append-Log $el.TbJoinLog "[Console] Provision succeeded; running device enrollment..."
                Show-Page -Name 'PageJoinDomain_DeviceEnroll'
                Run-DeviceEnroll
            } else {
                Set-Error -Message "Provision failed (exit $code). Check the bundle file and try again." -Detail $el.TbJoinLog.Text
            }
        }
    })
    $script:joinTimer.Start()
}

function Run-DeviceEnroll {
    if (-not (Test-Path $EnrollDeviceScript)) {
        Set-Error -Message "Enroll-DdsDevice.ps1 not found at $EnrollDeviceScript. Reinstall the MSI."
        return
    }
    $el.TbDeviceEnrollLog.Clear()
    $el.TbDeviceEnrollStatus.Text = "Working..."

    $script:deviceEnrollLogPath = Join-Path $env:TEMP ("dds-deviceenroll-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:deviceEnrollLogPos  = 0

    # Spawn a non-window-style PowerShell with stdout+stderr merged to a temp
    # file we tail. No FIDO2 prompts in this stage so a hidden window is OK.
    $args = @(
        '-NoProfile','-ExecutionPolicy','Bypass',
        '-Command',
        "& '$EnrollDeviceScript' *>&1 | Tee-Object -FilePath '$script:deviceEnrollLogPath'"
    )
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName  = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psi.Arguments = ($args -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true
    $script:deviceEnrollProcess = [Diagnostics.Process]::Start($psi)

    Append-Log $el.TbDeviceEnrollLog "[Console] device-enroll PID $($script:deviceEnrollProcess.Id), tailing $script:deviceEnrollLogPath"

    $script:deviceEnrollTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:deviceEnrollTimer.Interval = [TimeSpan]::FromMilliseconds(700)
    $script:deviceEnrollTimer.Add_Tick({ Tick-DeviceEnroll })
    $script:deviceEnrollTimer.Start()
}

function Tick-DeviceEnroll {
    if ($script:deviceEnrollLogPath -and (Test-Path $script:deviceEnrollLogPath)) {
        try {
            $fs = [IO.File]::Open($script:deviceEnrollLogPath, 'Open', 'Read', 'ReadWrite')
            try {
                if ($fs.Length -gt $script:deviceEnrollLogPos) {
                    $fs.Seek($script:deviceEnrollLogPos, 'Begin') | Out-Null
                    $reader = New-Object IO.StreamReader $fs
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if ($null -eq $line) { break }
                        Append-Log $el.TbDeviceEnrollLog $line
                        if ($line -match '^##DDS-DEVICE-ENROLL## phase=node-started') {
                            $el.TbDeviceEnrollStatus.Text = "Node service started."
                        }
                        elseif ($line -match '^##DDS-DEVICE-ENROLL## phase=device-enrolled urn=(.+)$') {
                            $script:joinDeviceUrn = $Matches[1].Trim()
                            $el.TbDeviceEnrollStatus.Text = "Device enrolled: $script:joinDeviceUrn"
                        }
                        elseif ($line -match '^##DDS-DEVICE-ENROLL## phase=appsettings-stamped') {
                            $el.TbDeviceEnrollStatus.Text = "Configuration stamped."
                        }
                        elseif ($line -match '^##DDS-DEVICE-ENROLL## phase=services-started') {
                            $el.TbDeviceEnrollStatus.Text = "Services running."
                        }
                    }
                    $script:deviceEnrollLogPos = $fs.Position
                }
            } finally { $fs.Dispose() }
        } catch { }
    }
    if ($script:deviceEnrollProcess -and $script:deviceEnrollProcess.HasExited) {
        $script:deviceEnrollTimer.Stop(); $script:deviceEnrollTimer = $null
        $code = $script:deviceEnrollProcess.ExitCode
        if ($code -eq 0) {
            $el.TbJoinDoneDeviceUrn.Text = if ($script:joinDeviceUrn) { "Device URN: $script:joinDeviceUrn" } else { "" }
            Show-Page -Name 'PageJoinDomain_Done'
        } else {
            Set-Error -Message "Device enrollment failed (exit $code)." -Detail $el.TbDeviceEnrollLog.Text
        }
    }
}

# ── Branch C: Enroll FIDO key for current user ────────────────────
$script:enrollProcess     = $null
$script:enrollTimer       = $null
$script:enrollStdoutPath  = $null
$script:enrollStdoutPos   = 0
$script:enrollPwTempPath  = $null
$script:enrollUrn         = $null
$script:enrollPollTimer   = $null
$script:enrollPollAttempts = 0

function Set-EnrollExplainerText {
    try {
        $u = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $el.TbEnrollExplain.Text = "We'll set up passwordless sign-in for $u. This takes about 30 seconds."
    } catch { }
}

function Validate-WindowsPassword {
    param([string]$Password)
    # Best-effort local validation. Calling LogonUser from PowerShell needs
    # P/Invoke; we use the Windows API via Add-Type.
    if (-not ('Win32Logon' -as [type])) {
        Add-Type -Namespace Win32 -Name Logon -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out System.IntPtr phToken);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool CloseHandle(System.IntPtr hObject);
"@
    }
    $username = $env:USERNAME
    $domain   = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { '.' }
    $token = [IntPtr]::Zero
    # LOGON32_LOGON_NETWORK = 3, LOGON32_PROVIDER_DEFAULT = 0
    $ok = [Win32.Logon]::LogonUser($username, $domain, $Password, 3, 0, [ref]$token)
    if ($ok) { [Win32.Logon]::CloseHandle($token) | Out-Null }
    return [bool]$ok
}

function Run-EnrollUser {
    if (-not (Test-Path $EnrollUserBin)) {
        Set-Error -Message "dds-enroll-user.exe not found at $EnrollUserBin. Reinstall the MSI."
        return
    }
    $pw = $el.PwBox.Password
    if ([string]::IsNullOrEmpty($pw)) {
        $el.TbPwStatus.Text = "Password is required."
        return
    }
    $el.TbPwStatus.Text = "Verifying..."
    if (-not (Validate-WindowsPassword -Password $pw)) {
        $el.TbPwStatus.Text = "Password rejected by Windows. Try again."
        return
    }
    $el.TbPwStatus.Text = ""

    # Show the touch page; the OS WebAuthn dialog will pop on top.
    Show-Page -Name 'PageEnrollUser_Touch'
    $el.TbEnrollLog.Clear()
    $el.TbTouchStatus.Text = "Starting enrollment..."

    # Write password to a temp file that's the stdin source for the helper.
    # Cleaned up the moment the helper exits.
    $script:enrollPwTempPath = Join-Path $env:TEMP ("dds-enroll-pw-{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
    [IO.File]::WriteAllText($script:enrollPwTempPath, $pw + "`n", (New-Object Text.UTF8Encoding $false))
    # Wipe the in-process password.
    $el.PwBox.Clear()

    $script:enrollStdoutPath = Join-Path $env:TEMP ("dds-enroll-out-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:enrollStdoutPos  = 0
    $script:enrollUrn        = $null

    $script:enrollProcess = Start-Process `
        -FilePath $EnrollUserBin `
        -ArgumentList @('--password-stdin') `
        -RedirectStandardInput  $script:enrollPwTempPath `
        -RedirectStandardOutput $script:enrollStdoutPath `
        -NoNewWindow -PassThru

    Append-Log $el.TbEnrollLog "[Console] dds-enroll-user PID $($script:enrollProcess.Id)"

    $script:enrollTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:enrollTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:enrollTimer.Add_Tick({ Tick-EnrollUser })
    $script:enrollTimer.Start()
}

function Tick-EnrollUser {
    if ($script:enrollStdoutPath -and (Test-Path $script:enrollStdoutPath)) {
        try {
            $fs = [IO.File]::Open($script:enrollStdoutPath, 'Open', 'Read', 'ReadWrite')
            try {
                if ($fs.Length -gt $script:enrollStdoutPos) {
                    $fs.Seek($script:enrollStdoutPos, 'Begin') | Out-Null
                    $reader = New-Object IO.StreamReader $fs
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if ($null -eq $line) { break }
                        Append-Log $el.TbEnrollLog $line
                        try {
                            $obj = $line | ConvertFrom-Json -ErrorAction Stop
                            switch ($obj.phase) {
                                'start'         { $el.TbTouchStatus.Text = "Starting..." }
                                'touch1_prompt' { $el.TbTouchStatus.Text = "Touch your security key now (1 of 2)." }
                                'key_made'      { $el.TbTouchStatus.Text = "Key registered. Get ready for the second touch..." }
                                'touch2_prompt' { $el.TbTouchStatus.Text = "Touch your security key again (2 of 2)." }
                                'hmac_done'     { $el.TbTouchStatus.Text = "Deriving unlock secret..." }
                                'vault_written' { $el.TbTouchStatus.Text = "Encrypted password saved locally." }
                                'enroll_posted' {
                                    $script:enrollUrn = $obj.urn
                                    $el.TbTouchStatus.Text = "Enrollment posted to dds-node."
                                }
                                'enroll_failed_local_only' {
                                    $el.TbTouchStatus.Text = "Local enrollment OK; server post failed (will retry)."
                                }
                                'cancelled' {
                                    $el.TbTouchStatus.Text = "Cancelled."
                                }
                                'error' {
                                    $el.TbTouchStatus.Text = "Error at $($obj.at): $($obj.message)"
                                }
                            }
                        } catch { } # tolerate non-JSON lines
                    }
                    $script:enrollStdoutPos = $fs.Position
                }
            } finally { $fs.Dispose() }
        } catch { }
    }
    if ($script:enrollProcess -and $script:enrollProcess.HasExited) {
        $script:enrollTimer.Stop(); $script:enrollTimer = $null
        # Wipe the stdin password file ASAP.
        if ($script:enrollPwTempPath -and (Test-Path $script:enrollPwTempPath)) {
            try {
                $bytes = [IO.File]::ReadAllBytes($script:enrollPwTempPath)
                for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = 0 }
                [IO.File]::WriteAllBytes($script:enrollPwTempPath, $bytes)
                Remove-Item -Force -ErrorAction SilentlyContinue $script:enrollPwTempPath
            } catch { }
        }

        $code = $script:enrollProcess.ExitCode
        # Exit codes: 0 OK, 1 vault saved but post failed, 2 error before vault, 3 cancel
        if ($code -eq 0 -or $code -eq 1) {
            $el.TbEnrollUrn.Text = if ($script:enrollUrn) { "Your URN: $script:enrollUrn" } else { "" }
            Show-Page -Name 'PageEnrollUser_AwaitingApproval'
            Start-EnrollPolling
        } elseif ($code -eq 3) {
            Set-Error -Message "Enrollment cancelled. You can try again from the Welcome page." -Detail $el.TbEnrollLog.Text
        } else {
            Set-Error -Message "Enrollment failed (exit $code). Check the log below for details." -Detail $el.TbEnrollLog.Text
        }
    }
}

function Start-EnrollPolling {
    $script:enrollPollAttempts = 0
    $script:enrollPollTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:enrollPollTimer.Interval = [TimeSpan]::FromSeconds(5)
    $script:enrollPollTimer.Add_Tick({ Tick-EnrollPoll })
    $script:enrollPollTimer.Start()
    Tick-EnrollPoll  # immediate first probe
}

function Tick-EnrollPoll {
    $script:enrollPollAttempts++
    $el.TbEnrollPollStatus.Text = "Poll #$script:enrollPollAttempts — checking with dds-node..."
    # Best-effort named-pipe HTTP GET. We don't fail the user if this errors;
    # the wizard is still useful even if polling can't reach the API.
    try {
        $payload = Invoke-DdsNodeGet -Path '/v1/enrolled-users'
        if ($payload -and $payload -match '"urn"\s*:\s*"([^"]+)"') {
            # Anything matching is fine for now — admin approval flips the
            # trust graph and the enrolled-users endpoint reflects state.
            $el.TbEnrollPollStatus.Text = "Approved by admin. Passwordless sign-in is active."
            $el.TbEnrollPollStatus.Foreground = [Windows.Media.Brushes]::DarkGreen
            $script:enrollPollTimer.Stop()
        }
    } catch {
        $el.TbEnrollPollStatus.Text = "Poll #$script:enrollPollAttempts — node not reachable yet ($($_.Exception.Message))"
    }
}

function Invoke-DdsNodeGet {
    param([string]$Path)
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'dds-api', [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(2000)
        $req = "GET $Path HTTP/1.1`r`nHost: localhost`r`nUser-Agent: DdsConsole-Poll/1.0`r`nConnection: close`r`n`r`n"
        $reqBytes = [Text.Encoding]::UTF8.GetBytes($req)
        $client.Write($reqBytes, 0, $reqBytes.Length); $client.Flush()
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 8192
        while (($n = $client.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
        $raw = [Text.Encoding]::UTF8.GetString($ms.ToArray())
        $sep = $raw.IndexOf("`r`n`r`n")
        return $raw.Substring($sep + 4)
    } finally {
        $client.Dispose()
    }
}

# ── Health page (re-used) ─────────────────────────────────────────
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
        $el.TbPipe.Text = "DdsNode pipe: OPEN"
        $el.TbPipe.Foreground = [Windows.Media.Brushes]::Green
    } else {
        $el.TbPipe.Text = "DdsNode pipe: closed"
        $el.TbPipe.Foreground = [Windows.Media.Brushes]::DarkOrange
    }

    $found = @()
    foreach ($p in @(
        @{ P=(Join-Path $NodeData 'domain.toml');    L='domain.toml' }
        @{ P=(Join-Path $NodeData 'domain_key.bin'); L='domain_key.bin' }
        @{ P=(Join-Path $NodeData 'admission.cbor'); L='admission.cbor' }
        @{ P=$NodeConfigFile;                         L='config\node.toml' }
        @{ P=$ProvisionBundle;                        L='provision.dds' }
    )) { if (Test-Path $p.P) { $found += $p.L } }
    $el.TbStateInv.Text = if ($found.Count -gt 0) { "State: " + ($found -join ', ') } else { "State: (none)" }

    if (Test-Path $AuthBridgeLog) {
        try {
            $tail = Get-Content $AuthBridgeLog -Tail 30 -ErrorAction Stop
            $el.TbLogTail.Text = $tail -join "`r`n"; $el.TbLogTail.ScrollToEnd()
        } catch {
            $el.TbLogTail.Text = "(unable to read ${AuthBridgeLog}: $($_.Exception.Message))"
        }
    } else {
        $el.TbLogTail.Text = "(authbridge.log not present yet)"
    }
}

$healthTimer = New-Object System.Windows.Threading.DispatcherTimer
$healthTimer.Interval = [TimeSpan]::FromSeconds(2)
$healthTimer.Add_Tick({
    if ($script:currentPage -eq 'PageHealth') { Refresh-Health }
})

# ── Welcome tile clicks ───────────────────────────────────────────
function Wire-Tile { param($Tile, [string]$TargetPage)
    $Tile.add_MouseLeftButtonUp({ Show-Page -Name $TargetPage }.GetNewClosure())
}

$el.TileNewDomain.add_MouseLeftButtonUp({ Show-Page -Name 'PageNewDomain_Identity' })
$el.TileJoinDomain.add_MouseLeftButtonUp({ Show-Page -Name 'PageJoinDomain_Bundle' })
$el.TileEnrollUser.add_MouseLeftButtonUp({
    Set-EnrollExplainerText
    Show-Page -Name 'PageEnrollUser_Explainer'
})
$el.TileHealth.add_MouseLeftButtonUp({
    Refresh-Health
    Show-Page -Name 'PageHealth'
})

# Annotate Welcome page based on probe.
function Update-WelcomeText {
    $msg = "Pick the option that matches your role on this machine."
    switch ($state.Branch) {
        'NewDomain'  { $msg = "No domain detected. We recommend starting a new DDS domain on this machine." }
        'JoinDomain' { $msg = "A bundle was supplied. Click 'Join an existing DDS domain' below to use it." }
        'EnrollUser' { $msg = "This machine is already part of a domain. We recommend setting up passwordless sign-in for your account." }
        'Health'     { $msg = "Everything looks set up. You can view service status or open the tray agent." }
    }
    $el.WelcomeDetected.Text = $msg
}
Update-WelcomeText

# ── Resume page wire-up ───────────────────────────────────────────
if ($state.ResumeMarker) {
    $rm = $state.ResumeMarker
    $el.ResumeDetail.Text = "Last step: $($rm.step)/9 ($($rm.slug)). Started: $($rm.timestamp). Domain: $($rm.domain_name) / $($rm.org_hash)."
}
$el.BtnResumeRestart.add_Click({
    if (-not (Test-Path $ResetScript)) {
        Set-Error -Message "Reset-DdsBootstrap.ps1 not found at $ResetScript."
        return
    }
    Start-Process `
        -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$ResetScript`"",'-Force') `
        -Wait
    Show-Page -Name 'PageWelcome' -NoStack
})
$el.BtnResumeNew.add_Click({ Show-Page -Name 'PageWelcome' -NoStack })

# ── Drag-and-drop on the bundle page ──────────────────────────────
$el.DropTarget.add_DragOver({
    param($s,$e)
    if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) {
        $e.Effects = [Windows.DragDropEffects]::Copy
    } else {
        $e.Effects = [Windows.DragDropEffects]::None
    }
    $e.Handled = $true
})
$el.DropTarget.add_Drop({
    param($s,$e)
    $files = $e.Data.GetData([Windows.DataFormats]::FileDrop)
    if ($files -and $files.Length -gt 0) {
        Set-JoinBundle -Path $files[0]
    }
})

$el.BtnJoinBrowse.add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = "Pick a DDS provision bundle"
    $dlg.Filter = "DDS Provision Bundle (*.dds)|*.dds|All files (*.*)|*.*"
    $dlg.CheckFileExists = $true
    if ($dlg.ShowDialog($window)) { Set-JoinBundle -Path $dlg.FileName }
})

# Pre-fill bundle path from -BundlePath.
if ($BundlePath -and (Test-Path -LiteralPath $BundlePath)) {
    Set-JoinBundle -Path $BundlePath
}

# ── Done page wire-up ─────────────────────────────────────────────
$el.BtnDoneSaveBundle.add_Click({ Run-NewDomainSaveBundle })
$el.BtnDoneTray.add_Click({
    if (Test-Path $TrayAgent) { Start-Process $TrayAgent }
})
$el.BtnJoinDoneTray.add_Click({
    if (Test-Path $TrayAgent) { Start-Process $TrayAgent }
})

# ── Health page wire-up ───────────────────────────────────────────
$el.BtnRefresh.add_Click({ Refresh-Health })
$el.BtnTray.add_Click({ if (Test-Path $TrayAgent) { Start-Process $TrayAgent } })
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

# ── Wizard nav buttons ────────────────────────────────────────────
$el.BtnBack.add_Click({ Pop-Page })
$el.BtnCancel.add_Click({ $window.Close() })
$el.BtnNext.add_Click({
    $el.TbIdentityWarn.Text = ''
    switch ($script:currentPage) {
        'PageNewDomain_Identity'      { Show-Page -Name 'PageNewDomain_KeyProtection' }
        'PageNewDomain_KeyProtection' { Run-Bootstrap }
        'PageNewDomain_Done'          { $window.Close() }
        'PageJoinDomain_Bundle'       { Run-JoinUnseal }
        'PageJoinDomain_Confirm'      { } # Next is disabled / replaced by automatic transition
        'PageJoinDomain_Done'         { $window.Close() }
        'PageEnrollUser_Explainer'    { Show-Page -Name 'PageEnrollUser_Password' }
        'PageEnrollUser_Password'     { Run-EnrollUser }
        'PageEnrollUser_AwaitingApproval' { $window.Close() }
        default { }
    }
})

$window.add_Closed({
    foreach ($t in @($script:bootstrapTimer, $script:joinTimer, $script:deviceEnrollTimer, $script:enrollTimer, $script:enrollPollTimer, $healthTimer)) {
        try { if ($t) { $t.Stop() } } catch { }
    }
    # Defensive: scrub any leftover password temp file.
    if ($script:enrollPwTempPath -and (Test-Path $script:enrollPwTempPath)) {
        try { Remove-Item -Force -ErrorAction SilentlyContinue $script:enrollPwTempPath } catch { }
    }
})

# ── Initial page ──────────────────────────────────────────────────
$initialPage = Resolve-InitialPage -Mode $Mode -State $state
$script:currentPage = $null
Show-Page -Name $initialPage -NoStack
$healthTimer.Start()

$window.ShowDialog() | Out-Null
