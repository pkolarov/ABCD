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
    [ValidateSet('Auto','NewDomain','JoinDomain','EnrollUser','Health','UsersPolicy')]
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
$DdsBin              = Join-Path $BinDir      "dds.exe"
$EnrollUserBin       = Join-Path $BinDir      "dds-enroll-user.exe"
# The node's local API listens on this named pipe (see node.toml
# [network].api_addr). The `dds` CLI reaches it with the `pipe:` scheme.
$NodeUrl             = 'pipe:dds-api'
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
        'UsersPolicy' { return 'PagePolicy' }
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
        <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
        <StackPanel>
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
          <Border x:Name="TileUsersPolicy" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Margin="0,0,0,10" Background="White"
                  Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="Create a user account / manage policy"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Admin: create a new Windows account for an enrolled DDS user (passwordless first-logon), or publish registry / service / password policy to the domain."/>
            </StackPanel>
          </Border>
          <Border x:Name="TileHealth" CornerRadius="6" BorderBrush="#cccccc"
                  BorderThickness="1" Padding="14" Margin="0,0,0,2" Background="White" Cursor="Hand">
            <StackPanel>
              <TextBlock FontSize="15" FontWeight="SemiBold"
                         Text="View status / open Tray Agent"/>
              <TextBlock Foreground="#555555" Margin="0,4,0,0" TextWrapping="Wrap"
                         Text="Skip onboarding and jump to the service status view."/>
            </StackPanel>
          </Border>
        </StackPanel>
        </ScrollViewer>
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
                   Text="A new console window will open shortly. Follow its prompts to protect the domain key. Once bootstrap finishes, you'll be asked to touch your FIDO2 key once more to register yourself as the first admin. Progress is mirrored here."/>
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
                   Text="Step 1 of 4 — Register a key for THIS account"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,4,0,12" TextWrapping="Wrap"
                   x:Name="TbEnrollExplain"
                   Text="This registers a security key for the Windows account you are currently signed in as. The new DDS user will be named after this account, so only this account's owner should register their key here."/>
        <StackPanel Grid.Row="2">
          <TextBlock FontWeight="SemiBold" Margin="0,0,0,4" Text="You'll need:"/>
          <TextBlock Margin="0,0,0,2" Text="• To be signed in as the person whose key you're registering (the DDS user is named after this account)"/>
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
          <Button x:Name="BtnUsersPolicy" Content="Users &amp; Policy..." Padding="14,4" Margin="4"/>
          <Button x:Name="BtnManage" Content="Manage people &amp; admins..." Padding="14,4" Margin="4"/>
          <Button x:Name="BtnDecommission" Content="Leave domain..." Padding="14,4" Margin="4"/>
          <Button x:Name="BtnRefresh" Content="Refresh now" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnTray"    Content="Open Tray Agent" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStartAll" Content="Start all services" Padding="14,4" Margin="4"/>
          <Button x:Name="BtnStopAll"  Content="Stop all services"  Padding="14,4" Margin="4"/>
        </StackPanel>
      </Grid>

      <!-- ============ Users & Policy ============ -->
      <Grid x:Name="PagePolicy" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Publisher authorization banner -->
        <Border Grid.Row="0" x:Name="PubBanner" Background="#FFF4CE" BorderBrush="#E0C36B"
                BorderThickness="1" CornerRadius="3" Padding="10" Margin="0,0,0,8">
          <Grid>
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <TextBlock Grid.Column="0" x:Name="TbPubStatus" TextWrapping="Wrap"
                       VerticalAlignment="Center" Text="Checking publish authorization..."/>
            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
              <Button x:Name="BtnPubAuthorize" Content="Authorize this machine" Padding="8,3"
                      Margin="8,0,0,0" Visibility="Collapsed"/>
              <Button x:Name="BtnPubCopyGrant" Content="Copy machine ID" Padding="8,3"
                      Margin="8,0,0,0" Visibility="Collapsed"/>
              <Button x:Name="BtnPubCheck" Content="Re-check" Padding="8,3" Margin="8,0,0,0"/>
            </StackPanel>
          </Grid>
        </Border>

        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
          <StackPanel>
            <!-- New user account (first-account claim) -->
            <GroupBox Header="Create a Windows account for a person" Padding="12" Margin="0,0,0,10">
              <StackPanel>
                <TextBlock TextWrapping="Wrap" Foreground="#444444" Margin="0,0,0,12"
                           Text="Onboard anyone onto DDS with their security key -- from THIS machine, whatever account you're signed in as. No password is ever typed and no borrowed account is used: the person's Windows account is created automatically the first time they sign in with their key."/>

                <!-- 1. The person -->
                <TextBlock Text="1.  Who is the account for?" FontWeight="SemiBold" Margin="0,0,0,4"/>
                <Grid Margin="0,0,0,2">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="150"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                  </Grid.RowDefinitions>
                  <TextBlock Grid.Row="0" Grid.Column="0" Text="Windows username:" VerticalAlignment="Center" Margin="0,3"/>
                  <StackPanel Grid.Row="0" Grid.Column="1" Orientation="Horizontal" Margin="0,3">
                    <TextBox x:Name="TbAcctUser" Width="200"
                             ToolTip="1-20 characters: letters, numbers, . - _   (no spaces; cannot end with a dot)"/>
                    <TextBlock VerticalAlignment="Center" Foreground="#888888" FontSize="11" Margin="10,0,0,0"
                               Text="e.g. jsmith -- the name they sign in with"/>
                  </StackPanel>
                  <TextBlock Grid.Row="1" Grid.Column="0" Text="Full name:" VerticalAlignment="Center" Margin="0,3"/>
                  <StackPanel Grid.Row="1" Grid.Column="1" Orientation="Horizontal" Margin="0,3">
                    <TextBox x:Name="TbAcctFullName" Width="240"/>
                    <TextBlock VerticalAlignment="Center" Foreground="#888888" FontSize="11" Margin="10,0,0,0"
                               Text="e.g. Jane Smith -- becomes the DDS user's name"/>
                  </StackPanel>
                </Grid>

                <!-- 2. Their key -->
                <TextBlock Text="2.  Their security key" FontWeight="SemiBold" Margin="0,10,0,4"/>
                <Border Background="#EAF3FB" BorderBrush="#B9D6EE" BorderThickness="1" CornerRadius="3"
                        Padding="10" Margin="0,0,0,6">
                  <StackPanel>
                    <TextBlock TextWrapping="Wrap" Foreground="#264a63"
                               Text="New person (no key registered yet): have them plug THEIR security key into this PC, then click Register. They touch their own key -- this creates their DDS identity named after the Full name above. No borrowed account, no password."/>
                    <Button x:Name="BtnEnrollNewPerson" Content="Register this person's key"
                            HorizontalAlignment="Left" Padding="12,4" Margin="0,8,0,0"/>
                    <TextBlock x:Name="TbEnrollNpStatus" Foreground="#264a63" FontSize="11"
                               TextWrapping="Wrap" Margin="0,6,0,0" Text=""/>
                  </StackPanel>
                </Border>
                <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                  <TextBlock VerticalAlignment="Center" Foreground="#888888" FontSize="11"
                             Text="Already enrolled? Pick them:"/>
                  <ComboBox x:Name="CbClaimSubject" Width="300" IsEditable="False" Margin="8,0,0,0"
                            ToolTip="DDS users already enrolled on this domain."/>
                  <Button x:Name="BtnLoadUsers" Content="Refresh" Padding="8,2" Margin="8,0,0,0"/>
                </StackPanel>
                <TextBlock Foreground="#888888" FontSize="11" TextWrapping="Wrap" Margin="0,4,0,2"
                           Text="DDS identity (filled in by Register, or by picking from the list):"/>
                <TextBox x:Name="TbClaimSubject" FontFamily="Consolas" FontSize="11" IsReadOnly="True"
                         Margin="0,0,0,12" Background="#F3F3F3"/>

                <!-- Groups -->
                <StackPanel Margin="0,0,0,12">
                  <TextBlock Text="Windows groups (optional)" FontWeight="SemiBold"/>
                  <TextBlock Foreground="#666666" FontSize="11" TextWrapping="Wrap" Margin="0,2,0,5"
                             Text="Which Windows groups the account belongs to, separated by commas. Leave 'Users' for a normal account; add 'Administrators' to make them a local admin on the PC."/>
                  <TextBox x:Name="TbAcctGroups" Text="Users" Width="360" HorizontalAlignment="Left"
                           ToolTip="Comma-separated Windows group names, e.g. Users, Remote Desktop Users"/>
                </StackPanel>

                <!-- 3. Which computers -->
                <StackPanel Margin="0,0,0,12">
                  <TextBlock Text="3.  Which computers can this account be created on?" FontWeight="SemiBold"/>
                  <TextBlock Foreground="#666666" FontSize="11" TextWrapping="Wrap" Margin="0,2,0,5"
                             Text="'All computers' is the usual choice. Pick a specific computer only if this account should exist on just one machine -- then paste that computer's device ID (starts with urn:vouchsafe:). Note: the account is auto-created only on workgroup or Entra-joined PCs, not on Active-Directory domain-joined machines."/>
                  <RadioButton x:Name="RbAcctAllDevices" GroupName="AcctScope"
                               Content="All computers in the domain" IsChecked="True" Margin="0,0,0,4"/>
                  <StackPanel Orientation="Horizontal">
                    <RadioButton x:Name="RbAcctDevice" GroupName="AcctScope"
                                 Content="Only a specific computer:" VerticalAlignment="Center" Margin="0,0,6,0"/>
                    <TextBox x:Name="TbAcctDeviceUrn" Width="300" FontFamily="Consolas" FontSize="11"
                             ToolTip="The target computer's device ID (urn:vouchsafe:...). Run 'dds status' on that PC to find it."/>
                  </StackPanel>
                </StackPanel>

                <!-- Password never expires -->
                <StackPanel Margin="0,0,0,12">
                  <CheckBox x:Name="CbAcctPwNever" Content="Password never expires (recommended)" IsChecked="True"/>
                  <TextBlock Foreground="#666666" FontSize="11" TextWrapping="Wrap" Margin="20,2,0,0"
                             Text="Keep this on. DDS manages the password and wraps it with the security key, so it never needs to be changed."/>
                </StackPanel>

                <!-- 4. Approve (in-console admin vouch) -->
                <TextBlock Text="4.  Approve this person (admin)" FontWeight="SemiBold" Margin="0,0,0,4"/>
                <Border Background="#FBF3EA" BorderBrush="#EED9B9" BorderThickness="1" CornerRadius="3"
                        Padding="10" Margin="0,0,0,10">
                  <StackPanel>
                    <TextBlock TextWrapping="Wrap" Foreground="#63482a"
                               Text="An administrator approves the new user by touching the ADMIN security key (not the person's key). This is the same approval the tray's 'Approve Enrollments' does -- now right here, so you don't have to leave this window. It unlocks once step 2 has registered someone (or you pick an enrolled person from the list)."/>
                    <Button x:Name="BtnApproveNewPerson" Content="Approve (touch admin key)" IsEnabled="False"
                            HorizontalAlignment="Left" Padding="12,4" Margin="0,8,0,0"/>
                    <TextBlock x:Name="TbApproveNpStatus" Foreground="#63482a" FontSize="11"
                               TextWrapping="Wrap" Margin="0,6,0,0" Text=""/>
                  </StackPanel>
                </Border>

                <!-- 5. Publish -->
                <TextBlock Text="5.  Create the account" FontWeight="SemiBold" Margin="0,0,0,4"/>
                <Button x:Name="BtnCreateAccount" Content="Publish -- create this account" IsEnabled="False"
                        HorizontalAlignment="Left" Padding="16,6" Margin="0,2,0,2"/>
                <TextBlock Foreground="#666666" FontSize="11" TextWrapping="Wrap" Margin="0,3,0,0"
                           Text="Unlocks once step 4 approves this person. Publishes the account to the domain; it reaches the target computer(s) within about a minute and is created when the person first signs in with their security key. Progress and errors appear in the Output box below."/>
              </StackPanel>
            </GroupBox>

            <!-- Advanced: author any policy from JSON / templates -->
            <GroupBox Header="Author any policy (registry, services, password, accounts)" Padding="10">
              <StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                  <TextBlock Text="Platform:" VerticalAlignment="Center"/>
                  <ComboBox x:Name="CbPlatform" Width="110" Margin="6,0,16,0">
                    <ComboBoxItem Content="windows" IsSelected="True"/>
                    <ComboBoxItem Content="macos"/>
                    <ComboBoxItem Content="linux"/>
                  </ComboBox>
                  <TextBlock Text="Template:" VerticalAlignment="Center"/>
                  <ComboBox x:Name="CbTemplate" Width="200" Margin="6,0,12,0">
                    <ComboBoxItem Content="Registry value" IsSelected="True"/>
                    <ComboBoxItem Content="Service config"/>
                    <ComboBoxItem Content="Password policy"/>
                    <ComboBoxItem Content="Local account"/>
                    <ComboBoxItem Content="Empty"/>
                  </ComboBox>
                  <Button x:Name="BtnFillTemplate" Content="Insert template" Padding="8,2"/>
                </StackPanel>
                <TextBox x:Name="TbPolicyJson" Height="170" AcceptsReturn="True" AcceptsTab="True"
                         FontFamily="Consolas" FontSize="12" VerticalScrollBarVisibility="Auto"
                         HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap"
                         Background="#1e1e1e" Foreground="#dcdcdc"/>
                <Button x:Name="BtnPublishJson" Content="Publish policy" HorizontalAlignment="Left"
                        Padding="14,5" Margin="0,8,0,0"/>
              </StackPanel>
            </GroupBox>
          </StackPanel>
        </ScrollViewer>

        <GroupBox Grid.Row="2" Header="Output" Margin="0,8,0,0">
          <TextBox x:Name="TbPolicyLog" Height="96" IsReadOnly="True" FontFamily="Consolas"
                   FontSize="11" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
        </GroupBox>
      </Grid>

      <!-- ============ Manage people & admins ============ -->
      <Grid x:Name="PageManage" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0">
          <TextBlock FontSize="16" FontWeight="SemiBold" Text="Manage people &amp; administrators"/>
          <TextBlock Foreground="#555555" Margin="0,4,0,8" TextWrapping="Wrap"
                     Text="Approve or remove people's access, and add or remove administrators. Every change is signed with an ADMIN security key and then confirmed to have replicated to another node before it's reported as done."/>
        </StackPanel>

        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
          <StackPanel>
            <!-- People -->
            <GroupBox Header="People on this domain" Padding="10" Margin="0,0,0,10">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="260"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,10,0">
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,4">
                    <Button x:Name="BtnMgRefreshUsers" Content="Refresh" Padding="10,3"/>
                    <CheckBox x:Name="CbMgShowRevoked" Content="Show removed (offboarded) people"
                              VerticalAlignment="Center" Margin="12,0,0,0"/>
                  </StackPanel>
                  <ListBox x:Name="LbMgUsers" Height="150" FontFamily="Consolas" FontSize="11"/>
                </StackPanel>
                <StackPanel Grid.Column="1">
                  <TextBlock Text="Selected person" FontWeight="SemiBold"/>
                  <TextBlock x:Name="TbMgUserDetail" Foreground="#555555" FontSize="11"
                             TextWrapping="Wrap" Margin="0,2,0,8" Text="(pick a person on the left)"/>
                  <Button x:Name="BtnMgOffboard" Content="Remove access (offboard)…" IsEnabled="False"
                          Padding="10,5" Margin="0,0,0,6"/>
                  <Button x:Name="BtnMgMakeAdmin" Content="Make this person an admin…" IsEnabled="False"
                          Padding="10,5"/>
                </StackPanel>
              </Grid>
            </GroupBox>

            <!-- Admins -->
            <GroupBox Header="Administrators (trusted roots)" Padding="10" Margin="0,0,0,10">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="260"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,10,0">
                  <Button x:Name="BtnMgRefreshAdmins" Content="Refresh" Padding="10,3" HorizontalAlignment="Left" Margin="0,0,0,4"/>
                  <ListBox x:Name="LbMgAdmins" Height="110" FontFamily="Consolas" FontSize="11"/>
                </StackPanel>
                <StackPanel Grid.Column="1">
                  <TextBlock Text="Selected admin" FontWeight="SemiBold"/>
                  <TextBlock x:Name="TbMgAdminDetail" Foreground="#555555" FontSize="11"
                             TextWrapping="Wrap" Margin="0,2,0,8" Text="(pick an admin on the left)"/>
                  <Button x:Name="BtnMgRemoveAdmin" Content="Remove admin rights…" IsEnabled="False"
                          Padding="10,5"/>
                  <TextBlock Foreground="#888888" FontSize="10" TextWrapping="Wrap" Margin="0,6,0,0"
                             Text="The founding (bootstrap) admin can't be removed here — its authority is anchored in each node's config, not a vouch."/>
                </StackPanel>
              </Grid>
            </GroupBox>

            <!-- Replication confirmation -->
            <Border Background="#EAF3FB" BorderBrush="#B9D6EE" BorderThickness="1" CornerRadius="3" Padding="8">
              <TextBlock x:Name="TbMgReplStatus" Foreground="#264a63" TextWrapping="Wrap"
                         Text="Replication status of the last change appears here."/>
            </Border>
          </StackPanel>
        </ScrollViewer>

        <GroupBox Grid.Row="2" Header="Output" Margin="0,8,0,0">
          <TextBox x:Name="TbMgLog" Height="90" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                   VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                   TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
        </GroupBox>
      </Grid>

      <!-- ============ Decommission / leave domain ============ -->
      <Grid x:Name="PageDecommission" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" FontSize="16" FontWeight="SemiBold" Foreground="#B33A00"
                   Text="Remove DDS / leave the domain on this machine"/>
        <TextBlock Grid.Row="1" Foreground="#555555" Margin="0,6,0,10" TextWrapping="Wrap"
                   Text="This wipes this machine's DDS domain identity (node key, domain files, admission cert) and stops the services, returning the machine to an un-provisioned state. Windows accounts already created on this PC are NOT deleted. Use this before uninstalling, or to re-join a different domain."/>
        <StackPanel Grid.Row="2">
          <CheckBox x:Name="CbDecomRevoke" Margin="0,0,0,6"
                    Content="Also revoke this machine's admission so peers stop trusting it (recommended)"/>
          <TextBlock Foreground="#888888" FontSize="11" TextWrapping="Wrap" Margin="20,0,0,10"
                     Text="Requires the domain key on THIS machine. If the domain key lives elsewhere, leave this off and run 'dds-node revoke-admission' from the machine that has it. Without revocation, other nodes keep trusting this machine's peer id until its admission cert expires."/>
          <CheckBox x:Name="CbDecomConfirm" Margin="0,0,0,10"
                    Content="I understand this wipes DDS provisioning state on this machine."/>
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnDecomRun" Content="Leave domain / wipe state" IsEnabled="False"
                    Padding="14,6" Margin="0,0,10,0" Background="#F3D6C6"/>
            <TextBlock x:Name="TbDecomStatus" VerticalAlignment="Center" Foreground="#555555"/>
          </StackPanel>
        </StackPanel>
        <TextBox Grid.Row="3" x:Name="TbDecomLog" IsReadOnly="True" FontFamily="Consolas" FontSize="11"
                 Margin="0,10,0,0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"
                 TextWrapping="NoWrap" Background="#1e1e1e" Foreground="#dcdcdc"/>
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
    'PageHealth','PagePolicy','PageManage','PageDecommission','PageError',
    'BtnManage','BtnMgRefreshUsers','CbMgShowRevoked','LbMgUsers','TbMgUserDetail',
    'BtnMgOffboard','BtnMgMakeAdmin','BtnMgRefreshAdmins','LbMgAdmins','TbMgAdminDetail',
    'BtnMgRemoveAdmin','TbMgReplStatus','TbMgLog',
    'CbDecomRevoke','CbDecomConfirm','BtnDecomRun','TbDecomStatus','TbDecomLog','BtnDecommission',
    'PubBanner','TbPubStatus','BtnPubCheck','BtnPubCopyGrant','BtnPubAuthorize',
    'BtnEnrollNewPerson','TbEnrollNpStatus','CbClaimSubject','BtnLoadUsers','TbClaimSubject','TbAcctUser','TbAcctFullName','TbAcctGroups',
    'RbAcctAllDevices','RbAcctDevice','TbAcctDeviceUrn','CbAcctPwNever','BtnCreateAccount',
    'BtnApproveNewPerson','TbApproveNpStatus',
    'CbPlatform','CbTemplate','BtnFillTemplate','TbPolicyJson','BtnPublishJson','TbPolicyLog',
    'BtnUsersPolicy',
    'WelcomeDetected','TileNewDomain','TileJoinDomain','TileEnrollUser','TileUsersPolicy','TileHealth',
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
    'PageHealth','PagePolicy','PageManage','PageDecommission','PageError'
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
        'PageEnrollUser_Explainer' { $el.HdrSubtitle.Text = 'Set up passwordless sign-in'; Set-EnrollExplainerText }
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
        'PagePolicy' {
            $el.HdrSubtitle.Text = 'Users & Policy'
            $el.BtnNext.Visibility = 'Hidden'
            # Back returns to Health when we came from there; otherwise Close.
            $el.BtnBack.IsEnabled = ($script:pageStack.Count -gt 0)
            $el.BtnCancel.Content = 'Close'
            # Refresh live state on entry (publisher authorization + user list).
            Enter-PolicyPage
        }
        'PageManage' {
            $el.HdrSubtitle.Text = 'Manage people & admins'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnBack.IsEnabled = ($script:pageStack.Count -gt 0)
            $el.BtnCancel.Content = 'Close'
            Enter-ManagePage
        }
        'PageDecommission' {
            $el.HdrSubtitle.Text = 'Leave domain'
            $el.BtnNext.Visibility = 'Hidden'
            $el.BtnBack.IsEnabled = ($script:pageStack.Count -gt 0)
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

# ── Wizard journal (bulletproofing) ───────────────────────────────
# Every multi-step lifecycle flow writes a small JSON journal to
# $DataRoot\wizard-journal\<flow>.json recording the step it reached and
# the identifiers (URNs, JTIs) it produced. Two things fall out of this:
#   1. If the console crashes or is closed mid-flow, the NEXT launch can
#      detect the half-finished journal and offer to resume/verify rather
#      than leaving the operator guessing.
#   2. Each flow re-reads its journal before acting, so a repeated action
#      is idempotent (e.g. "already approved this subject — skip the
#      touch, go straight to confirm").
$JournalDir = Join-Path $DataRoot 'wizard-journal'

function Get-JournalPath { param([string]$Flow) Join-Path $JournalDir ("{0}.json" -f $Flow) }

function Write-Journal {
    param([string]$Flow, [hashtable]$State)
    try {
        if (-not (Test-Path $JournalDir)) { New-Item -ItemType Directory -Force -Path $JournalDir | Out-Null }
        $State['flow']       = $Flow
        $State['updated_at'] = (Get-Date).ToString('o')
        $path = Get-JournalPath $Flow
        # Write to a temp sibling then move, so a crash mid-write can't
        # leave a truncated journal that fails to parse on resume.
        $tmp = "$path.tmp"
        ($State | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $path -Force
    } catch {
        # Journaling is best-effort telemetry, never fail the flow on it.
        Write-Host "journal write failed ($Flow): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

function Read-Journal {
    param([string]$Flow)
    $path = Get-JournalPath $Flow
    if (-not (Test-Path $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Clear-Journal {
    param([string]$Flow)
    $path = Get-JournalPath $Flow
    if (Test-Path $path) { try { Remove-Item -Force -LiteralPath $path } catch { } }
}

# ── Peer replication confirmation ─────────────────────────────────
# After any publish (create account, approve, offboard, add/remove
# admin), confirm the change actually replicated by asking a connected
# peer whether it holds the token(s) we just minted. Rides the node's
# GET /v1/replication/confirm endpoint (which probes peers over the
# existing anti-entropy sync protocol). Returns a pscustomobject:
#   Reached   = [bool] the endpoint answered
#   Peers     = [int]  admitted+connected peers the node could ask
#   Confirmed = [string[]] JTIs proven present on >=1 peer
#   Pending   = [string[]] JTIs asked-about but not yet confirmed
#   Message   = human summary for the UI
# NOTE: runs synchronously on the WPF UI thread (like the other ceremony
# steps), so the window is unresponsive while it polls. The node's probe
# endpoint self-caps at ~8-12s per call, and the retry defaults are kept
# low so an explicit admin action blocks for at most a few seconds in the
# common (LAN, sub-second sync) case. Callers on a hot path (page-open
# resume) pass -Retries 1 to bound it to a single probe.
function Confirm-Replication {
    param([string[]]$Jtis, [int]$Retries = 3, [int]$DelayMs = 1000)
    $jtis = @($Jtis | Where-Object { $_ }) | Select-Object -Unique
    if (-not $jtis -or $jtis.Count -eq 0) {
        return [pscustomobject]@{ Reached=$false; Peers=0; Confirmed=@(); Pending=@(); Message='(nothing to confirm)' }
    }
    $query = ($jtis -join ',')
    $lastPeers = 0
    for ($attempt = 1; $attempt -le [Math]::Max(1,$Retries); $attempt++) {
        try {
            $body = Invoke-DdsNodeGet -Path ("/v1/replication/confirm?jtis={0}" -f $query)
            $obj  = $body | ConvertFrom-Json
            # A non-200 (503 channel-closed, 504 timeout, 400) returns a
            # JSON error body with no admitted_connected field. Under
            # Set-StrictMode -Version Latest, reading the missing property
            # would throw and be misreported as "endpoint unreachable", so
            # detect the error shape explicitly (mirrors Refresh-PublisherStatus).
            $props = @($obj.PSObject.Properties.Name)
            if ($props -notcontains 'admitted_connected') {
                $why = if ($props -contains 'error') { [string]$obj.error } else { 'unexpected response' }
                # A node error is not a transport failure; report it and
                # stop (retrying won't change a shutting-down/starved node).
                return [pscustomobject]@{ Reached=$true; Peers=0; Confirmed=@(); Pending=$jtis;
                    Message=("The node could not run the replication check ({0}). The change is saved on THIS node; it will still replicate to peers." -f $why) }
            }
            $peers = [int]$obj.admitted_connected
            $lastPeers = $peers
            $confirmed = @(); if ($props -contains 'confirmed_jtis' -and $obj.confirmed_jtis) { $confirmed = @($obj.confirmed_jtis) }
            $pending = @($jtis | Where-Object { $confirmed -notcontains $_ })
            if ($peers -eq 0) {
                return [pscustomobject]@{ Reached=$true; Peers=0; Confirmed=@(); Pending=$jtis;
                    Message='No other nodes are connected right now, so replication could not be confirmed. The change is saved on THIS node and will sync when a peer connects.' }
            }
            if ($pending.Count -eq 0) {
                return [pscustomobject]@{ Reached=$true; Peers=$peers; Confirmed=$confirmed; Pending=@();
                    Message=("Confirmed replicated to {0} peer node(s)." -f $peers) }
            }
            # Some still pending — peers are online but haven't caught up
            # yet; wait a beat and re-probe (sync fires within ~60s but is
            # usually far faster).
            if ($attempt -lt $Retries) { Start-Sleep -Milliseconds $DelayMs }
        } catch {
            if ($attempt -lt $Retries) { Start-Sleep -Milliseconds $DelayMs }
            else {
                return [pscustomobject]@{ Reached=$false; Peers=0; Confirmed=@(); Pending=$jtis;
                    Message=("Could not reach the replication-confirm endpoint: {0}" -f $_.Exception.Message) }
            }
        }
    }
    return [pscustomobject]@{ Reached=$true; Peers=$lastPeers; Confirmed=@(); Pending=$jtis;
        Message=("Peers are connected but have not confirmed the change yet (still replicating). It should converge within a minute.") }
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
            Run-AdminSetupStep
        } else {
            Set-Status "Bootstrap failed (exit $code)." '#D13438'
            Set-Error -Message "Bootstrap failed with exit code $code." -Detail $el.TbLog.Text
        }
    }
}

# ── Branch A: admin setup (runs immediately after a successful bootstrap) ──
# C-2 security gate: dds-node refuses POST /v1/admin/setup until the
# operator has bootstrapped AND the .bootstrap sentinel exists (created by
# Bootstrap-DdsDomain.ps1's final step). Historically the wizard just told
# the operator to "launch the tray agent to enroll users" and left admin
# creation as a separate, easy-to-forget manual step — so a freshly
# bootstrapped domain had no admin and Admin Setup silently refused
# client-side (see AUDIT-2026-07-19). Run it here instead, automatically,
# via dds-enroll-user.exe --admin-setup -- same NDJSON/log-tail pattern as
# Authorize/Approve/New Person above (Read-AuthLog et al.), no MessageBox
# popups.
$script:adminSetupProc  = $null
$script:adminSetupTimer = $null
$script:adminSetupLog   = ''
$script:adminSetupPos   = 0
$script:adminSetupOk    = $false

function Stop-AdminSetupWait {
    if ($script:adminSetupTimer) { $script:adminSetupTimer.Stop(); $script:adminSetupTimer = $null }
}

function Finish-NewDomainWizard {
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
}

# Drain any newly-written NDJSON lines from the admin-setup log. Factored
# out so the exit branch can drain ONE more time after the process has
# exited (same race note as Read-AuthLog / Tick-AuthorizeMachine).
function Read-AdminSetupLog {
    if (-not ($script:adminSetupLog -and (Test-Path $script:adminSetupLog))) { return }
    try {
        $fs = [IO.File]::Open($script:adminSetupLog, 'Open', 'Read', 'ReadWrite')
        try {
            $fs.Seek($script:adminSetupPos, 'Begin') | Out-Null
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $script:adminSetupPos = $fs.Position
                if (-not $line.Trim()) { continue }
                try { $obj = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                switch ($obj.phase) {
                    'touch_prompt'       { Set-Status "Touch your FIDO2 key now to register the first admin..." '#0078d4' }
                    'credential_created' { Set-Status "Key registered; submitting admin setup..." '#0078d4' }
                    'admin_created'      { $script:adminSetupOk = $true; Append-Log $el.TbLog "[Console] Admin account created: $($obj.urn)" }
                    'error'              { Append-Log $el.TbLog "[Console] Admin setup error ($($obj.at)): $($obj.message)" }
                }
            }
        } finally { $fs.Close() }
    } catch { }
}

function Tick-AdminSetupWait {
    Read-AdminSetupLog
    if (-not $script:adminSetupProc -or -not $script:adminSetupProc.HasExited) { return }
    # Race fix (see Tick-AuthorizeMachine): the exe can flush its terminal
    # line and exit back-to-back, landing between a drain and this
    # HasExited check. One final drain guarantees the last line is read.
    Read-AdminSetupLog
    Stop-AdminSetupWait
    if ($script:adminSetupOk) {
        Set-Status "Bootstrap and admin setup completed successfully." '#107C10'
    } elseif (-not ($el.TbStatus.Text -match 'error')) {
        $code = $script:adminSetupProc.ExitCode
        $suffix = if ($null -ne $code) { " (exit $code)" } else { "" }
        Set-Status "Domain bootstrapped, but admin setup did not complete$suffix - retry from the tray icon's Admin Setup menu." '#D13438'
    }
    if ($script:adminSetupLog -and (Test-Path $script:adminSetupLog)) { Remove-Item -Force -ErrorAction SilentlyContinue $script:adminSetupLog }
    Finish-NewDomainWizard
}

function Run-AdminSetupStep {
    if (-not (Test-Path $EnrollUserBin)) {
        Append-Log $el.TbLog "[Console] $EnrollUserBin not found -- skipping automatic admin setup. Reinstall the MSI, then use the tray icon's Admin Setup menu."
        Set-Status "Domain bootstrapped. Admin setup skipped (dds-enroll-user.exe missing)." '#D13438'
        Finish-NewDomainWizard
        return
    }
    $script:adminSetupLog = Join-Path $env:TEMP ("dds-admin-setup-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:adminSetupPos = 0
    $script:adminSetupOk  = $false
    Set-Status "Bootstrap complete. Registering the first admin - touch your FIDO2 key when prompted..." '#0078d4'
    Append-Log $el.TbLog "[Console] Launching admin setup ($EnrollUserBin --admin-setup)..."
    try {
        $script:adminSetupProc = Start-Process -FilePath $EnrollUserBin -ArgumentList '--admin-setup' `
            -RedirectStandardOutput $script:adminSetupLog -NoNewWindow -PassThru
        # See Start-AuthorizeMachine: retain .Handle so ExitCode reads back
        # on Windows PowerShell 5.1 after the child exits.
        try { $null = $script:adminSetupProc.Handle } catch { }
    } catch {
        Append-Log $el.TbLog "[Console] Could not start admin setup: $($_.Exception.Message)"
        Set-Status "Domain bootstrapped, but admin setup failed to start - retry from the tray icon." '#D13438'
        Finish-NewDomainWizard
        return
    }
    $script:adminSetupTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:adminSetupTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:adminSetupTimer.Add_Tick({ Tick-AdminSetupWait })
    $script:adminSetupTimer.Start()
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

    Stop-AdminSetupWait
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
        # Guard on the timer still existing: a second tick can be queued on a
        # busy UI thread before the first nulls the timer; without this the
        # re-entrant tick calls .Stop() on $null and the exception bubbles up
        # through ShowDialog() as a spurious post-success crash.
        if ($script:joinTimer -and $script:joinProcess.HasExited) {
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
    # Guard on the timer still existing so a re-entrant tick queued before the
    # first nulls it can't call .Stop() on $null (the post-success crash).
    if ($script:deviceEnrollTimer -and $script:deviceEnrollProcess -and $script:deviceEnrollProcess.HasExited) {
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
        $el.TbEnrollExplain.Text = "This registers a security key for the Windows account you are signed in as right now -- $u -- and the new DDS user will be named after it. IMPORTANT: only the owner of '$u' should register their key here. Setting up a different person? Do NOT enroll them from this account -- their DDS user would be named '$u' and their key would unlock this account. Instead, have them sign in to their own Windows account and run this there. (An admin 'enroll a new person by name' flow is planned.)"
    } catch {
        $el.TbEnrollExplain.Text = "This registers a security key for the Windows account you are signed in as right now, and the new DDS user will be named after it. Only the account's own owner should register their key here."
    }
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

    # Cache the process handle NOW, while the child is alive. A Start-Process
    # -PassThru object created WITH output redirection does not retain a
    # process handle on Windows PowerShell 5.1, so a later $proc.ExitCode read
    # returns $null -- which would defeat the exit-code gate in Tick-EnrollUser
    # and misreport a successful enrollment as a failure. Touching .Handle
    # forces the handle to be held so ExitCode is populated after exit.
    try { $null = $script:enrollProcess.Handle } catch { }

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
    # Guard on the timer still existing so a re-entrant tick queued before the
    # first nulls it can't call .Stop() on $null (the post-success crash).
    if ($script:enrollTimer -and $script:enrollProcess -and $script:enrollProcess.HasExited) {
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
$el.TileUsersPolicy.add_MouseLeftButtonUp({ Show-Page -Name 'PagePolicy' })
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

# ── Users & Policy page ───────────────────────────────────────────
$script:pubGrantCmd       = ''
$script:pubNodeUrn        = ''
$script:policyUsersLoaded = $false
$script:pubInitTried      = $false

function Get-ComboText {
    param($Cb)
    if ($Cb -and $Cb.SelectedItem) { return [string]$Cb.SelectedItem.Content }
    return ''
}

# Run the `dds` CLI, capturing stdout/stderr and the exit code without
# tripping $ErrorActionPreference='Stop' (native stderr via `2>&1` would).
function Invoke-DdsCli {
    param([string[]]$DdsArgs)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = $DdsBin
    $psi.Arguments = (($DdsArgs | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' ')
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    # Drain stdout asynchronously while reading stderr, so a child that fills
    # one pipe buffer can't deadlock against the parent reading the other.
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $out = $outTask.GetAwaiter().GetResult()
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $out; Err = $err }
}

function Refresh-PublisherStatus {
    $amber  = [Windows.Media.BrushConverter]::new().ConvertFromString('#FFF4CE')
    $amberB = [Windows.Media.BrushConverter]::new().ConvertFromString('#E0C36B')
    $green  = [Windows.Media.BrushConverter]::new().ConvertFromString('#DFF6DD')
    $greenB = [Windows.Media.BrushConverter]::new().ConvertFromString('#6BB700')
    try {
        $body = Invoke-DdsNodeGet -Path '/v1/policy/publisher-status?platform=windows'
        $st = $body | ConvertFrom-Json
        # Invoke-DdsNodeGet returns the body without inspecting the HTTP
        # status. An admin-gate 403 yields a valid JSON error body
        # ({"error":"not_authorized"}) with no can_publish field — detect it
        # by shape so we don't mislabel a permission problem as "no capability".
        $props = @($st.PSObject.Properties.Name)
        if ($props -notcontains 'can_publish') {
            $el.PubBanner.Background  = $amber
            $el.PubBanner.BorderBrush = $amberB
            $why = if ($props -contains 'error') { [string]$st.error } else { 'unexpected response' }
            $el.TbPubStatus.Text = "Could not read publish authorization ($why). This console may not be running as a DDS admin; publishing is unavailable until it is."
            $el.BtnPubCopyGrant.Visibility = 'Collapsed'
            $el.BtnPubAuthorize.Visibility = 'Collapsed'
            return
        }
        if ($st.can_publish) {
            $el.PubBanner.Background  = $green
            $el.PubBanner.BorderBrush = $greenB
            $el.TbPubStatus.Text = "This node is authorized to publish policy. New accounts and policies replicate to peers within ~60 seconds."
            $el.BtnPubCopyGrant.Visibility = 'Collapsed'
            $el.BtnPubAuthorize.Visibility = 'Collapsed'
            $script:pubGrantCmd = ''
        } else {
            $el.PubBanner.Background  = $amber
            $el.PubBanner.BorderBrush = $amberB
            $script:pubNodeUrn  = [string]$st.node_urn
            $script:pubGrantCmd = [string]$st.grant_command
            # One-time: publish this node's identity so a future admin
            # approval can bind to it (admin_vouch needs a live attestation).
            if (-not $script:pubInitTried) {
                $script:pubInitTried = $true
                try { $null = Invoke-DdsCli @('--node-url', $NodeUrl, 'policy', 'publisher-init') } catch { }
            }
            $el.TbPubStatus.Text = "This machine is not yet authorized to publish policy to the domain. If the DDS admin key is on THIS PC, click 'Authorize this machine' and touch it (one-time). Otherwise, copy this machine's ID and have an admin authorize it from their PC."
            $el.BtnPubCopyGrant.Visibility = 'Visible'
            $el.BtnPubAuthorize.Visibility = 'Visible'
        }
    } catch {
        $el.PubBanner.Background  = $amber
        $el.PubBanner.BorderBrush = $amberB
        $el.TbPubStatus.Text = "Could not reach the DDS node to check publish authorization. Is the DdsNode service running?  ($($_.Exception.Message))"
        $el.BtnPubCopyGrant.Visibility = 'Collapsed'
        $el.BtnPubAuthorize.Visibility = 'Collapsed'
    }
}

function Load-EnrolledUsers {
    try {
        # /v1/enrolled-users requires a device_urn query param; the node
        # ignores its value for the list, so an empty one satisfies the
        # extractor (omitting it returns a plaintext 400, not JSON).
        $body = Invoke-DdsNodeGet -Path '/v1/enrolled-users?device_urn='
        $data = $body | ConvertFrom-Json
        $el.CbClaimSubject.Items.Clear()
        $count = 0
        if ($data -and $data.users) {
            foreach ($u in $data.users) {
                $suffix = if ($u.vouched) { '' } else { '  (not yet approved)' }
                $item = New-Object Windows.Controls.ComboBoxItem
                $item.Content = "$($u.display_name)  -  $($u.subject_urn)$suffix"
                $item.Tag     = [pscustomobject]@{ Urn = [string]$u.subject_urn; Vouched = [bool]$u.vouched; Display = [string]$u.display_name }
                [void]$el.CbClaimSubject.Items.Add($item)
                $count++
            }
        }
        Append-Log $el.TbPolicyLog "[users] loaded $count enrolled user(s)"
        return $true
    } catch {
        Append-Log $el.TbPolicyLog "[users] could not load enrolled users: $($_.Exception.Message)"
        return $false
    }
}

function Enter-PolicyPage {
    Refresh-PublisherStatus
    # Load the user list once, but only latch the flag on a successful load
    # so a failure (e.g. node still starting) retries on the next entry.
    if (-not $script:policyUsersLoaded) {
        if (Load-EnrolledUsers) { $script:policyUsersLoaded = $true }
    }
}

# Build a WindowsPolicyDocument JSON for a first-account claim.
function New-ClaimPolicyJson {
    param(
        [string]$Username, [string]$Subject, [string]$FullName,
        [string[]]$Groups, [string]$DeviceUrn, [bool]$PwNeverExpires
    )
    $acct = [ordered]@{
        username          = $Username
        action            = 'Create'
        claim_subject_urn = $Subject
    }
    if ($FullName)                  { $acct.full_name = $FullName }
    if ($Groups -and $Groups.Count) { $acct.groups = @($Groups) }
    if ($PwNeverExpires)            { $acct.password_never_expires = $true }

    $scope = [ordered]@{}
    if ($DeviceUrn) { $scope.identity_urns = @($DeviceUrn) }

    $doc = [ordered]@{
        policy_id    = "windows/claim/$Username"
        display_name = "New account: $Username"
        version      = 1
        scope        = $scope
        settings     = @()
        enforcement  = 'Enforce'
        windows      = [ordered]@{ local_accounts = @($acct) }
    }
    return ($doc | ConvertTo-Json -Depth 12)
}

# Write the document to a temp file (UTF-8, no BOM — the CLI's JSON
# parser does not skip a BOM) and publish via the `dds` CLI.
function Publish-Policy {
    param([string]$Platform, [string]$Json)
    if (-not (Test-Path $DdsBin)) {
        Append-Log $el.TbPolicyLog "[publish] dds.exe not found at $DdsBin — reinstall the MSI."
        return
    }
    $sub = switch ($Platform) {
        'windows' { 'publish-windows' }
        'macos'   { 'publish-macos' }
        'linux'   { 'publish-linux' }
        default   { 'publish-windows' }
    }
    $tmp = Join-Path $env:TEMP ("dds-policy-{0:yyyyMMdd-HHmmss-fff}.json" -f (Get-Date))
    try {
        [System.IO.File]::WriteAllText($tmp, $Json, (New-Object System.Text.UTF8Encoding($false)))
        Append-Log $el.TbPolicyLog "[publish] $Platform policy..."
        $r = Invoke-DdsCli @('--node-url', $NodeUrl, 'policy', $sub, '--from-file', $tmp)
        foreach ($line in ($r.Out -split "`r?`n")) { if ($line.Trim()) { Append-Log $el.TbPolicyLog $line } }
        foreach ($line in ($r.Err -split "`r?`n")) { if ($line.Trim()) { Append-Log $el.TbPolicyLog $line } }
        if ($r.ExitCode -eq 0) {
            Append-Log $el.TbPolicyLog "[publish] OK — peers replicate within ~60 seconds."
            Refresh-PublisherStatus
        } else {
            Append-Log $el.TbPolicyLog "[publish] FAILED (exit $($r.ExitCode))"
        }
    } catch {
        Append-Log $el.TbPolicyLog "[publish] error: $($_.Exception.Message)"
    } finally {
        if (Test-Path $tmp) { Remove-Item -Force -ErrorAction SilentlyContinue $tmp }
    }
}

function Set-PolicyTemplate {
    param([string]$Name)
    $tpl = switch ($Name) {
        'Registry value' { @'
{
  "policy_id": "security/example-registry",
  "display_name": "Example registry value",
  "version": 1,
  "scope": {},
  "settings": [],
  "enforcement": "Enforce",
  "windows": {
    "registry": [
      { "hive": "LocalMachine", "key": "SOFTWARE\\Policies\\DDS\\Example", "name": "Enabled", "value": { "Dword": 1 }, "action": "Set" }
    ]
  }
}
'@ }
        'Service config' { @'
{
  "policy_id": "services/example",
  "display_name": "Example service config",
  "version": 1,
  "scope": {},
  "settings": [],
  "enforcement": "Enforce",
  "windows": {
    "services": [
      { "name": "RemoteRegistry", "start_type": "Disabled", "action": "Stop" }
    ]
  }
}
'@ }
        'Password policy' { @'
{
  "policy_id": "security/password-policy",
  "display_name": "Password policy",
  "version": 1,
  "scope": {},
  "settings": [],
  "enforcement": "Enforce",
  "windows": {
    "password_policy": { "min_length": 12, "max_age_days": 90, "complexity_required": true, "lockout_threshold": 5, "lockout_duration_minutes": 15 }
  }
}
'@ }
        'Local account' { @'
{
  "policy_id": "windows/account/svc-example",
  "display_name": "Local account: svc-example",
  "version": 1,
  "scope": {},
  "settings": [],
  "enforcement": "Enforce",
  "windows": {
    "local_accounts": [
      { "username": "svc-example", "action": "Create", "full_name": "Example Service Account", "groups": ["Users"], "password_never_expires": true }
    ]
  }
}
'@ }
        default { '' }
    }
    $el.TbPolicyJson.Text = $tpl
}

# ---- Enroll a brand-new person by name (bare enroll; works from any account) ----
$script:npProc  = $null
$script:npTimer = $null
$script:npLog   = ''
$script:npPos   = 0
$script:npUrn   = ''

function Start-EnrollNewPerson {
    if ($script:npProc -and -not $script:npProc.HasExited) {
        Append-Log $el.TbPolicyLog "[enroll] a registration is already in progress."
        return
    }
    if (-not (Test-Path $EnrollUserBin)) {
        $el.TbEnrollNpStatus.Text = "dds-enroll-user.exe not found -- reinstall the MSI."
        return
    }
    $user = ([string]$el.TbAcctUser.Text).Trim()
    $full = ([string]$el.TbAcctFullName.Text).Trim()
    if ($user.Length -lt 1 -or $user.Length -gt 20 -or ($user -notmatch '^[A-Za-z0-9._-]+$') -or $user.EndsWith('.')) {
        $el.TbEnrollNpStatus.Text = "Enter a valid Windows username first (1-20 chars: letters, numbers, . - _; no spaces)."
        return
    }
    if (-not $full) {
        $el.TbEnrollNpStatus.Text = "Enter the person's full name first (it becomes the DDS user's name)."
        return
    }
    # Strip double-quotes AND backslashes: the name is placed inside a
    # quoted CLI arg, and a trailing backslash would escape the closing
    # quote (CommandLineToArgvW). Real names contain neither.
    $fullClean = ($full -replace '["\\]','')
    $script:npUrn = ''
    $script:npLog = Join-Path $env:TEMP ("dds-newperson-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:npPos = 0
    $el.TbEnrollNpStatus.Text = "Ask $full to plug in THEIR security key and touch it when the Windows prompt appears..."
    Append-Log $el.TbPolicyLog "[enroll] registering new person '$full' (username $user) -- waiting for their key touch..."
    $argLine = "--new-user --label `"$user`" --display-name `"$fullClean`""
    try {
        $script:npProc = Start-Process -FilePath $EnrollUserBin -ArgumentList $argLine `
            -RedirectStandardOutput $script:npLog -NoNewWindow -PassThru
        # Retain the process handle while the child is alive so $npProc.ExitCode
        # is readable after exit -- a redirected Start-Process -PassThru object
        # drops its handle on Windows PowerShell 5.1 and ExitCode reads $null.
        try { $null = $script:npProc.Handle } catch { }
    } catch {
        $el.TbEnrollNpStatus.Text = "Could not start enrollment: $($_.Exception.Message)"
        return
    }
    Update-AccountSteps   # locks the combo + Approve + Register while the key touch is pending
    $script:npTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:npTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:npTimer.Add_Tick({ Tick-EnrollNewPerson })
    $script:npTimer.Start()
}

# Drain any newly-written NDJSON lines from the new-person enroll log and
# fold them into UI/status state. Factored out of Tick-EnrollNewPerson so the
# exit branch can drain ONE more time after the process has exited (see the
# race note there).
function Read-NpLog {
    if (-not ($script:npLog -and (Test-Path $script:npLog))) { return }
    try {
        $fs = [IO.File]::Open($script:npLog, 'Open', 'Read', 'ReadWrite')
        try {
            $fs.Seek($script:npPos, 'Begin') | Out-Null
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $script:npPos = $fs.Position
                if (-not $line.Trim()) { continue }
                try { $obj = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                switch ($obj.phase) {
                    'touch1_prompt' { $el.TbEnrollNpStatus.Text = "Touch the security key now..." }
                    'key_made'      { $el.TbEnrollNpStatus.Text = "Key registered; posting to dds-node..." }
                    'enroll_posted' { $script:npUrn = [string]$obj.urn; Append-Log $el.TbPolicyLog "[enroll] enrolled: $($obj.urn)" }
                    'error'         { Append-Log $el.TbPolicyLog "[enroll] error: $($obj.message)" }
                }
            }
        } finally { $fs.Close() }
    } catch { }
}

function Tick-EnrollNewPerson {
    Read-NpLog
    # Guard on the timer still existing so a re-entrant tick queued before the
    # first nulls it can't call .Stop() on $null (the post-success crash guard,
    # matching the join/device/enroll ticks).
    if ($script:npTimer -and $script:npProc -and $script:npProc.HasExited) {
        # Race fix: dds-enroll-user.exe flushes its terminal 'enroll_posted' line
        # and exits back-to-back (DdsEnrollUser.cpp emit+flush then return 0), so
        # the process can exit in the window BETWEEN the drain above and this
        # HasExited check -- leaving $npUrn unset and a server-side-successful
        # registration misreported as "did not complete". HasExited guarantees
        # stdout is flushed and closed, so one final drain captures the last line
        # before we judge the outcome.
        Read-NpLog
        $script:npTimer.Stop(); $script:npTimer = $null
        $el.BtnEnrollNewPerson.IsEnabled = $true
        # Success is signalled by the terminal 'enroll_posted' line captured
        # above (the helper emits it iff the server accepted the enrollment and
        # then exits 0 -- see DdsEnrollUser.cpp). Gate on that flag, NOT on
        # ExitCode: a redirected Start-Process -PassThru can read back a $null
        # ExitCode on PS 5.1 (the .Handle touch at launch mitigates it, but the
        # drained flag is the authoritative server-success signal regardless).
        if ($script:npUrn) {
            $el.TbClaimSubject.Text = $script:npUrn
            $script:approvedUrn = ''   # a freshly-registered person still needs approval
            $el.TbEnrollNpStatus.Text = "Registered. Now do step 4: Approve (touch the ADMIN key), then step 5: Create the account."
            Append-Log $el.TbPolicyLog "[enroll] DONE. Next: step 4 Approve '$($el.TbAcctUser.Text)', then step 5 Create."
            Load-EnrolledUsers | Out-Null
            Update-AccountSteps
        } else {
            $code = $script:npProc.ExitCode
            $suffix = if ($null -ne $code) { " (exit $code)" } else { "" }
            $el.TbEnrollNpStatus.Text = "Registration did not complete$suffix. See the Output box."
        }
        Update-AccountSteps   # re-enable the combo/Register/steps now that the ceremony finished
        if ($script:npLog -and (Test-Path $script:npLog)) { Remove-Item -Force -ErrorAction SilentlyContinue $script:npLog }
    }
}

# ---- Authorize THIS machine to publish (admin vouch of the node URN) ----
$script:authProc  = $null
$script:authTimer = $null
$script:authLog   = ''
$script:authPos   = 0
$script:authOk    = $false

function Start-AuthorizeMachine {
    if ($script:authProc -and -not $script:authProc.HasExited) { return }
    if (-not (Test-Path $EnrollUserBin)) {
        $el.TbPubStatus.Text = "dds-enroll-user.exe not found -- reinstall the MSI."
        return
    }
    if (-not $script:pubNodeUrn) {
        Refresh-PublisherStatus
        if (-not $script:pubNodeUrn) { $el.TbPubStatus.Text = "Machine ID not known yet -- click Re-check, then try again."; return }
    }
    $urn = $script:pubNodeUrn
    $purpose = 'dds:policy-publisher-windows'
    $script:authLog = Join-Path $env:TEMP ("dds-authorize-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:authPos = 0
    $script:authOk  = $false
    $el.TbPubStatus.Text = "Touch your admin security key when the Windows prompt appears to authorize this machine..."
    Append-Log $el.TbPolicyLog "[authorize] vouching this machine for $purpose -- waiting for admin key touch..."
    $argLine = "--vouch --subject-urn `"$urn`" --purpose `"$purpose`""
    try {
        $script:authProc = Start-Process -FilePath $EnrollUserBin -ArgumentList $argLine `
            -RedirectStandardOutput $script:authLog -NoNewWindow -PassThru
        # Retain the process handle while the child is alive so $authProc.ExitCode
        # is readable after exit -- a redirected Start-Process -PassThru object
        # drops its handle on Windows PowerShell 5.1 and ExitCode reads $null.
        try { $null = $script:authProc.Handle } catch { }
    } catch {
        $el.TbPubStatus.Text = "Could not start authorization: $($_.Exception.Message)"
        return
    }
    $el.BtnPubAuthorize.IsEnabled = $false
    $script:authTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:authTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:authTimer.Add_Tick({ Tick-AuthorizeMachine })
    $script:authTimer.Start()
}

# Drain any newly-written NDJSON lines from the authorize log and fold them
# into UI/status state. Factored out so the exit branch can drain ONE more
# time after the process has exited (see the race note in Tick-AuthorizeMachine).
function Read-AuthLog {
    if (-not ($script:authLog -and (Test-Path $script:authLog))) { return }
    try {
        $fs = [IO.File]::Open($script:authLog, 'Open', 'Read', 'ReadWrite')
        try {
            $fs.Seek($script:authPos, 'Begin') | Out-Null
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $script:authPos = $fs.Position
                if (-not $line.Trim()) { continue }
                try { $obj = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                switch ($obj.phase) {
                    'touch_prompt' { $el.TbPubStatus.Text = "Touch your admin security key now..." }
                    'asserted'     { $el.TbPubStatus.Text = "Admin key verified; submitting authorization..." }
                    'vouched'      { $script:authOk = $true; Append-Log $el.TbPolicyLog "[authorize] vouched by $($obj.admin_urn)" }
                    'error'        { Append-Log $el.TbPolicyLog "[authorize] error: $($obj.message)"; $el.TbPubStatus.Text = "Authorization failed: $($obj.message)" }
                }
            }
        } finally { $fs.Close() }
    } catch { }
}

function Tick-AuthorizeMachine {
    Read-AuthLog
    if ($script:authTimer -and $script:authProc -and $script:authProc.HasExited) {
        # Race fix: dds-enroll-user.exe flushes its terminal 'vouched' line and
        # exits back-to-back (DdsEnrollUser.cpp emit+flush then return 0), so the
        # process can exit in the window BETWEEN the drain above and this
        # HasExited check -- leaving $authOk false and a server-side-successful
        # vouch misreported as "did not complete". HasExited guarantees stdout is
        # flushed and closed, so one final drain captures the last line before we
        # judge the outcome.
        Read-AuthLog
        $script:authTimer.Stop(); $script:authTimer = $null
        $el.BtnPubAuthorize.IsEnabled = $true
        # Success is signalled by the terminal 'vouched' line captured above
        # (emitted iff the server accepted the vouch, then exit 0). Gate on that
        # flag, NOT on ExitCode -- see the note in Tick-EnrollNewPerson.
        if ($script:authOk) {
            Append-Log $el.TbPolicyLog "[authorize] DONE -- this machine can now publish policy."
            Refresh-PublisherStatus
        } elseif (-not ($el.TbPubStatus.Text -match 'failed')) {
            $code = $script:authProc.ExitCode
            $suffix = if ($null -ne $code) { " (exit $code)" } else { "" }
            $el.TbPubStatus.Text = "Authorization did not complete$suffix. See the Output box."
        }
        if ($script:authLog -and (Test-Path $script:authLog)) { Remove-Item -Force -ErrorAction SilentlyContinue $script:authLog }
    }
}

# ---- Approve (admin-vouch) the selected person for dds:session, in-console ----
# Same admin ceremony the tray's "Approve Enrollments" runs, via the generic
# dds-enroll-user.exe --vouch mode (subject = the person's URN, purpose =
# dds:session). Mirrors Start-AuthorizeMachine, including the PS 5.1 .Handle
# quirk fix + post-exit final drain + flag-primary success gate.
$script:apProc      = $null
$script:apTimer     = $null
$script:apLog       = ''
$script:apPos       = 0
$script:apOk        = $false
$script:apVouchJti  = ''   # jti of the approval vouch (for peer replication-confirm)
$script:apSubject   = ''   # subject URN captured at approve LAUNCH (bind success to this)
$script:approvedUrn = ''   # URN approved (or known-approved) for the current subject

# Enable/lock the numbered account steps from the current state: Approve unlocks
# once there is a subject; Create unlocks once that subject has been approved.
function Update-AccountSteps {
    $subj = ([string]$el.TbClaimSubject.Text).Trim()
    $user = ([string]$el.TbAcctUser.Text).Trim()
    $busy = (($script:apProc -and -not $script:apProc.HasExited) -or ($script:npProc -and -not $script:npProc.HasExited))
    # While a register/approve ceremony is in flight, lock everything that could
    # change the subject mid-touch -- otherwise a combo switch or a second
    # Register could approve/create the WRONG person (the touch is asynchronous).
    if ($el.BtnEnrollNewPerson)  { $el.BtnEnrollNewPerson.IsEnabled  = (-not $busy) }
    if ($el.CbClaimSubject)      { $el.CbClaimSubject.IsEnabled      = (-not $busy) }
    if ($el.BtnLoadUsers)        { $el.BtnLoadUsers.IsEnabled        = (-not $busy) }
    if ($el.BtnApproveNewPerson) { $el.BtnApproveNewPerson.IsEnabled = ($subj.Length -gt 0) -and (-not $busy) }
    # Create needs an approved subject AND a Windows username (the local account
    # name). Picking an already-enrolled DDS user fills only the URN, so require
    # the username here rather than failing with "username required" on click.
    if ($el.BtnCreateAccount)    { $el.BtnCreateAccount.IsEnabled    = ($subj.Length -gt 0) -and ($user.Length -gt 0) -and ($script:approvedUrn -eq $subj) -and (-not $busy) }
}

function Read-ApLog {
    if (-not ($script:apLog -and (Test-Path $script:apLog))) { return }
    try {
        $fs = [IO.File]::Open($script:apLog, 'Open', 'Read', 'ReadWrite')
        try {
            $fs.Seek($script:apPos, 'Begin') | Out-Null
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $script:apPos = $fs.Position
                if (-not $line.Trim()) { continue }
                try { $obj = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                switch ($obj.phase) {
                    'touch_prompt' { $el.TbApproveNpStatus.Text = "Touch the ADMIN security key now..." }
                    'asserted'     { $el.TbApproveNpStatus.Text = "Admin key verified; submitting approval..." }
                    'vouched'      { $script:apOk = $true; $script:apVouchJti = [string]$obj.jti; Append-Log $el.TbPolicyLog "[approve] approved by $($obj.admin_urn)" }
                    'error'        { Append-Log $el.TbPolicyLog "[approve] error: $($obj.message)"; $el.TbApproveNpStatus.Text = "Approval failed: $($obj.message)" }
                }
            }
        } finally { $fs.Close() }
    } catch { }
}

function Start-ApproveNewPerson {
    if ($script:apProc -and -not $script:apProc.HasExited) { return }
    if (-not (Test-Path $EnrollUserBin)) {
        $el.TbApproveNpStatus.Text = "dds-enroll-user.exe not found -- reinstall the MSI."
        return
    }
    $subj = ([string]$el.TbClaimSubject.Text).Trim()
    if ($subj.Length -lt 1) {
        $el.TbApproveNpStatus.Text = "Register the person's key first (step 2), or pick an enrolled person, so there is someone to approve."
        return
    }
    $script:apSubject = $subj   # bind the eventual approval to THIS subject, not the live box
    $purpose = 'dds:session'
    $script:apLog = Join-Path $env:TEMP ("dds-approve-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:apPos = 0
    $script:apOk  = $false
    $el.TbApproveNpStatus.Text = "Touch the ADMIN security key when the Windows prompt appears to approve this person..."
    Append-Log $el.TbPolicyLog "[approve] admin-vouching $subj ($purpose) -- waiting for admin key touch..."
    $argLine = "--vouch --subject-urn `"$subj`" --purpose `"$purpose`""
    try {
        $script:apProc = Start-Process -FilePath $EnrollUserBin -ArgumentList $argLine `
            -RedirectStandardOutput $script:apLog -NoNewWindow -PassThru
        # Retain the process handle while the child is alive so $apProc.ExitCode
        # is readable after exit (redirected Start-Process -PassThru drops it on
        # Windows PowerShell 5.1 and ExitCode reads $null).
        try { $null = $script:apProc.Handle } catch { }
    } catch {
        $el.TbApproveNpStatus.Text = "Could not start approval: $($_.Exception.Message)"
        return
    }
    Update-AccountSteps   # locks Approve + the combo + Register while the touch is pending
    $script:apTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:apTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:apTimer.Add_Tick({ Tick-ApproveNewPerson })
    $script:apTimer.Start()
}

function Tick-ApproveNewPerson {
    Read-ApLog
    if ($script:apTimer -and $script:apProc -and $script:apProc.HasExited) {
        # Final drain after exit: the helper flushes the terminal 'vouched' line
        # then exits back-to-back. Gate on the drained flag, not ExitCode.
        Read-ApLog
        $script:apTimer.Stop(); $script:apTimer = $null
        if ($script:apOk) {
            # Bind to the subject captured at LAUNCH (inputs were locked against
            # change during the touch, but be explicit): the person we vouched.
            $script:approvedUrn = $script:apSubject
            $u = ([string]$el.TbAcctUser.Text).Trim()
            Append-Log $el.TbPolicyLog "[approve] DONE -- $($script:approvedUrn) is approved."
            # Confirm the approval vouch actually replicated to a peer
            # before telling the operator it's done (bulletproofing: the
            # approval must reach the machine the person will sign in on).
            if ($script:apVouchJti) {
                $el.TbApproveNpStatus.Text = "Approved. Confirming replication to peers..."
                $conf = Confirm-Replication -Jtis @($script:apVouchJti)
                Append-Log $el.TbPolicyLog "[approve] $($conf.Message)"
                $el.TbApproveNpStatus.Text = if ($u) { "Approved ($($conf.Message)). Now do step 5: 'Publish -- create this account'." } else { "Approved ($($conf.Message)). Enter a Windows username in step 1, then do step 5 (Create)." }
            } else {
                $el.TbApproveNpStatus.Text = if ($u) { "Approved. Now do step 5: 'Publish -- create this account'." } else { "Approved. Enter a Windows username in step 1, then do step 5 (Create)." }
            }
            Load-EnrolledUsers | Out-Null
        } elseif (-not ($el.TbApproveNpStatus.Text -match 'failed')) {
            $code = $script:apProc.ExitCode
            $suffix = if ($null -ne $code) { " (exit $code)" } else { "" }
            $el.TbApproveNpStatus.Text = "Approval did not complete$suffix. See the Output box."
        }
        Update-AccountSteps
        if ($script:apLog -and (Test-Path $script:apLog)) { Remove-Item -Force -ErrorAction SilentlyContinue $script:apLog }
    }
}

# ── Manage people & admins page ───────────────────────────────────
# All actions here are admin ceremonies (touch the ADMIN key) followed
# by a peer replication-confirm so nothing is reported "done" until it
# has actually propagated (or we've told the operator no peer was online
# to confirm against). Each ceremony writes a journal so a crash mid-
# flow is recoverable on next launch (see Resume-PendingJournals).
$script:mgUsers   = @()   # last-loaded enrolled users (objects)
$script:mgAdmins  = @()   # last-loaded admin roots (objects)
$script:mgProc    = $null # in-flight offboard/admin ceremony process
$script:mgTimer   = $null
$script:mgLog     = ''
$script:mgPos     = 0
$script:mgResult  = $null # parsed 'revoked'/'vouched' body from the ceremony
$script:mgFlow    = ''    # journal flow name of the in-flight ceremony

function Enter-ManagePage {
    Resume-PendingLifecycleJournals
    Load-ManageUsers
    Load-ManageAdmins
}

# Bulletproofing: on entry, detect any lifecycle ceremony that was
# interrupted (the console crashed/closed between the admin touch and
# the confirm/clear). For a journal that reached 'published' we already
# have the token JTIs, so re-run the peer-confirm and clear it. For one
# that only reached 'started', warn the operator that the action may not
# have completed so they can verify (re-running it is safe — offboard is
# idempotent, re-approve is a no-op).
function Resume-PendingLifecycleJournals {
    foreach ($flow in @('offboard','make-admin','remove-admin')) {
        $j = Read-Journal -Flow $flow
        if (-not $j) { continue }
        if ($j.status -eq 'published' -and $j.jtis) {
            Append-Log $el.TbMgLog "[resume] a previous '$flow' completed but wasn't confirmed; re-checking replication..."
            # Single quick probe on the page-open hot path so the UI isn't
            # frozen by the full retry loop (this runs on the dispatcher thread).
            $conf = Confirm-Replication -Jtis @($j.jtis) -Retries 1
            $el.TbMgReplStatus.Text = "Recovered '$flow': $($conf.Message)"
            Append-Log $el.TbMgLog "[resume] $($conf.Message)"
            Clear-Journal -Flow $flow
        } elseif ($j.status -eq 'started') {
            Append-Log $el.TbMgLog "[resume] a previous '$flow' for '$($j.label)' was interrupted before it finished. Verify the person's status below and re-run if needed (it's safe to repeat)."
            Clear-Journal -Flow $flow
        } else {
            Clear-Journal -Flow $flow
        }
    }
}

function Get-SelectedMgUser  { if ($el.LbMgUsers.SelectedIndex -ge 0 -and $el.LbMgUsers.SelectedIndex -lt $script:mgUsers.Count) { return $script:mgUsers[$el.LbMgUsers.SelectedIndex] } return $null }
function Get-SelectedMgAdmin { if ($el.LbMgAdmins.SelectedIndex -ge 0 -and $el.LbMgAdmins.SelectedIndex -lt $script:mgAdmins.Count) { return $script:mgAdmins[$el.LbMgAdmins.SelectedIndex] } return $null }

function Load-ManageUsers {
    try {
        $inc = if ($el.CbMgShowRevoked.IsChecked) { '1' } else { '0' }
        $body = Invoke-DdsNodeGet -Path ("/v1/enrolled-users?device_urn=&include_revoked={0}" -f $inc)
        $data = $body | ConvertFrom-Json
        $script:mgUsers = @()
        $el.LbMgUsers.Items.Clear()
        if ($data -and $data.users) {
            foreach ($u in $data.users) {
                $status = if ($u.revoked) { 'REMOVED' } elseif ($u.vouched) { 'active' } else { 'pending approval' }
                $script:mgUsers += $u
                [void]$el.LbMgUsers.Items.Add(("[{0,-16}] {1}  {2}" -f $status, $u.display_name, $u.subject_urn))
            }
        }
        Append-Log $el.TbMgLog ("[people] loaded {0} user(s)" -f $script:mgUsers.Count)
    } catch {
        Append-Log $el.TbMgLog "[people] load failed: $($_.Exception.Message)"
    }
    Update-ManageButtons
}

function Load-ManageAdmins {
    try {
        $body = Invoke-DdsNodeGet -Path '/v1/admin/roots'
        $data = $body | ConvertFrom-Json
        $script:mgAdmins = @()
        $el.LbMgAdmins.Items.Clear()
        if ($data -and $data.roots) {
            foreach ($r in $data.roots) {
                $tag = if ($r.is_bootstrap) { 'founding admin' } else { 'admin' }
                $nm  = if ($r.display_name) { $r.display_name } else { '(unnamed)' }
                $script:mgAdmins += $r
                [void]$el.LbMgAdmins.Items.Add(("[{0,-14}] {1}  {2}" -f $tag, $nm, $r.urn))
            }
        }
        Append-Log $el.TbMgLog ("[admins] loaded {0} administrator(s)" -f $script:mgAdmins.Count)
    } catch {
        Append-Log $el.TbMgLog "[admins] load failed: $($_.Exception.Message)"
    }
    Update-ManageButtons
}

function Update-ManageButtons {
    $busy = ($script:mgProc -and -not $script:mgProc.HasExited)
    $u = Get-SelectedMgUser
    $a = Get-SelectedMgAdmin
    if ($el.BtnMgOffboard)    { $el.BtnMgOffboard.IsEnabled    = (-not $busy) -and ($null -ne $u) -and (-not $u.revoked) }
    # Promote is only meaningful for an approved (vouched) person who is
    # not already an admin.
    $uIsAdmin = $false
    if ($u) { $uIsAdmin = @($script:mgAdmins | Where-Object { $_.urn -eq $u.subject_urn }).Count -gt 0 }
    if ($el.BtnMgMakeAdmin)   { $el.BtnMgMakeAdmin.IsEnabled   = (-not $busy) -and ($null -ne $u) -and ($u.vouched) -and (-not $u.revoked) -and (-not $uIsAdmin) }
    if ($el.BtnMgRemoveAdmin) { $el.BtnMgRemoveAdmin.IsEnabled = (-not $busy) -and ($null -ne $a) -and (-not $a.is_bootstrap) }
    if ($el.BtnMgRefreshUsers)  { $el.BtnMgRefreshUsers.IsEnabled  = (-not $busy) }
    if ($el.BtnMgRefreshAdmins) { $el.BtnMgRefreshAdmins.IsEnabled = (-not $busy) }
    if ($el.LbMgUsers)  { $el.LbMgUsers.IsEnabled  = (-not $busy) }
    if ($el.LbMgAdmins) { $el.LbMgAdmins.IsEnabled = (-not $busy) }
}

# Run an admin ceremony (offboard = revoke-vouch, promote/remove admin =
# vouch/revoke-vouch with purpose dds:admin) via dds-enroll-user.exe,
# tail its NDJSON, then confirm replication of the resulting token(s).
# $Kind: 'offboard' | 'make-admin' | 'remove-admin'
function Start-ManageCeremony {
    param([string]$Kind, [string]$SubjectUrn, [string]$Label)
    if ($script:mgProc -and -not $script:mgProc.HasExited) { return }
    if (-not (Test-Path $EnrollUserBin)) { Append-Log $el.TbMgLog "dds-enroll-user.exe not found -- reinstall the MSI."; return }
    if (-not $SubjectUrn) { Append-Log $el.TbMgLog "no subject selected."; return }

    $script:mgFlow   = "$Kind"
    $script:mgResult = $null
    $script:mgLog = Join-Path $env:TEMP ("dds-manage-{0:yyyyMMdd-HHmmss-fff}.log" -f (Get-Date))
    $script:mgPos = 0

    # Build the journal up front so a crash after the touch but before
    # confirm is recoverable.
    Write-Journal -Flow $Kind -State @{ status='started'; kind=$Kind; subject_urn=$SubjectUrn; label=$Label }

    switch ($Kind) {
        'offboard'     { $argLine = "--revoke-vouch --subject-urn `"$SubjectUrn`"" ; $verb = 'Removing access for' }
        'make-admin'   { $argLine = "--vouch --subject-urn `"$SubjectUrn`" --purpose `"dds:admin`"" ; $verb = 'Granting admin to' }
        'remove-admin' { $argLine = "--revoke-vouch --subject-urn `"$SubjectUrn`" --purpose `"dds:admin`"" ; $verb = 'Removing admin from' }
        default        { Append-Log $el.TbMgLog "unknown ceremony '$Kind'"; return }
    }
    $el.TbMgReplStatus.Text = "$verb $Label -- touch the ADMIN security key when the Windows prompt appears..."
    Append-Log $el.TbMgLog "[$Kind] $verb $Label ($SubjectUrn) -- waiting for admin key touch..."
    try {
        $script:mgProc = Start-Process -FilePath $EnrollUserBin -ArgumentList $argLine `
            -RedirectStandardOutput $script:mgLog -NoNewWindow -PassThru
        try { $null = $script:mgProc.Handle } catch { }  # PS 5.1 ExitCode quirk
    } catch {
        Append-Log $el.TbMgLog "[$Kind] could not start: $($_.Exception.Message)"
        Clear-Journal -Flow $Kind
        return
    }
    Update-ManageButtons
    $script:mgTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:mgTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:mgTimer.Add_Tick({ Tick-ManageCeremony })
    $script:mgTimer.Start()
}

function Read-MgLog {
    if (-not ($script:mgLog -and (Test-Path $script:mgLog))) { return }
    try {
        $fs = [IO.File]::Open($script:mgLog, 'Open', 'Read', 'ReadWrite')
        try {
            $fs.Seek($script:mgPos, 'Begin') | Out-Null
            $sr = New-Object IO.StreamReader($fs)
            while ($null -ne ($line = $sr.ReadLine())) {
                $script:mgPos = $fs.Position
                if (-not $line.Trim()) { continue }
                try { $obj = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
                switch ($obj.phase) {
                    'touch_prompt' { $el.TbMgReplStatus.Text = "Touch the ADMIN security key now..." }
                    'asserted'     { $el.TbMgReplStatus.Text = "Admin key verified; submitting..." }
                    'vouched'      { $script:mgResult = $obj; Append-Log $el.TbMgLog "[$($script:mgFlow)] server accepted (jti $($obj.jti))" }
                    'revoked'      {
                        # 'body' carries the raw server JSON (revoked[], foreign[], demoted, published).
                        try { $script:mgResult = ($obj.body | ConvertFrom-Json) } catch { $script:mgResult = $null }
                        Append-Log $el.TbMgLog "[$($script:mgFlow)] server accepted revocation"
                    }
                    'error'        { Append-Log $el.TbMgLog "[$($script:mgFlow)] error: $($obj.message)"; $el.TbMgReplStatus.Text = "Failed: $($obj.message)" }
                }
            }
        } finally { $fs.Close() }
    } catch { }
}

function Tick-ManageCeremony {
    Read-MgLog
    if ($script:mgTimer -and $script:mgProc -and $script:mgProc.HasExited) {
        Read-MgLog   # final drain (helper flushes terminal line then exits)
        $script:mgTimer.Stop(); $script:mgTimer = $null
        Complete-ManageCeremony
        Update-ManageButtons
        if ($script:mgLog -and (Test-Path $script:mgLog)) { Remove-Item -Force -ErrorAction SilentlyContinue $script:mgLog }
    }
}

# After the ceremony process exits: judge success from the drained
# result (not ExitCode -- PS 5.1 redirected-PassThru quirk), collect the
# token JTIs to confirm, run the peer replication-confirm, update the
# journal, and refresh the lists.
function Complete-ManageCeremony {
    $flow = $script:mgFlow
    $res  = $script:mgResult
    if (-not $res) {
        $code = if ($script:mgProc) { $script:mgProc.ExitCode } else { $null }
        $suffix = if ($null -ne $code) { " (exit $code)" } else { "" }
        $el.TbMgReplStatus.Text = "Did not complete$suffix. See the Output box."
        Write-Journal -Flow $flow -State @{ status='failed' }
        return
    }

    # Collect the JTIs to confirm on peers.
    $jtis = @()
    $summary = ''
    if ($flow -eq 'offboard' -or $flow -eq 'remove-admin') {
        if ($res.revoked) { $jtis = @($res.revoked | ForEach-Object { $_.revoke_jti }) }
        $foreignCount = if ($res.foreign) { @($res.foreign).Count } else { 0 }
        $summary = ("Revoked {0} grant(s)." -f (@($res.revoked).Count))
        if ($res.demoted_from_trusted_roots) { $summary += " Admin rights removed." }
        if ($foreignCount -gt 0) {
            $summary += (" NOTE: {0} grant(s) were issued by a DIFFERENT admin and must be revoked by THAT admin to fully complete removal." -f $foreignCount)
            foreach ($f in $res.foreign) { Append-Log $el.TbMgLog ("[$flow] still-active grant from other admin {0} (purpose {1})" -f $f.issuer, $f.purpose) }
        }
    } elseif ($flow -eq 'make-admin') {
        if ($res.jti) { $jtis = @($res.jti) }
        $summary = "Admin rights granted."
    }

    Write-Journal -Flow $flow -State @{ status='published'; jtis=$jtis; summary=$summary }

    # Confirm replication against a peer.
    $el.TbMgReplStatus.Text = "$summary  Confirming replication to peers..."
    $conf = Confirm-Replication -Jtis $jtis
    $el.TbMgReplStatus.Text = "$summary  $($conf.Message)"
    Append-Log $el.TbMgLog "[$flow] $($conf.Message)"

    # The change is durably committed locally either way; the journal is
    # cleared once we've reported (peer-confirmed or peer-unavailable),
    # since there is nothing left for a resume to finish.
    Clear-Journal -Flow $flow

    # Refresh so the lists reflect the new state.
    Load-ManageUsers
    Load-ManageAdmins
}

$el.BtnMgRefreshUsers.add_Click({ Load-ManageUsers })
$el.BtnMgRefreshAdmins.add_Click({ Load-ManageAdmins })
$el.CbMgShowRevoked.add_Click({ Load-ManageUsers })
$el.LbMgUsers.add_SelectionChanged({
    $u = Get-SelectedMgUser
    if ($u) {
        $st = if ($u.revoked) { 'Removed (offboarded)' } elseif ($u.vouched) { 'Active' } else { 'Pending approval' }
        $el.TbMgUserDetail.Text = "$($u.display_name)`nStatus: $st`n$($u.subject_urn)"
    } else { $el.TbMgUserDetail.Text = '(pick a person on the left)' }
    Update-ManageButtons
})
$el.LbMgAdmins.add_SelectionChanged({
    $a = Get-SelectedMgAdmin
    if ($a) {
        $nm = if ($a.display_name) { $a.display_name } else { '(unnamed)' }
        $kind = if ($a.is_bootstrap) { 'Founding admin (cannot be removed here)' } else { 'Administrator' }
        $el.TbMgAdminDetail.Text = "$nm`n$kind`n$($a.urn)"
    } else { $el.TbMgAdminDetail.Text = '(pick an admin on the left)' }
    Update-ManageButtons
})
$el.BtnMgOffboard.add_Click({
    $u = Get-SelectedMgUser
    if (-not $u) { return }
    $r = [Windows.MessageBox]::Show(
        "Remove all access for '$($u.display_name)'? Their security-key sign-in stops on new logons across the domain. Windows accounts already created are not deleted. Already-issued sessions remain valid until they expire (up to 24h).",
        "Confirm offboarding", 'YesNo', 'Warning')
    if ($r -ne 'Yes') { return }
    Start-ManageCeremony -Kind 'offboard' -SubjectUrn $u.subject_urn -Label $u.display_name
})
$el.BtnMgMakeAdmin.add_Click({
    $u = Get-SelectedMgUser
    if (-not $u) { return }
    $r = [Windows.MessageBox]::Show(
        "Make '$($u.display_name)' a domain administrator? They will be able to approve, offboard, and publish policy.",
        "Confirm add admin", 'YesNo', 'Question')
    if ($r -ne 'Yes') { return }
    Start-ManageCeremony -Kind 'make-admin' -SubjectUrn $u.subject_urn -Label $u.display_name
})
$el.BtnMgRemoveAdmin.add_Click({
    $a = Get-SelectedMgAdmin
    if (-not $a) { return }
    if ($a.is_bootstrap) { Append-Log $el.TbMgLog "[remove-admin] the founding admin can't be removed here."; return }
    $nm = if ($a.display_name) { $a.display_name } else { $a.urn }
    $r = [Windows.MessageBox]::Show(
        "Remove admin rights from '$nm'? They keep their own sign-in but can no longer approve/offboard others or publish policy. This revokes the dds:admin grant YOU issued; if another admin also granted it, that admin must revoke theirs too.",
        "Confirm remove admin", 'YesNo', 'Warning')
    if ($r -ne 'Yes') { return }
    Start-ManageCeremony -Kind 'remove-admin' -SubjectUrn $a.urn -Label $nm
})

# ── Decommission / leave domain page ──────────────────────────────
function Update-DecomButton {
    $el.BtnDecomRun.IsEnabled = [bool]$el.CbDecomConfirm.IsChecked
}
$el.CbDecomConfirm.add_Click({ Update-DecomButton })
$el.BtnDecomRun.add_Click({
    if (-not $el.CbDecomConfirm.IsChecked) { return }
    $el.BtnDecomRun.IsEnabled = $false
    $el.TbDecomLog.Clear()

    # Optionally revoke this machine's admission first (best-effort;
    # requires the domain key on THIS machine). We record the intent in a
    # journal so a crash between revoke and wipe is visible on next launch.
    Write-Journal -Flow 'decommission' -State @{ status='started'; revoke=[bool]$el.CbDecomRevoke.IsChecked }

    if ($el.CbDecomRevoke.IsChecked) {
        $el.TbDecomStatus.Text = "Revoking this machine's admission..."
        Append-Log $el.TbDecomLog "[decom] attempting: dds-node revoke-admission (needs the domain key on this machine)"
        try {
            $peerId = ''
            try {
                $info = Invoke-DdsNodeGet -Path '/v1/node/info' | ConvertFrom-Json
                $peerId = [string]$info.peer_id
            } catch { }
            $domainKey = Join-Path $NodeData 'domain_key.bin'
            $domainToml = Join-Path $NodeData 'domain.toml'
            if (-not ((Test-Path $domainKey) -and (Test-Path $domainToml) -and $peerId)) {
                Append-Log $el.TbDecomLog "[decom] skipping revocation: domain key not on this machine or peer id unknown. Run 'dds-node revoke-admission' from the machine that holds the domain key."
            } else {
                # dds-node revoke-admission --domain-key <f> --domain <f> --peer-id <id> --out <f>
                $args2 = @('revoke-admission','--domain-key',$domainKey,'--domain',$domainToml,'--peer-id',$peerId,'--out',(Join-Path $NodeData 'self-revocation.cbor'))
                $p = Start-Process -FilePath $NodeBin -ArgumentList $args2 -NoNewWindow -PassThru -Wait
                if ($p.ExitCode -eq 0) {
                    Append-Log $el.TbDecomLog "[decom] admission revoked; importing so it fans out to peers before we stop..."
                    $imp = @('import-revocation','--file',(Join-Path $NodeData 'self-revocation.cbor'))
                    Start-Process -FilePath $NodeBin -ArgumentList $imp -NoNewWindow -PassThru -Wait | Out-Null
                    # Give gossip a moment to fan the revocation out.
                    Start-Sleep -Seconds 2
                } else {
                    Append-Log $el.TbDecomLog "[decom] revoke-admission exited $($p.ExitCode); continuing with local wipe."
                }
            }
        } catch {
            Append-Log $el.TbDecomLog "[decom] revocation step failed: $($_.Exception.Message). Continuing with local wipe."
        }
    }

    # Wipe local provisioning state via the existing Reset script (-Force).
    if (-not (Test-Path $ResetScript)) {
        Append-Log $el.TbDecomLog "[decom] Reset-DdsBootstrap.ps1 not found -- reinstall the MSI."
        $el.TbDecomStatus.Text = "Reset script missing."
        Clear-Journal -Flow 'decommission'
        $el.BtnDecomRun.IsEnabled = $true
        return
    }
    $el.TbDecomStatus.Text = "Wiping DDS state..."
    Append-Log $el.TbDecomLog "[decom] running Reset-DdsBootstrap.ps1 -Force ..."
    try {
        $p = Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$ResetScript`"",'-Force') `
            -NoNewWindow -PassThru -Wait
        if ($p.ExitCode -eq 0) {
            Append-Log $el.TbDecomLog "[decom] DONE. This machine has left the domain. You can now uninstall DDS or join a different domain."
            $el.TbDecomStatus.Text = "Done -- machine left the domain."
        } else {
            Append-Log $el.TbDecomLog "[decom] Reset exited $($p.ExitCode)."
            $el.TbDecomStatus.Text = "Reset failed (exit $($p.ExitCode))."
        }
    } catch {
        Append-Log $el.TbDecomLog "[decom] wipe failed: $($_.Exception.Message)"
        $el.TbDecomStatus.Text = "Wipe failed."
    }
    Clear-Journal -Flow 'decommission'
    $el.BtnDecomRun.IsEnabled = $true
})

$el.BtnUsersPolicy.add_Click({ Show-Page -Name 'PagePolicy' })
$el.BtnManage.add_Click({ Show-Page -Name 'PageManage' })
$el.BtnDecommission.add_Click({ Show-Page -Name 'PageDecommission' })
$el.BtnEnrollNewPerson.add_Click({ Start-EnrollNewPerson })
$el.BtnApproveNewPerson.add_Click({ Start-ApproveNewPerson })
$el.BtnPubAuthorize.add_Click({ Start-AuthorizeMachine })
$el.BtnPubCheck.add_Click({ Refresh-PublisherStatus })
$el.BtnPubCopyGrant.add_Click({
    if ($script:pubNodeUrn) {
        try { [Windows.Clipboard]::SetText($script:pubNodeUrn); Append-Log $el.TbPolicyLog "[authorize] machine ID copied to clipboard" } catch { }
    }
})
$el.BtnLoadUsers.add_Click({ Load-EnrolledUsers })
# Create (step 5) is gated on a Windows username being present, so re-evaluate
# the step buttons whenever the username field changes.
$el.TbAcctUser.add_TextChanged({ Update-AccountSteps })
$el.CbClaimSubject.add_SelectionChanged({
    $sel = $el.CbClaimSubject.SelectedItem
    if ($sel -and $sel.Tag) {
        $info = $sel.Tag
        $el.TbClaimSubject.Text = [string]$info.Urn
        # Prefill the DDS display name (safe, non-identifying). The Windows
        # username (step 1) is a login-name decision, so we do NOT guess it --
        # but we hint when it's missing so Create isn't mysteriously locked.
        if (-not ([string]$el.TbAcctFullName.Text).Trim() -and $info.Display) { $el.TbAcctFullName.Text = [string]$info.Display }
        $needUser = -not ([string]$el.TbAcctUser.Text).Trim()
        if ($info.Vouched) {
            $script:approvedUrn = [string]$info.Urn
            $el.TbApproveNpStatus.Text = if ($needUser) { "Already approved. Enter a Windows username in step 1 to create the account." } else { "Already approved -- go straight to step 5 (Create)." }
        } else {
            $el.TbApproveNpStatus.Text = "Not yet approved -- do step 4 (Approve) first."
        }
        Update-AccountSteps
    }
})
$el.BtnFillTemplate.add_Click({ Set-PolicyTemplate (Get-ComboText $el.CbTemplate) })
$el.BtnPublishJson.add_Click({
    $platform = Get-ComboText $el.CbPlatform
    $json = [string]$el.TbPolicyJson.Text
    if (-not $json.Trim()) { Append-Log $el.TbPolicyLog "[publish] nothing to publish (JSON is empty)"; return }
    try { $null = $json | ConvertFrom-Json } catch { Append-Log $el.TbPolicyLog "[publish] invalid JSON: $($_.Exception.Message)"; return }
    Publish-Policy -Platform $platform -Json $json
})
$el.BtnCreateAccount.add_Click({
    $user    = ([string]$el.TbAcctUser.Text).Trim()
    $subject = ([string]$el.TbClaimSubject.Text).Trim()
    if (-not $user)    { Append-Log $el.TbPolicyLog "[account] Windows username is required"; return }
    if (-not $subject) { Append-Log $el.TbPolicyLog "[account] a DDS user (subject URN) is required — pick one or paste a URN"; return }
    if ($user.Length -gt 20 -or ($user -notmatch '^[A-Za-z0-9._-]+$') -or $user.EndsWith('.')) {
        Append-Log $el.TbPolicyLog "[account] invalid username: 1-20 chars, letters/digits/._- only, not ending in a dot"
        return
    }
    $full = ([string]$el.TbAcctFullName.Text).Trim()
    $groups = @()
    $rawGroups = ([string]$el.TbAcctGroups.Text).Trim()
    if ($rawGroups) { $groups = @($rawGroups -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    # Mirror the applier's AccountEnforcer.IsValidGroupName so an invalid
    # group is caught here rather than silently failing the whole directive
    # on every endpoint.
    $badGroup = $groups | Where-Object {
        $_.Length -gt 256 -or $_.EndsWith('.') -or $_.EndsWith(' ') -or
        ($_ -match '["/\\\[\]:;|=,+*?<>@]') -or ($_ -match '[\x00-\x1f]')
    } | Select-Object -First 1
    if ($badGroup) {
        Append-Log $el.TbPolicyLog "[account] invalid group name '$badGroup' — avoid these characters: / \ [ ] : ; | = , + * ? < > @ and double-quotes; max 256 chars, no trailing dot/space"
        return
    }
    $deviceUrn = ''
    if ($el.RbAcctDevice.IsChecked) {
        $deviceUrn = ([string]$el.TbAcctDeviceUrn.Text).Trim()
        if (-not $deviceUrn) { Append-Log $el.TbPolicyLog "[account] enter a device URN or choose 'All devices'"; return }
    }
    $pwNever = [bool]$el.CbAcctPwNever.IsChecked
    $json = New-ClaimPolicyJson -Username $user -Subject $subject -FullName $full -Groups $groups -DeviceUrn $deviceUrn -PwNeverExpires $pwNever
    Append-Log $el.TbPolicyLog "[account] publishing first-logon claim: '$user' -> $subject"
    Publish-Policy -Platform 'windows' -Json $json
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
    foreach ($t in @($script:bootstrapTimer, $script:adminSetupTimer, $script:joinTimer, $script:deviceEnrollTimer, $script:enrollTimer, $script:enrollPollTimer, $script:npTimer, $script:authTimer, $script:apTimer, $script:mgTimer, $healthTimer)) {
        try { if ($t) { $t.Stop() } } catch { }
    }
    # Don't orphan an in-flight FIDO2 ceremony helper (and its WebAuthn
    # prompt) if the operator closes the window mid-ceremony.
    foreach ($p in @($script:mgProc, $script:apProc, $script:npProc, $script:authProc, $script:adminSetupProc)) {
        try { if ($p -and -not $p.HasExited) { $p.Kill() } } catch { }
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
