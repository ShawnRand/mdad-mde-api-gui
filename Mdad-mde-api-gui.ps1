<#
.SYNOPSIS
	Simple PowerShell GUI for Microsoft Defender for Endpoint API machine actions.

.DESCRIPTION
	Sample response tool that benefits from APIs and are using PowerShell as the tool of choice to perform actions in bulk. It doesn't require installation and can easily be adapted by anyone with some scripting experience. The tool currently accepts advanced hunting queries, computer names, and CSVs as device input methods. Once devices are selected, three types of actions can be performed:

	- Tagging devices
	- Performing Quick/Full AV scan, and
	- Performing Isolation/Release from Isolation

	An Azure AD AppID and Secret is required to connect to API and the tool needs the following App Permissions:

	- AdvancedQuery.Read.All
	- Machine.Isolate
	- Machine.ReadWrite.All
	- Machine.Scan

Learn how about Advanced Hunting Queries https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide
Kusto Query Language (KQL) overview https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
DeviceInfo table https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceinfo-table?view=o365-worldwide

All Workstation Devices 
DeviceInfo
| where DeviceType == "Workstation"
| distinct DeviceName, DeviceId

All Windows Server 2012R2 & 2008R2

DeviceInfo
| where OSPlatform in ("WindowsServer2008R2","WindowsServer2012R2")
| distinct DeviceName, DeviceId

#>


#===========================================================[Classes]===========================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ProcessDPI {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetProcessDPIAware();      
}
'@
$null = [ProcessDPI]::SetProcessDPIAware()


#===========================================================[Variables]===========================================================


$script:selectedmachines = @{}
$credspath = 'c:\temp\mdeuicreds.txt'
$helpQueryBox = "
AH Query: Specify advanced hunting query that will return DeviceId and DeviceName, e.g.: 'DeviceInfo | distinct DeviceId, DeviceName'`r`n
Computer Name(s): Specify one o more FQDN computer names, e.g.: 'computer1.contoso.com, computer2.contoso.com'`r`n
CSV: Specify path to CSV file with computer names, e.g.: 'C:\temp\Computers.csv'"

$UnclickableColour = "#8d8989"
$ClickableColour = "#ff7b00"
$TextBoxFont = 'Microsoft Sans Serif,10'

#===========================================================[WinForm]===========================================================


[System.Windows.Forms.Application]::EnableVisualStyles()


$MainForm = New-Object system.Windows.Forms.Form
$MainForm.SuspendLayout()
$MainForm.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
$MainForm.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$MainForm.ClientSize = '950,800'
$MainForm.text = "Microsoft MDAD Tagging GUI"
$MainForm.BackColor = "#ffffff"
$MainForm.TopMost = $false

$iconBase64      = "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"
$iconBytes       = [Convert]::FromBase64String($iconBase64)
# initialize a Memory stream holding the bytes
$stream          = [System.IO.MemoryStream]::new($iconBytes, 0, $iconBytes.Length)
$MainForm.Icon       = [System.Drawing.Icon]::FromHandle(([System.Drawing.Bitmap]::new($stream).GetHIcon()))

#add an image to the form using Base64
$base64ImageString = "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"
$imageBytes = [Convert]::FromBase64String($base64ImageString)
$ms = New-Object IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
$ms.Write($imageBytes, 0, $imageBytes.Length);
$logo = [System.Drawing.Image]::FromStream($ms, $true)

$pictureBox = new-object Windows.Forms.PictureBox
$pictureBox.Width =  $logo.Size.Width = 150;
$pictureBox.Height =  $logo.Size.Height = 145; 
$pictureBox.Location = New-Object System.Drawing.Size(750, 145) 
$pictureBox.Image = $logo;
#$Mainform.Controls.Add($pictureBox)

$Branding = New-Object system.Windows.Forms.Label
$Branding.text = "Microsoft Defender Advanced Dashboards"
$Branding.AutoSize = $true
$Branding.width = 125
$Branding.height = 80
$Branding.location = New-Object System.Drawing.Point(80, 195)
$Branding.Font = 'Microsoft Sans Serif,25,style=Bold'

$Title = New-Object system.Windows.Forms.Label
$Title.text = "1 - Connect with MDE API Credentials"
$Title.AutoSize = $true
$Title.width = 25
$Title.height = 10
$Title.location = New-Object System.Drawing.Point(20, 20)
$Title.Font = 'Microsoft Sans Serif,12,style=Bold'

$AppIdBoxLabel = New-Object system.Windows.Forms.Label
$AppIdBoxLabel.text = "App Id:"
$AppIdBoxLabel.AutoSize = $true
$AppIdBoxLabel.width = 25
$AppIdBoxLabel.height = 10
$AppIdBoxLabel.location = New-Object System.Drawing.Point(20, 50)
$AppIdBoxLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$AppIdBox = New-Object system.Windows.Forms.TextBox
$AppIdBox.multiline = $false
$AppIdBox.width = 314
$AppIdBox.height = 20
$AppIdBox.location = New-Object System.Drawing.Point(100, 50)
$AppIdBox.Font = $TextBoxFont
$AppIdBox.Visible = $true

$AppSecretBoxLabel = New-Object system.Windows.Forms.Label
$AppSecretBoxLabel.text = "App Secret:"
$AppSecretBoxLabel.AutoSize = $true
$AppSecretBoxLabel.width = 25
$AppSecretBoxLabel.height = 10
$AppSecretBoxLabel.location = New-Object System.Drawing.Point(20, 75)
$AppSecretBoxLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$AppSecretBox = New-Object system.Windows.Forms.TextBox
$AppSecretBox.multiline = $false
$AppSecretBox.width = 314
$AppSecretBox.height = 20
$AppSecretBox.location = New-Object System.Drawing.Point(100, 75)
$AppSecretBox.Font = $TextBoxFont
$AppSecretBox.Visible = $true
$AppSecretBox.PasswordChar = '*'

$TenantIdBoxLabel = New-Object system.Windows.Forms.Label
$TenantIdBoxLabel.text = "Tenant Id:"
$TenantIdBoxLabel.AutoSize = $true
$TenantIdBoxLabel.width = 25
$TenantIdBoxLabel.height = 10
$TenantIdBoxLabel.location = New-Object System.Drawing.Point(20, 100)
$TenantIdBoxLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$TenantIdBox = New-Object system.Windows.Forms.TextBox
$TenantIdBox.multiline = $false
$TenantIdBox.width = 314
$TenantIdBox.height = 20
$TenantIdBox.location = New-Object System.Drawing.Point(100, 100)
$TenantIdBox.Font = $TextBoxFont
$TenantIdBox.Visible = $true

$ConnectionStatusLabel = New-Object system.Windows.Forms.Label
$ConnectionStatusLabel.text = "Status:"
$ConnectionStatusLabel.AutoSize = $true
$ConnectionStatusLabel.width = 25
$ConnectionStatusLabel.height = 10
$ConnectionStatusLabel.location = New-Object System.Drawing.Point(20, 135)
$ConnectionStatusLabel.Font = 'Microsoft Sans Serif,10,style=Bold'

$ConnectionStatus = New-Object system.Windows.Forms.Label
$ConnectionStatus.text = "Not Connected"
$ConnectionStatus.AutoSize = $true
$ConnectionStatus.width = 25
$ConnectionStatus.height = 10
$ConnectionStatus.location = New-Object System.Drawing.Point(100, 135)
$ConnectionStatus.Font = 'Microsoft Sans Serif,10'

$SaveCredCheckbox = new-object System.Windows.Forms.checkbox
$SaveCredCheckbox.Location = New-Object System.Drawing.Point(200, 135)
$SaveCredCheckbox.AutoSize = $true
$SaveCredCheckbox.width = 60
$SaveCredCheckbox.height = 10
$SaveCredCheckbox.Text = "Save Credentials"
$SaveCredCheckbox.Font = 'Microsoft Sans Serif,10'
$SaveCredCheckbox.Checked = $false

$ConnectBtn = New-Object system.Windows.Forms.Button
$ConnectBtn.BackColor = "#ff7b00"
$ConnectBtn.text = "Connect"
$ConnectBtn.width = 90
$ConnectBtn.height = 30
$ConnectBtn.location = New-Object System.Drawing.Point(325, 130)
$ConnectBtn.Font = 'Microsoft Sans Serif,10'
$ConnectBtn.ForeColor = "#ffffff"
$ConnectBtn.Visible = $True

$TitleActions = New-Object system.Windows.Forms.Label
$TitleActions.text = "3 - Tag selected devices"
$TitleActions.AutoSize = $true
$TitleActions.width = 25
$TitleActions.height = 10
$TitleActions.location = New-Object System.Drawing.Point(500, 20)
$TitleActions.Font = 'Microsoft Sans Serif,12,style=Bold'

$TagDeviceGroupBox = New-Object System.Windows.Forms.GroupBox
$TagDeviceGroupBox.Location = New-Object System.Drawing.Point(500,40)
$TagDeviceGroupBox.width = 400
$TagDeviceGroupBox.height = 100
$TagDeviceGroupBox.Text = "Device tag"
$TagDeviceGroupBox.Font = 'Microsoft Sans Serif,10,style=Bold'

$DeviceTag = New-Object system.Windows.Forms.TextBox
$Devicetag.multiline = $false
$DeviceTag.width = 200
$DeviceTag.height = 25
$DeviceTag.location = New-Object System.Drawing.Point(20, 20)
$Devicetag.Font = 'Microsoft Sans Serif,10'
$DeviceTag.Visible = $true
$Devicetag.Enabled = $false

$TagDeviceBtn = New-Object system.Windows.Forms.Button
$TagDeviceBtn.BackColor = $UnclickableColour
$TagDeviceBtn.text = "Apply Tag"
$TagDeviceBtn.width = 110
$TagDeviceBtn.height = 30
$TagDeviceBtn.location = New-Object System.Drawing.Point(280, 15)
$TagDeviceBtn.Font = 'Microsoft Sans Serif,10'
$TagDeviceBtn.ForeColor = "#ffffff"
$TagDeviceBtn.Visible = $true

$RMTagDeviceBtn = New-Object system.Windows.Forms.Button
$RMTagDeviceBtn.BackColor = $UnclickableColour
$RMTagDeviceBtn.text = "Remove Tag"
$RMTagDeviceBtn.width = 110
$RMTagDeviceBtn.height = 30
$RMTagDeviceBtn.location = New-Object System.Drawing.Point(280, 45)
$RMTagDeviceBtn.Font = 'Microsoft Sans Serif,10'
$RmTagDeviceBtn.ForeColor = "#ffffff"
$RmTagDeviceBtn.Visible = $true

$TagDeviceGroupBox.Controls.AddRange(@($DeviceTag, $TagDeviceBtn, $RMTagDeviceBtn ))

<#$ScanGroupBox = New-Object System.Windows.Forms.GroupBox
$ScanGroupBox.Location = New-Object System.Drawing.Point(500,105)
$ScanGroupBox.width = 400
$ScanGroupBox.height = 50
$ScanGroupBox.Text = "Scan mode"
$ScanGroupBox.Font = 'Microsoft Sans Serif,10,style=Bold'

$ScanRadioButton1 = New-Object System.Windows.Forms.RadioButton
$ScanRadioButton1.Width = 80
$ScanRadioButton1.Height = 20
$ScanRadioButton1.location = New-Object System.Drawing.Point(20, 20)
$ScanRadioButton1.Checked = $false
$ScanRadioButton1.Enabled = $false
$ScanRadioButton1.Text = "Full Scan"
$ScanRadioButton1.Font = 'Microsoft Sans Serif,8'
 
$ScanRadioButton2 = New-Object System.Windows.Forms.RadioButton
$ScanRadioButton2.Width = 80
$ScanRadioButton2.Height = 20
$ScanRadioButton2.location = New-Object System.Drawing.Point(120, 20)
$ScanRadioButton2.Checked = $true
$ScanRadioButton2.Enabled = $false
$ScanRadioButton2.Text = "Quick Scan"
$ScanRadioButton2.Font = 'Microsoft Sans Serif,8'

$ScanDeviceBtn = New-Object system.Windows.Forms.Button
$ScanDeviceBtn.BackColor = $UnclickableColour
$ScanDeviceBtn.text = "AV Scan"
$ScanDeviceBtn.width = 110
$ScanDeviceBtn.height = 30
$ScanDeviceBtn.location = New-Object System.Drawing.Point(280, 15)
$ScanDeviceBtn.Font = 'Microsoft Sans Serif,10'
$ScanDeviceBtn.ForeColor = "#ffffff"
$ScanDeviceBtn.Visible = $true

$ScanGroupBox.Controls.AddRange(@($ScanRadioButton1, $ScanRadioButton2, $ScanDeviceBtn))

$IsolateGroupBox = New-Object System.Windows.Forms.GroupBox
$IsolateGroupBox.Location = '500,165'
$IsolateGroupBox.Width = 400
$IsolateGroupBox.height = 90
$IsolateGroupBox.text = "Isolation"
$IsolateGroupBox.Font = 'Microsoft Sans Serif,10,style=Bold'

$IsolateRadioButton1 = New-Object System.Windows.Forms.RadioButton
$IsolateRadioButton1.width = 60
$IsolateRadioButton1.height = 20
$IsolateRadioButton1.location = New-Object System.Drawing.Point(20, 20)
$IsolateRadioButton1.Checked = $false
$IsolateRadioButton1.Enabled = $false
$IsolateRadioButton1.Text = "Full"
$IsolateRadioButton1.Font = 'Microsoft Sans Serif,8'
 
$IsolateRadioButton2 = New-Object System.Windows.Forms.RadioButton
$IsolateRadioButton2.width = 120
$IsolateRadioButton2.height = 20
$IsolateRadioButton2.location = New-Object System.Drawing.Point(120, 20)
$IsolateRadioButton2.Checked = $true
$IsolateRadioButton2.Enabled = $false
$IsolateRadioButton2.Text = "Selective"
$IsolateRadioButton2.Font = 'Microsoft Sans Serif,8'

$IsolateDeviceBtn = New-Object system.Windows.Forms.Button
$IsolateDeviceBtn.BackColor = $UnclickableColour
$IsolateDeviceBtn.text = "Isolate Device"
$IsolateDeviceBtn.width = 110
$IsolateDeviceBtn.height = 30
$IsolateDeviceBtn.location = New-Object System.Drawing.Point(280, 15)
$IsolateDeviceBtn.Font = 'Microsoft Sans Serif,10'
$IsolateDeviceBtn.ForeColor = "#ffffff"
$IsolateDeviceBtn.Visible = $true

$ReleaseFromIsolationBtn = New-Object system.Windows.Forms.Button
$ReleaseFromIsolationBtn.BackColor = $UnclickableColour
$ReleaseFromIsolationBtn.text = "Release Device"
$ReleaseFromIsolationBtn.width = 110
$ReleaseFromIsolationBtn.height = 30
$ReleaseFromIsolationBtn.location = New-Object System.Drawing.Point(280, 50)
$ReleaseFromIsolationBtn.Font = 'Microsoft Sans Serif,10'
$ReleaseFromIsolationBtn.ForeColor = "#ffffff"
$ReleaseFromIsolationBtn.Visible = $true

$IsolateGroupBox.Controls.AddRange(@($IsolateRadioButton1, $IsolateRadioButton2, $IsolateDeviceBtn, $ReleaseFromIsolationBtn))
#>
$InputRadioBox = New-Object System.Windows.Forms.GroupBox
$InputRadioBox.width = 880
$InputRadioBox.height = 240
$InputRadioBox.location = New-Object System.Drawing.Point(20, 290)
$InputRadioBox.text = "2 - Select Devices to Apply or Remove Tag"
$InputRadioBox.Font = 'Microsoft Sans Serif,12,style=Bold'
    
$InputRadioButton1 = New-Object System.Windows.Forms.RadioButton
$InputRadioButton1.width = 90
$InputRadioButton1.height = 20
$InputRadioButton1.location = New-Object System.Drawing.Point(20, 25)
$InputRadioButton1.Checked = $true
$InputRadioButton1.Enabled = $false
$InputRadioButton1.Text = "AH Query"
$InputRadioButton1.Font = 'Microsoft Sans Serif,10'
 
$InputRadioButton2 = New-Object System.Windows.Forms.RadioButton
$InputRadioButton2.width = 140
$InputRadioButton2.height = 20
$InputRadioButton2.location = New-Object System.Drawing.Point(110, 25)
$InputRadioButton2.Checked = $false
$InputRadioButton2.Enabled = $false
$InputRadioButton2.Text = "Computer Name(s)"
$InputRadioButton2.Font = 'Microsoft Sans Serif,10'
 
$InputRadioButton3 = New-Object System.Windows.Forms.RadioButton
$InputRadioButton3.width = 60
$InputRadioButton3.height = 20
$InputRadioButton3.location = New-Object System.Drawing.Point(265, 25)
$InputRadioButton3.Checked = $false
$InputRadioButton3.Enabled = $false
$InputRadioButton3.Text = "CSV"
$InputRadioButton3.Font = 'Microsoft Sans Serif,10'

$QueryBox = New-Object system.Windows.Forms.TextBox
$QueryBox.multiline = $true
$QueryBox.text = $helpQueryBox 
$QueryBox.width = 850
$QueryBox.height = 120
$QueryBox.location = New-Object System.Drawing.Point(20, 60)
$QueryBox.ScrollBars = 'Vertical'
$QueryBox.Font = $TextBoxFont
$QueryBox.Visible = $true
$QueryBox.Enabled = $false

$RunQueryBtn = New-Object system.Windows.Forms.Button
$RunQueryBtn.BackColor = $UnclickableColour
$RunQueryBtn.text = "Run Query"
$RunQueryBtn.width = 90
$RunQueryBtn.height = 30
$RunQueryBtn.location = New-Object System.Drawing.Point(20, 190)
$RunQueryBtn.Font = 'Microsoft Sans Serif,10'
$RunQueryBtn.ForeColor = "#ffffff"
$RunQueryBtn.Visible = $true

$GetDevicesFromQueryBtn = New-Object System.Windows.Forms.Button
$GetDevicesFromQueryBtn.BackColor = $UnclickableColour
$GetDevicesFromQueryBtn.text = "Get Devices"
$GetDevicesFromQueryBtn.width = 180
$GetDevicesFromQueryBtn.height = 30
$GetDevicesFromQueryBtn.location = New-Object System.Drawing.Point(690, 190)
$GetDevicesFromQueryBtn.Font = 'Microsoft Sans Serif,10'
$GetDevicesFromQueryBtn.ForeColor = "#ffffff"
$GetDevicesFromQueryBtn.Visible = $true

$SelectedDevicesBtn = New-Object system.Windows.Forms.Button
$SelectedDevicesBtn.BackColor = $UnclickableColour
$SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
$SelectedDevicesBtn.width = 150
$SelectedDevicesBtn.height = 30
$SelectedDevicesBtn.location = New-Object System.Drawing.Point(530, 190)
$SelectedDevicesBtn.Font = 'Microsoft Sans Serif,10'
$SelectedDevicesBtn.ForeColor = "#ffffff"
$SelectedDevicesBtn.Visible = $false

$ClearSelectedDevicesBtn = New-Object system.Windows.Forms.Button
$ClearSelectedDevicesBtn.BackColor = $UnclickableColour
$ClearSelectedDevicesBtn.text = "Clear Selection"
$ClearSelectedDevicesBtn.width = 150
$ClearSelectedDevicesBtn.height = 30
$ClearSelectedDevicesBtn.location = New-Object System.Drawing.Point(370, 190)
$ClearSelectedDevicesBtn.Font = 'Microsoft Sans Serif,10'
$ClearSelectedDevicesBtn.ForeColor = "#ffffff"
$ClearSelectedDevicesBtn.Visible = $false

$InputRadioBox.Controls.AddRange(@($InputRadioButton1, $InputRadioButton2, $InputRadioButton3, $QueryBox, $RunQueryBtn, $GetDevicesFromQueryBtn, $SelectedDevicesBtn, $ClearSelectedDevicesBtn))

$LogBoxLabel = New-Object system.Windows.Forms.Label
$LogBoxLabel.text = "4 - Logs:"
$LogBoxLabel.width = 394
$LogBoxLabel.height = 20
$LogBoxLabel.location = New-Object System.Drawing.Point(20, 600)
$LogBoxLabel.Font = 'Microsoft Sans Serif,12,style=Bold'
$LogBoxLabel.Visible = $true

$LogBox = New-Object system.Windows.Forms.TextBox
$LogBox.multiline = $true
$LogBox.width = 880
$LogBox.height = 100
$LogBox.location = New-Object System.Drawing.Point(20, 630)
$LogBox.ScrollBars = 'Vertical'
$LogBox.Font = $TextBoxFont
$LogBox.Visible = $true

$ExportLogBtn = New-Object system.Windows.Forms.Button
$ExportLogBtn.BackColor = '#FFF0F8FF'
$ExportLogBtn.text = "Export Logs"
$ExportLogBtn.width = 90
$ExportLogBtn.height = 30
$ExportLogBtn.location = New-Object System.Drawing.Point(20, 750)
$ExportLogBtn.Font = 'Microsoft Sans Serif,10'
$ExportLogBtn.ForeColor = "#ff000000"
$ExportLogBtn.Visible = $true

$GetActionsHistoryBtn = New-Object system.Windows.Forms.Button
$GetActionsHistoryBtn.BackColor = $UnclickableColour
$GetActionsHistoryBtn.text = "Get Actions History"
$GetActionsHistoryBtn.width = 150
$GetActionsHistoryBtn.height = 30
$GetActionsHistoryBtn.location = New-Object System.Drawing.Point(130, 750)
$GetActionsHistoryBtn.Font = 'Microsoft Sans Serif,10'
$GetActionsHistoryBtn.ForeColor = "#ffffff"
$GetActionsHistoryBtn.Visible = $true

$ExportActionsHistoryBtn = New-Object system.Windows.Forms.Button
$ExportActionsHistoryBtn.BackColor = $UnclickableColour
$ExportActionsHistoryBtn.text = "Export Actions History"
$ExportActionsHistoryBtn.width = 150
$ExportActionsHistoryBtn.height = 30
$ExportActionsHistoryBtn.location = New-Object System.Drawing.Point(300, 750)
$ExportActionsHistoryBtn.Font = 'Microsoft Sans Serif,10'
$ExportActionsHistoryBtn.ForeColor = "#ffffff"
$ExportActionsHistoryBtn.Visible = $true

$cancelBtn = New-Object system.Windows.Forms.Button
$cancelBtn.BackColor = '#FFF0F8FF'
$cancelBtn.text = "Cancel"
$cancelBtn.width = 90
$cancelBtn.height = 30
$cancelBtn.location = New-Object System.Drawing.Point(810, 750)
$cancelBtn.Font = 'Microsoft Sans Serif,10'
$cancelBtn.ForeColor = "#ff000000"
$cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$MainForm.CancelButton = $cancelBtn
$MainForm.Controls.Add($cancelBtn)

#$MainForm.AutoScaleMode = 'dpi'

$MainForm.controls.AddRange(@($Title,
        $Description, 
        $ConnectionStatusLabel, 
        $ConnectionStatus,
        $cancelBtn, 
        $AppIdBox, 
        $AppSecretBox,
        $TenantIdBox, 
        $AppIdBoxLabel, 
        $AppSecretBoxLabel, 
        $TenantIdBoxLabel, 
        $ConnectBtn, 
        $TitleActions, 
        $LogBoxLabel, 
        $LogBox, 
        $QueryBoxLabel,
        $pictureBox, 
        $Branding,
        #$IsolateGroupBox,
        $SaveCredCheckbox,
        #$ScanGroupBox,
        $InputRadioBox,
        $TagDeviceGroupBox,
        $ExportLogBtn,
        $GetActionsHistoryBtn,
        $ExportActionsHistoryBtn))


#===========================================================[Functions]===========================================================


#Authentication

function GetToken {
    $ConnectionStatus.ForeColor = "#000000"
    $ConnectionStatus.Text = 'Connecting...'
    $tenantId = $TenantIdBox.Text
    $appId = $AppIdBox.Text
    $appSecret = $AppSecretBox.Text
    $resourceAppIdUri = 'https://api.securitycenter.windows.com'
    $oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
    $authBody = [Ordered] @{
        resource      = "$resourceAppIdUri"
        client_id     = "$appId"
        client_secret = "$appSecret"
        grant_type    = 'client_credentials'
    }
    
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $token = $authResponse.access_token
    $script:headers = @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $token"
    }
    
    if ($authresponse) {
        $ConnectionStatus.text = "Connected"
        $ConnectionStatus.ForeColor = "#7ed321"
        $LogBox.AppendText((get-date).ToString() + " Successfully connected to Tenant ID: " + $tenantId + [Environment]::NewLine)
        ChangeButtonColours -Buttons $GetDevicesFromQueryBtn, $SelectedDevicesBtn, $ClearSelectedDevicesBtn, $RunQueryBtn, $ExportActionsHistoryBtn, $GetActionsHistoryBtn
        EnableRadioButtons
        SaveCreds
        $Devicetag.Enabled = $true
        $QueryBox.Enabled = $true
        return $headers
    }
    else {
        $ConnectionStatus.text = "Connection Failed"
        [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $Error[0] , "Error")
        $ConnectionStatus.ForeColor = "#D0021B"
        $cancelBtn.text = "Close"
    }

}

function SaveCreds{
    if($SaveCredCheckbox.Checked){
        $securespassword = $AppSecretBox.Text | ConvertTo-SecureString -AsPlainText -Force
        $securestring = $securespassword | ConvertFrom-SecureString
        $creds = @($TenantIdBox.Text, $AppIdBox.Text, $securestring)
        $creds | Out-File $credspath
    }
    }

function ChangeButtonColours {
        [CmdletBinding()]
        Param (
           [Parameter(Mandatory=$True)]
           $Buttons
        )
    $ButtonsToChangeColour = $Buttons

    foreach( $Button in $ButtonsToChangeColour) {
        $Button.BackColor = $ClickableColour
    }
}

function EnableRadioButtons {
    $ButtonsToEnable = <#$ScanRadioButton1, $ScanRadioButton2, $IsolateRadioButton1, $IsolateRadioButton2,#> $InputRadioButton1, 
                        $InputRadioButton2, $InputRadioButton3

    foreach( $Button in $ButtonsToEnable) {
        $Button.Enabled = $true
    }
}

function GetDevice {
    $machines = $QueryBox.Text
    $machines = $machines.Split(",")
    $machines = $machines.replace(' ','')
    $script:selectedmachines = @{}
    foreach($machine in $machines){
        Start-Sleep -Seconds 2
        $MachineName = $machine
        $url = "https://api.securitycenter.windows.com/api/machines/$MachineName"  
        $webResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $MachineId = $webResponse.id
        if (-not $script:selectedmachines.contains($machine)) {
            $script:selectedmachines.Add($MachineName, $MachineId)
        }
    }
    $filtermachines = $script:selectedmachines | Out-GridView -Title "Select devices to perform action on:" -PassThru 
    $script:selectedmachines.clear()
    foreach ($machine in $filtermachines) {
        $script:selectedmachines.Add($machine.Name, $machine.Value)
    }
    if ($script:selectedmachines.Keys.Count -gt 0) {
        ChangeButtonColours -Buttons $RMTagDeviceBtn, $TagDeviceBtn, $ScanDeviceBtn, $IsolateDeviceBtn, $ReleaseFromIsolationBtn, $ExportActionsHistoryBtn, $GetActionsHistoryBtn
        $SelectedDevicesBtn.Visible = $true
        $SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
        $ClearSelectedDevicesBtn.Visible = $true
    }
    $LogBox.AppendText((get-date).ToString() + " Devices selected count: " + ($script:selectedmachines.Keys.count -join [Environment]::NewLine) + [Environment]::NewLine + ($script:selectedmachines.Keys -join [Environment]::NewLine) + [Environment]::NewLine)
}


function TagDevice {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $MachineId = $_.value
        $MachineTag = $DeviceTag.Text
        $body = @{
            "Value"  = $MachineTag;
            "Action" = "Add";
        }

        $url = "https://api.securitycenter.windows.com/api/machines/$MachineId/tags" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { 
            $LogBox.AppendText((get-date).ToString() + " Applying machine tag: " + $MachineTag + " Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
        
    }
}

function RemoveTagfromDevice {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $MachineId = $_.value
        $MachineTag = $DeviceTag.Text
        $body = @{
            "Value"  = $MachineTag;
            "Action" = "Remove";
        }

        $url = "https://api.securitycenter.windows.com/api/machines/$MachineId/tags" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { 
            $LogBox.AppendText((get-date).ToString() + " Removing machine tag: " + $MachineTag + " Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
        
    }
}



function ScanDevice {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $machineid = $_.Value
        if ($ScanRadioButton1.Checked) { $ScanMode = 'Full' } else { $ScanMode = 'Quick' }
        $body = @{
            "Comment"  = "AV Scan";
            "ScanType" = $ScanMode;
        }
        $url = "https://api.securitycenter.windows.com/api/machines/$machineid/runAntiVirusScan" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { $LogBox.AppendText((get-date).ToString() + " " + $ScanMode + " AV Scan on Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
    }
}

function IsolateDevice {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $machineid = $_.Value
        $IsolationType = 'Selective'
        if ($IsolateRadioButton1.Checked) { $IsolationType = 'Full' }
        $body = @{
            "Comment"  = "Isolating device";
            "IsolationType" = $IsolationType;
        }
        $url = "https://api.securitycenter.windows.com/api/machines/$machineid/isolate" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                #[System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message + $_.ErrorDetails, "Error")
                $LogBox.AppendText((get-date).ToString() + " ErrorMessage: " + $_.ErrorDetails.Message + $_.Exception.Response.StatusCode + [Environment]::NewLine)
                
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { $LogBox.AppendText((get-date).ToString() + " " + $IsolationType + " Isolation on: " + " Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
    }
}

function ReleaseFromIsolation {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $machineid = $_.Value
        $body = @{
            "Comment"  = "Releasing device from isolation";
        }
        $url = "https://api.securitycenter.windows.com/api/machines/$machineid/unisolate" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                #[System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message + $_.ErrorDetails, "Error")
                $LogBox.AppendText("ErrorMessage: " + $_.ErrorDetails.Message + $_.Exception.Response.StatusCode + [Environment]::NewLine)
                
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { $LogBox.AppendText($IsolationType + " Releasing isolation on: " + " Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
    }
}


# This function is not present in GUI to avoid any unwanted changes to the environments
function OffboardDevice {
    $script:selectedmachines.GetEnumerator() | foreach-object {
        Start-Sleep -Seconds 2
        $machineid = $_.Value
        $body = @{
            "Comment"  = "Offboarding machine using API";
        }
        $url = "https://api.securitycenter.windows.com/api/machines/$machineid/offboard" 
        try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
        Catch {
            if ($_.ErrorDetails.Message) {
                #[System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message + $_.ErrorDetails, "Error")
                $LogBox.AppendText("ErrorMessage: " + $_.ErrorDetails.Message + $_.Exception.Response.StatusCode + [Environment]::NewLine)
                
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Status: " + $webResponse.StatusCode)
            }
        }
        if ($null -ne $webResponse.statuscode) { $LogBox.AppendText("Offboarding machine: " + [Environment]::NewLine + " Machine Name: " + $_.Key + " Status code: " + $webResponse.statuscode + [Environment]::NewLine) }
    }
}


function RunQuery {
    Start-Sleep -Seconds 2
    $url = "https://api.securitycenter.windows.com/api/advancedqueries/run"  
    $body = @{
        "Query" = $QueryBox.Text;
    }
    try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
    Catch {
        if ($_.ErrorDetails.Message) {
            [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
        }
        else {
            $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode)
        }
    }
    $LogBox.AppendText((get-date).ToString() + " Query Results: " + $webresponse + [Environment]::NewLine)
}

function GetDevicesFromQuery {
    if($InputRadioButton1.Checked -and (-not (($QueryBox.Text).contains('distinct') -and ($QueryBox.Text).contains('DeviceId')))){ 
        $QueryBox.Text = $QueryBox.Text + [Environment]::NewLine + "| distinct DeviceName, DeviceId"
        [System.Windows.Forms.MessageBox]::Show("Query should return DeviceName and DeviceId. `nAppending `"| distinct DeviceName, DeviceId`" to the query.", "Warning")
        } 
    $url = "https://api.securitycenter.windows.com/api/advancedqueries/run"
    $body = @{
        "Query" = $QueryBox.Text;
    }
    $LogBox.AppendText((get-date).ToString() + " Executing query: " + $QueryBox.Text + [Environment]::NewLine) 
    try { $webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop }
    Catch {
        if ($_.ErrorDetails.Message) {
            [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
        }
        else {
            $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode)
        }
    }
    $results = ($webResponse | ConvertFrom-Json).Results
    $LogBox.AppendText("Query results returned: " + $results.count + [Environment]::NewLine) 
    $script:selectedmachines = @{}
    foreach ($result in $results) {
        if (-not $script:selectedmachines.contains($result.DeviceName)) {
            $script:selectedmachines.Add($result.DeviceName, $result.DeviceId)
        }
    }
    $filtermachines = $script:selectedmachines | Out-GridView -Title "Select devices to perform action on:" -PassThru 
    $script:selectedmachines.clear()
    foreach ($machine in $filtermachines) {
        $script:selectedmachines.Add($machine.Name, $machine.Value)
    }
    if ($script:selectedmachines.Keys.Count -gt 0) {
        ChangeButtonColours -Buttons $RMTagDeviceBtn, $TagDeviceBtn, $ScanDeviceBtn, $IsolateDeviceBtn, $ReleaseFromIsolationBtn, $ExportActionsHistoryBtn, $GetActionsHistoryBtn
        $SelectedDevicesBtn.Visible = $true
        $SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
        $ClearSelectedDevicesBtn.Visible = $true
    }
    $LogBox.AppendText((get-date).ToString() + " Devices selected count: " + ($script:selectedmachines.Keys.count -join [Environment]::NewLine) + [Environment]::NewLine + ($script:selectedmachines.Keys -join [Environment]::NewLine) + [Environment]::NewLine)
}

function ViewSelectedDevices {
    $filtermachines = $script:selectedmachines | Out-GridView -Title "Select devices to perform action on:" -PassThru 
    $script:selectedmachines.clear()
    foreach ($machine in $filtermachines) {
        $script:selectedmachines.Add($machine.Name, $machine.Value)
    }
    $SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
    if ($null -eq $script:selectedmachines.Keys.Count) {
        $SelectedDevicesBtn.Visible = $false
        $SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
        $ClearSelectedDevicesBtn.Visible = $false
    }
    $LogBox.AppendText((get-date).ToString() + " Devices selected count: " + ($script:selectedmachines.Keys.count -join [Environment]::NewLine) + [Environment]::NewLine + ($script:selectedmachines.Keys -join [Environment]::NewLine) + [Environment]::NewLine)
}

function ClearSelectedDevices {
    $script:selectedmachines = @{}
    $ClearSelectedDevicesBtn.Visible = $false
    $SelectedDevicesBtn.Visible = $false
    $LogBox.AppendText((get-date).ToString() + " Devices selected count: " + $script:selectedmachines.Keys.count + [Environment]::NewLine)
}


function GetDevicesFromCsv {
    if((Test-Path $QueryBox.Text) -and ($QueryBox.Text).EndsWith(".csv")) {
    $machines = Import-Csv -Path $QueryBox.Text
    $script:selectedmachines = @{}
    $LogBox.AppendText("Quering " + $machines.count + " machines from CSV file." + [Environment]::NewLine)
    foreach($machine in $machines){
        Start-Sleep -Seconds 2
        $MachineName = $machine.Name
        $url = "https://api.securitycenter.windows.com/api/machines/$MachineName"  
        $webResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $MachineId = $webResponse.id
        if (-not $script:selectedmachines.contains($machine.Name)) {
            $script:selectedmachines.Add($machine.Name, $MachineId)
        }
    }
    $filtermachines = $script:selectedmachines | Out-GridView -Title "Select devices to perform action on:" -PassThru 
    $script:selectedmachines.clear()
    foreach ($machine in $filtermachines) {
        $script:selectedmachines.Add($machine.Name, $machine.Value)
    }
    if ($script:selectedmachines.Keys.Count -gt 0) {
        ChangeButtonColours -Buttons $RMTagDeviceBtn, $TagDeviceBtn, $ScanDeviceBtn, $IsolateDeviceBtn, $ReleaseFromIsolationBtn
        $SelectedDevicesBtn.Visible = $true
        $SelectedDevicesBtn.text = "Selected Devices (" + $script:selectedmachines.Keys.count + ")"
        $ClearSelectedDevicesBtn.Visible = $true
    }
    $LogBox.AppendText((get-date).ToString() + " Devices selected count: " + ($script:selectedmachines.Keys.count -join [Environment]::NewLine) + [Environment]::NewLine + ($script:selectedmachines.Keys -join [Environment]::NewLine) + [Environment]::NewLine)
    } 
    else {
        [System.Windows.Forms.MessageBox]::Show($QueryBox.Text + " is not a valid CSV path." , "Error")
    }
}


function GetActionsHistory {
    $LogBox.AppendText("Getting machine actions list.." + [Environment]::NewLine)
    $url = "https://api-us.securitycenter.windows.com/api/machineactions" 
    try { $webResponse = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop }
    Catch {
        if ($_.ErrorDetails.Message) {
            [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
        }
        else {
            $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode)
        }
    }
    $results = ($webResponse.Content | Convertfrom-json).value
    $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode + " Machine actions count: " + $results.count + [Environment]::NewLine)
    $LogBox.AppendText((get-date).ToString() + " Last 10 machine actions: " + ($results | Select-Object type,computerDnsName,status -First 10 | Out-string) + [Environment]::NewLine)
    $results | Out-GridView -Title "Actions History" -PassThru 
}

function ExportActionsHistory {
    $LogBox.AppendText("Getting machine actions list.." + [Environment]::NewLine)
    $url = "https://api-us.securitycenter.windows.com/api/machineactions" 
    try { $webResponse = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop }
    Catch {
        if ($_.ErrorDetails.Message) {
            [System.Windows.Forms.MessageBox]::Show("ErrorMessage: " + $_.ErrorDetails.Message , "Error")
        }
        else {
            $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode)
        }
    }
    $results = ($webResponse.Content | Convertfrom-json).value
    $LogBox.AppendText((get-date).ToString() + " Status: " + $webResponse.StatusCode + " Machine actions count: " + $results.count + [Environment]::NewLine)
    $results | Export-Csv -Path .\Response_Actions.csv -NoTypeInformation
    $LogBox.AppendText((get-date).ToString() + " Export file created: " + (Get-Item .\Response_Actions.csv).FullName + [Environment]::NewLine)
}


function ExportLog{
    $LogBox.Text | Out-file .\mde_ui_log.txt
    $LogBox.AppendText((get-date).ToString() + " Log file created: " + (Get-Item .\mde_ui_log.txt).FullName + [Environment]::NewLine)
}

#===========================================================[Script]===========================================================


if(test-path $credspath){
    $creds = Get-Content $credspath
    $pass = $creds[2] | ConvertTo-SecureString
    $unsecurePassword = [PSCredential]::new(0, $pass).GetNetworkCredential().Password
    $TenantIdBox.Text = $creds[0]
    $AppIdBox.Text = $creds[1]
    $AppSecretBox.Text = $unsecurePassword
}


$ConnectBtn.Add_Click({ GetToken })

$TagDeviceBtn.Add_Click({ TagDevice })

$RMTagDeviceBtn.Add_Click({ RemoveTagfromDevice })

#$ScanDeviceBtn.Add_Click({ ScanDevice })

#$IsolateDeviceBtn.Add_Click({ IsolateDevice })

#$ReleaseFromIsolationBtn.Add_Click({ ReleaseFromIsolation })

$RunQueryBtn.Add_Click({ RunQuery })

$GetDevicesFromQueryBtn.Add_Click({ 
    if ($InputRadioButton1.Checked){
    GetDevicesFromQuery }
 elseif ($InputRadioButton2.Checked){
    GetDevice }
 elseif ($InputRadioButton3.Checked){
    GetDevicesFromCsv }
})

$SelectedDevicesBtn.Add_Click({ ViewSelectedDevices })

$ClearSelectedDevicesBtn.Add_Click({ ClearSelectedDevices })

$ExportLogBtn.Add_Click({ ExportLog })

$GetActionsHistoryBtn.Add_Click({ getActionsHistory })

$ExportActionsHistoryBtn.Add_Click({ ExportActionsHistory })

$MainForm.ResumeLayout()
[void]$MainForm.ShowDialog()
