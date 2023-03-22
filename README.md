# MDAD PoSH GUI for Tagging MDE Devices 
Simple PowerShell GUI for Microsoft Defender for Endpoint API machine actions.
![alt text](/MDAD-Tagging.jpg)
## Get started
1. Create Azure AD application as described here: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro?view=o365-worldwide
2. Grant the following API permissions to the application:

| Permission | Description |
|-------------------------|----------------------|
| AdvancedQuery.Read.All	| Run advanced queries |
| Machine.ReadWrite.All |	Read and write all machine information (used for tagging) |

3. Create application secret.
## Usage
1. **Connect** with AAD Tenant ID, Application Id and Application Secret of the application created earlier.
2. **Get Devices** that you want to perform actions on, using one of the following methods:
    * Advanced Hunting query (query result should contain DeviceName and DeviceId fields)
    * CSV file (single Name column with machine FQDNs)
    * Devices list separated with commas
3. Confirm selection in PowerShell forms pop-up.
4. Choose action that you want to perform on **Selected Devices**, the following actions are currently available:
    * Specify device tag in text box and **Apply tag** or **Remove tag**.
5. Verify actions result with **Logs** text box.


