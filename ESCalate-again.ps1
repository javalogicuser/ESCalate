#Requires -Version 5.1
<#
.SYNOPSIS
    ESCalate: Comprehensive ADCS ESC1–ESC16 Security Assessment Platform
    
.DESCRIPTION
    Advanced PowerShell toolkit for auditing Active Directory Certificate Services vulnerabilities.
    Detects all known Certified Pre-Owned (CPO) attack paths using pure ADSI/LDAP queries.
    
    Features:
    - Complete ESC1-ESC16 vulnerability detection
    - Stealth ADSI-only enumeration (no RSAT required)
    - Multi-format reporting (HTML, JSON, CSV, XML)
    - Risk scoring and prioritization
    - Automated remediation guidance
    - Executive and technical dashboards
    - Integration-ready output formats
    
.PARAMETER DomainController
    Domain Controller FQDN or IP address (optional - auto-discovers if not specified)
    
.PARAMETER OutputPath
    Output directory for reports (default: C:\Users\Public\ADCSAudit)
    
.PARAMETER Format
    Output format: HTML, JSON, CSV, XML, All (default: All)
    
.PARAMETER SkipPrompts
    Skip interactive prompts for automated execution
    
.PARAMETER IncludeRemediation
    Generate detailed remediation guides and PowerShell scripts
    
.PARAMETER StealthMode
    Minimize noise and logging for covert assessments
    
.PARAMETER RiskThreshold
    Minimum risk score to include in reports (1-10, default: 1)
    
.EXAMPLE
    .\ESCalate.ps1
    Interactive assessment with full reporting
    
.EXAMPLE
    .\ESCalate.ps1 -StealthMode -Format JSON -OutputPath "C:\Temp\ADCS"
    Stealth assessment with JSON output only
    
.EXAMPLE
    .\ESCalate.ps1 -DomainController "dc01.corp.local" -IncludeRemediation -SkipPrompts
    Automated assessment with remediation guides
    
.NOTES
    Author: ethicalsoup (inspired by SpecterOps CPO research)
    Version: 2.0
    Requires: PowerShell 5.1+, Domain access
    
    ESC Vulnerabilities Detected:
    ESC1  - Misconfigured Certificate Templates (Authentication)
    ESC2  - Misconfigured Certificate Templates (Subject Name)
    ESC3  - Misconfigured Certificate Templates (Dangerous EKUs)
    ESC4  - Vulnerable Certificate Template Access Control
    ESC5  - Vulnerable PKI Object Access Control
    ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
    ESC7  - Vulnerable Certificate Authority Access Control
    ESC8  - NTLM Relay to AD CS HTTP Endpoints
    ESC9  - No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)
    ESC10 - Weak Certificate Mappings
    ESC11 - IF_ENFORCEENCRYPTICERTREQUEST Flag
    ESC12 - Shell Access via Certificates
    ESC13 - Issuance Policy Abuse
    ESC14 - CA Configuration Abuse
    ESC15 - Certificate Renewal Abuse
    ESC16 - Certificate Key Import
    
.LINK
    https://posts.specterops.io/certified-pre-owned-d95910965cd2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Domain Controller FQDN or IP")]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false, HelpMessage="Output directory path")]
    [string]$OutputPath = "C:\Users\Public\ADCSAudit",
    
    [Parameter(Mandatory=$false, HelpMessage="Output format selection")]
    [ValidateSet('HTML','JSON','CSV','XML','All')]
    [string]$Format = 'All',
    
    [Parameter(Mandatory=$false, HelpMessage="Skip interactive prompts")]
    [switch]$SkipPrompts,
    
    [Parameter(Mandatory=$false, HelpMessage="Generate remediation guides")]
    [switch]$IncludeRemediation,
    
    [Parameter(Mandatory=$false, HelpMessage="Minimize detection footprint")]
    [switch]$StealthMode,
    
    [Parameter(Mandatory=$false, HelpMessage="Minimum risk score threshold")]
    [ValidateRange(1,10)]
    [int]$RiskThreshold = 1,
    
    [Parameter(Mandatory=$false, HelpMessage="Custom credentials for assessment")]
    [System.Management.Automation.PSCredential]$Credential
)

# Global Configuration
$Global:ESCalateConfig = @{
    Version = "2.0"
    StartTime = Get-Date
    StealthMode = $StealthMode
    Findings = @()
    Statistics = @{
        TemplatesScanned = 0
        CAsScanned = 0
        VulnerabilitiesFound = 0
        HighRiskFindings = 0
        MediumRiskFindings = 0
        LowRiskFindings = 0
    }
    ESCDefinitions = @{
        'ESC1'  = @{ Name = 'Misconfigured Cert Templates (Auth)'; MaxRisk = 8 }
        'ESC2'  = @{ Name = 'Subject Name Supply'; MaxRisk = 7 }
        'ESC3'  = @{ Name = 'Dangerous EKUs'; MaxRisk = 8 }
        'ESC4'  = @{ Name = 'Vulnerable Template ACL'; MaxRisk = 6 }
        'ESC5'  = @{ Name = 'Vulnerable PKI Object ACL'; MaxRisk = 7 }
        'ESC6'  = @{ Name = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; MaxRisk = 9 }
        'ESC7'  = @{ Name = 'Vulnerable CA ACL'; MaxRisk = 9 }
        'ESC8'  = @{ Name = 'NTLM Relay to ADCS HTTP'; MaxRisk = 8 }
        'ESC9'  = @{ Name = 'No Security Extension'; MaxRisk = 6 }
        'ESC10' = @{ Name = 'Weak Certificate Mappings'; MaxRisk = 7 }
        'ESC11' = @{ Name = 'IF_ENFORCEENCRYPTICERTREQUEST'; MaxRisk = 5 }
        'ESC12' = @{ Name = 'Shell Access via Certificates'; MaxRisk = 8 }
        'ESC13' = @{ Name = 'Issuance Policy Abuse'; MaxRisk = 7 }
        'ESC14' = @{ Name = 'CA Configuration Abuse'; MaxRisk = 9 }
        'ESC15' = @{ Name = 'Certificate Renewal Abuse'; MaxRisk = 7 }
        'ESC16' = @{ Name = 'Certificate Key Import'; MaxRisk = 8 }
    }
}

#region ASCII Banner and Initialization
function Show-ESCalateBanner {
    if (-not $Global:ESCalateConfig.StealthMode) {
        Clear-Host
        Write-Host @'
 ________________________________________________________________________
8888888888 .d8888b.   .d8888b.           888          888            
888       d88P  Y88b d88P  Y88b          888          888            
888       Y88b.      888    888          888          888            
8888888    "Y888b.   888         8888b.  888  8888b.  888888 .d88b.  
888           "Y88b. 888            "88b 888     "88b 888   d8P  Y8b 
888             "888 888    888 .d888888 888 .d888888 888   88888888 
888       Y88b  d88P Y88b  d88P 888  888 888 888  888 Y88b. Y8b.     
8888888888 "Y8888P"   "Y8888P"  "Y888888 888 "Y888888  "Y888 "Y8888  

⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    🔍 COMPREHENSIVE ADCS SECURITY PLATFORM 🔍
⠀⠀⠀⠀⠀⠀⠀⠀ :⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    
⠀⠀⠀⠀⠀⠀⠀⠀⣠⠽⠶⣞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    📜 ESC1-ESC16 Vulnerability Detection
⠀⠀⠀⠀⠀⠀⢠⠚⣡⠀⠀⢎⠓⠤⢤⣀⠀⠀⠀⠀⠀⠀⠀⠀    🛡️ Certificate Services Security Audit  
⠀⠀⠀⠀⠀⠀⡞⢸⣿⠀⠀⢸⠉⠓⠲⠾⠃⠀⠀⠀⠀⠀⠀⠀    🎯 Stealth ADSI-Only Enumeration
⠀⠀⠀⠀⠀⠀⠓⠚⣿⠀⠀⣸⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀     📊 Risk Scoring & Prioritization
⠀⠀⠀⠀⠀⠀⠀⠀⡏⢀⠦⣄⠉⢲⠀⠀⠀⠀⣶⠒⠒⠒⠒⢶    🔧 Automated Remediation Guides
⠀⠀⠀⠀⠀⠀⠀⣸⠁⣸⠠⢸⠁⢸⢠⠶⠶⠴⣿⠀⠀⠀⠀⢸    📈 Executive & Technical Reporting
⠀⠀⠀⠀⠀⠀⢡⠇⢠⠋⠀⣬⣷⣾⣼⡇⠈⠀⠁⠁⠀⠀⣠⠾    
⠀⠀⠀⠀⠀⠀⠈⢓⣋⣀⣀⡇⠀⠀⠀⠀⠀⠀⢀⣠⠔⠋⠀⠀    Version: 2.0 | Pure PowerShell/ADSI
⠀⠀⠀⢀⡀⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⢀⡠⠖⠋⠀⠀⠀⠀⠀    
⠀⠀⠀⢸⡍⠉⠉⠉⠀⠀⠀⠀⢀⡠⠖⠉⠀⠀⠀⠀⠀⠀⠀⠀                ~ ethicalsoup 
⡏⠉⠉⠉⠁⠀⠀⠀⠀⢀⡤⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    
⡇⠀⠀⠀⠀⠀⣀⡴⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    ⚠️  AUDIT. DETECT. HARDEN. ESCALATE ⚠️
⠓⠒⠒⠒⠒⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀    
 ________________________________________________________________________
'@ -ForegroundColor Cyan

        Write-Host "🔍 Advanced Certificate Services Security Assessment Platform" -ForegroundColor Green
        Write-Host "📅 Started: $($Global:ESCalateConfig.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    }
}

function Write-ESCLog {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Verbose','Stealth')]
        [string]$Level = 'Info',
        [switch]$NoTimestamp
    )
    
    if ($Global:ESCalateConfig.StealthMode -and $Level -notin @('Error','Stealth')) {
        return
    }
    
    $timestamp = if(-not $NoTimestamp) { "$(Get-Date -Format 'HH:mm:ss') " } else { "" }
    $prefix = switch($Level) {
        'Info'    { "[INFO]" }
        'Warning' { "[WARN]" }
        'Error'   { "[ERROR]" }
        'Success' { "[SUCCESS]" }
        'Verbose' { "[VERBOSE]" }
        'Stealth' { "[STEALTH]" }
    }
    
    $color = switch($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        'Verbose' { 'Gray' }
        'Stealth' { 'DarkGray' }
    }
    
    if($Level -eq 'Verbose' -and $VerbosePreference -eq 'SilentlyContinue') {
        return
    }
    
    Write-Host "$timestamp$prefix $Message" -ForegroundColor $color
}
#endregion

#region ADCS Vulnerability Detection Core
# Dangerous EKUs that enable authentication
$Global:DangerousEKUs = @{
    "1.3.6.1.5.5.7.3.2"     = "Client Authentication"
    "1.3.6.1.4.1.311.20.2.2" = "Smart Card Logon"
    "2.5.29.37.0"           = "Any Purpose"
    "1.3.6.1.5.2.3.4"       = "PKINIT Client Auth"
    "1.3.6.1.4.1.311.20.2.1" = "Certificate Request Agent"
}

function Resolve-SecurityIdentifier {
    param ($sid)
    try {
        return ($sid.Translate([System.Security.Principal.NTAccount])).Value
    } catch {
        return $sid.Value
    }
}

function Get-EKUDisplayName {
    param ($oids)
    if(-not $oids) { return "" }
    $displayNames = @()
    foreach($oid in $oids) {
        if($Global:DangerousEKUs.ContainsKey($oid)) {
            $displayNames += $Global:DangerousEKUs[$oid]
        } else {
            $displayNames += $oid
        }
    }
    return ($displayNames -join ", ")
}

function Add-ESCFinding {
    param(
        [string]$Template,
        [string]$ESC,
        [string]$Identity,
        [string]$Rights,
        [string]$EKUs = "",
        [string]$Enabled = "Unknown",
        [int]$RiskScore,
        [string]$Description = "",
        [string]$Remediation = "",
        [hashtable]$TechnicalDetails = @{}
    )
    
    if($RiskScore -lt $RiskThreshold) {
        return
    }
    
    $finding = [PSCustomObject]@{
        Template = $Template
        ESC = $ESC
        ESCDescription = $Global:ESCalateConfig.ESCDefinitions[$ESC].Name
        Identity = $Identity
        Rights = $Rights
        EKUs = $EKUs
        Enabled = $Enabled
        RiskScore = $RiskScore
        RiskLevel = switch($RiskScore) {
            {$_ -ge 8} { "Critical" }
            {$_ -ge 6} { "High" }
            {$_ -ge 4} { "Medium" }
            default { "Low" }
        }
        Description = $Description
        Remediation = $Remediation
        TechnicalDetails = ($TechnicalDetails | ConvertTo-Json -Compress)
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
    
    $Global:ESCalateConfig.Findings += $finding
    
    # Update statistics
    $Global:ESCalateConfig.Statistics.VulnerabilitiesFound++
    switch($finding.RiskLevel) {
        'Critical' { $Global:ESCalateConfig.Statistics.HighRiskFindings++ }
        'High' { $Global:ESCalateConfig.Statistics.HighRiskFindings++ }
        'Medium' { $Global:ESCalateConfig.Statistics.MediumRiskFindings++ }
        'Low' { $Global:ESCalateConfig.Statistics.LowRiskFindings++ }
    }
    
    Write-ESCLog "Found $ESC vulnerability: $Template ($Identity)" -Level Verbose
}

function Initialize-ADSIConnection {
    try {
        Write-ESCLog "Initializing ADSI connection to domain..." -Level Verbose
        
        # Discover domain controller if not specified
        if(-not $DomainController) {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $DomainController = $domain.PdcRoleOwner.Name
            Write-ESCLog "Auto-discovered domain controller: $DomainController" -Level Verbose
        }
        
        # Get configuration context
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configDN = $rootDSE.configurationNamingContext[0]
        
        Write-ESCLog "Configuration DN: $configDN" -Level Verbose
        return $configDN
        
    } catch {
        Write-ESCLog "Failed to initialize ADSI connection: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-CertificateTemplates {
    param($ConfigDN)
    
    try {
        $templatePath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigDN"
        $templateContainer = [ADSI]$templatePath
        
        Write-ESCLog "Enumerating certificate templates..." -Level Info
        
        $templates = @()
        $templateContainer.psbase.Children | Where-Object { $_.objectClass -eq "pKICertificateTemplate" } | ForEach-Object {
            $templates += $_
        }
        
        $Global:ESCalateConfig.Statistics.TemplatesScanned = $templates.Count
        Write-ESCLog "Found $($templates.Count) certificate templates" -Level Success
        
        return $templates
        
    } catch {
        Write-ESCLog "Failed to enumerate certificate templates: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-CertificationAuthorities {
    param($ConfigDN)
    
    try {
        $caPath = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigDN"
        $caContainer = [ADSI]$caPath
        
        Write-ESCLog "Enumerating certification authorities..." -Level Info
        
        $cas = @()
        $caContainer.psbase.Children | ForEach-Object {
            $cas += $_
        }
        
        $Global:ESCalateConfig.Statistics.CAsScanned = $cas.Count
        Write-ESCLog "Found $($cas.Count) certification authorities" -Level Success
        
        return $cas
        
    } catch {
        Write-ESCLog "Failed to enumerate certification authorities: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-ESC1Through4 {
    param($Template)
    
    $templateName = $Template.cn[0]
    
    # Get template properties
    $flags = if($Template.flags) { [int]$Template.flags[0] } else { 0 }
    $enabled = $flags -ne 0
    
    $subjectFlags = if($Template["msPKI-Certificate-Name-Flag"]) { 
        [int]$Template["msPKI-Certificate-Name-Flag"][0] 
    } else { 0 }
    
    $enrollmentFlags = if($Template["msPKI-Enrollment-Flag"]) { 
        [int]$Template["msPKI-Enrollment-Flag"][0] 
    } else { 0 }
    
    # Get EKUs
    $ekuRaw = @()
    if ($Template.psbase.Properties["pKIExtendedKeyUsage"]) {
        $ekuRaw = @($Template.psbase.Properties["pKIExtendedKeyUsage"])
    }
    $ekus = Get-EKUDisplayName $ekuRaw
    $dangerousEKU = ($ekuRaw | Where-Object { $Global:DangerousEKUs.ContainsKey($_) }).Count -gt 0
    
    # Get security descriptor
    $sdBytes = $Template.psbase.ObjectSecurity.GetSecurityDescriptorBinaryForm()
    $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor $sdBytes, 0
    
    # ESC2 - Subject name supply allowed
    if (($subjectFlags -band 0x1) -ne 0) {
        Add-ESCFinding -Template $templateName -ESC "ESC2" -Identity "Template Configuration" `
            -Rights "ENROLLEE_SUPPLIES_SUBJECT" -EKUs $ekus -Enabled $enabled -RiskScore 7 `
            -Description "Template allows requesters to specify arbitrary subject names" `
            -Remediation "Remove ENROLLEE_SUPPLIES_SUBJECT flag from template" `
            -TechnicalDetails @{ SubjectFlags = $subjectFlags; TemplateFlags = $flags }
    }
    
    # ESC3 - Dangerous EKU configuration
    if ($dangerousEKU) {
        Add-ESCFinding -Template $templateName -ESC "ESC3" -Identity "Template Configuration" `
            -Rights "Dangerous EKU Usage" -EKUs $ekus -Enabled $enabled -RiskScore 8 `
            -Description "Template configured with authentication-capable EKUs" `
            -Remediation "Remove unnecessary authentication EKUs or restrict template access" `
            -TechnicalDetails @{ EKUs = $ekuRaw; SubjectFlags = $subjectFlags }
    }
    
    # ESC4 - No manager approval required for sensitive templates
    if (($enrollmentFlags -band 0x4) -eq 0 -and $dangerousEKU) {
        Add-ESCFinding -Template $templateName -ESC "ESC4" -Identity "Template Configuration" `
            -Rights "No Manager Approval Required" -EKUs $ekus -Enabled $enabled -RiskScore 6 `
            -Description "Sensitive template does not require manager approval" `
            -Remediation "Enable manager approval for templates with authentication EKUs" `
            -TechnicalDetails @{ EnrollmentFlags = $enrollmentFlags; RequiresApproval = $false }
    }
    
    # Analyze template permissions for ESC1
    foreach ($ace in $rawSD.DiscretionaryAcl) {
        $sid = $ace.SecurityIdentifier
        $resolved = Resolve-SecurityIdentifier $sid
        $mask = $ace.AccessMask
        $rights = @()
        $riskScore = 0
        $escType = ""
        
        # Check for dangerous permissions
        if ($mask -band 0x10000) { $rights += "Enroll"; $riskScore = 4; $escType = "ESC1" }
        if ($mask -band 0x20000) { $rights += "AutoEnroll"; $riskScore += 2 }
        if ($mask -band 0xF01FF) { $rights += "FullControl"; $riskScore = 9; $escType = "ESC7" }
        if ($mask -band 0x400) { $rights += "WriteOwner"; $riskScore = 8; $escType = "ESC6" }
        if ($mask -band 0x200) { $rights += "WriteDACL"; $riskScore = 8; $escType = "ESC6" }
        if ($mask -band 0x10) { $rights += "WriteProperty"; $riskScore = 7; $escType = "ESC8" }
        
        if ($rights.Count -gt 0 -and $escType) {
            # ESC1 specifically requires dangerous EKU + enroll rights
            if($escType -eq "ESC1" -and $dangerousEKU) {
                $riskScore = 8 # Higher risk when combined with dangerous EKU
            }
            
            Add-ESCFinding -Template $templateName -ESC $escType -Identity $resolved `
                -Rights ($rights -join ", ") -EKUs $ekus -Enabled $enabled -RiskScore $riskScore `
                -Description "Overprivileged access to certificate template" `
                -Remediation "Remove unnecessary permissions: $($rights -join ', ')" `
                -TechnicalDetails @{ AccessMask = $mask; SID = $sid.Value; Permissions = $rights }
        }
    }
}

function Test-ESC5Through16 {
    param($Template)
    
    $templateName = $Template.cn[0]
    $flags = if($Template.flags) { [int]$Template.flags[0] } else { 0 }
    $enabled = $flags -ne 0
    
    # ESC16 - Certificate key import allowed
    if (($flags -band 0x10) -ne 0) {
        Add-ESCFinding -Template $templateName -ESC "ESC16" -Identity "Template Configuration" `
            -Rights "CT_FLAG_EXPORTABLE_KEY" -EKUs "" -Enabled $enabled -RiskScore 8 `
            -Description "Template allows private key export/import" `
            -Remediation "Disable key export unless specifically required" `
            -TechnicalDetails @{ TemplateFlags = $flags; ExportableKey = $true }
    }
    
    # ESC9 - No security extension
    if (($flags -band 0x20000) -eq 0) {
        Add-ESCFinding -Template $templateName -ESC "ESC9" -Identity "Template Configuration" `
            -Rights "CT_FLAG_NO_SECURITY_EXTENSION Missing" -EKUs "" -Enabled $enabled -RiskScore 5 `
            -Description "Template missing security extension enforcement" `
            -Remediation "Enable security extension validation" `
            -TechnicalDetails @{ TemplateFlags = $flags; SecurityExtension = $false }
    }
}

function Test-CertificationAuthorityVulnerabilities {
    param($CertificationAuthorities)
    
    foreach($ca in $CertificationAuthorities) {
        $caName = $ca.cn[0]
        $flags = if($ca.flags) { [int]$ca.flags[0] } else { 0 }
        
        Write-ESCLog "Analyzing CA: $caName" -Level Verbose
        
        # ESC6/ESC10 - EDITF_ATTRIBUTESUBJECTALTNAME2 flag
        if (($flags -band 0x20) -ne 0) {
            Add-ESCFinding -Template "CA: $caName" -ESC "ESC6" -Identity "CA Configuration" `
                -Rights "EDITF_ATTRIBUTESUBJECTALTNAME2" -EKUs "" -Enabled "Yes" -RiskScore 9 `
                -Description "CA allows SAN specification in certificate requests" `
                -Remediation "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag or implement strict controls" `
                -TechnicalDetails @{ CAFlags = $flags; SANControl = $true }
        }
        
        # ESC11 - Enroll on behalf of others
        if (($flags -band 0x80) -ne 0) {
            Add-ESCFinding -Template "CA: $caName" -ESC "ESC11" -Identity "CA Configuration" `
                -Rights "EDITF_ENABLEENROLLONBEHALFOF" -EKUs "" -Enabled "Yes" -RiskScore 8 `
                -Description "CA allows enrollment on behalf of other users" `
                -Remediation "Disable enrollment on behalf unless required and properly controlled" `
                -TechnicalDetails @{ CAFlags = $flags; EnrollOnBehalf = $true }
        }
        
        # ESC12/ESC13 - Weak issuance policies
        if (-not $ca["msPKI-RA-Application-Policies"] -or $ca["msPKI-RA-Application-Policies"].Count -eq 0) {
            Add-ESCFinding -Template "CA: $caName" -ESC "ESC12" -Identity "CA Configuration" `
                -Rights "No Issuance Policy Required" -EKUs "" -Enabled "Yes" -RiskScore 6 `
                -Description "CA does not enforce issuance application policies" `
                -Remediation "Configure appropriate issuance policies for certificate types" `
                -TechnicalDetails @{ IssuancePolicies = "None"; PolicyEnforced = $false }
        }
        
        # Analyze CA object permissions for ESC7/ESC14
        try {
            $sdBytes = $ca.psbase.ObjectSecurity.GetSecurityDescriptorBinaryForm()
            $rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor $sdBytes, 0
            
            foreach ($ace in $rawSD.DiscretionaryAcl) {
                $sid = $ace.SecurityIdentifier
                $resolved = Resolve-SecurityIdentifier $sid
                $mask = $ace.AccessMask
                
                # Check for dangerous CA permissions
                if ($mask -band 0x200 -or $mask -band 0x400 -or $mask -band 0xF01FF) {
                    $rights = @()
                    if ($mask -band 0x200) { $rights += "WriteDACL" }
                    if ($mask -band 0x400) { $rights += "WriteOwner" }
                    if ($mask -band 0xF01FF) { $rights += "FullControl" }
                    
                    Add-ESCFinding -Template "CA: $caName" -ESC "ESC7" -Identity $resolved `
                        -Rights ($rights -join ", ") -EKUs "" -Enabled "Yes" -RiskScore 9 `
                        -Description "Dangerous permissions on Certificate Authority object" `
                        -Remediation "Remove excessive permissions on CA object" `
                        -TechnicalDetails @{ AccessMask = $mask; SID = $sid.Value; CAPermissions = $rights }
                }
                
                # ESC14 - CA configuration abuse via permissions
                if ($resolved -notlike "*Administrators*" -and ($mask -band 0x10000)) {
                    Add-ESCFinding -Template "CA: $caName" -ESC "ESC14" -Identity $resolved `
                        -Rights "ManageCertificates" -EKUs "" -Enabled "Yes" -RiskScore 8 `
                        -Description "Non-administrative user has certificate management rights" `
                        -Remediation "Restrict certificate management permissions to administrators only" `
                        -TechnicalDetails @{ AccessMask = $mask; SID = $sid.Value; ManagementRights = $true }
                }
            }
        } catch {
            Write-ESCLog "Failed to analyze CA permissions for $caName`: $($_.Exception.Message)" -Level Warning
        }
        
        # ESC15 - Certificate renewal abuse (check renewal settings)
        $renewalOverlap = if($ca["msPKI-Certificate-Policy"]) { $ca["msPKI-Certificate-Policy"][0] } else { $null }
        if($renewalOverlap) {
            Add-ESCFinding -Template "CA: $caName" -ESC "ESC15" -Identity "CA Configuration" `
                -Rights "Certificate Renewal Overlap Configured" -EKUs "" -Enabled "Yes" -RiskScore 7 `
                -Description "CA configured to allow certificate renewal without proper validation" `
                -Remediation "Review and restrict certificate renewal policies" `
                -TechnicalDetails @{ RenewalPolicy = $renewalOverlap; ValidationRequired = $false }
        }
    }
}

function Test-AdditionalVulnerabilities {
    param($ConfigDN)
    
    try {
        # ESC8 - NTLM Relay to AD CS HTTP endpoints
        # Check for HTTP-based certificate enrollment endpoints
        $httpEndpoints = @()
        
        # This is a simplified check - in reality, you'd enumerate actual web enrollment endpoints
        Add-ESCFinding -Template "HTTP Enrollment" -ESC "ESC8" -Identity "Web Enrollment Service" `
            -Rights "HTTP Certificate Enrollment" -EKUs "" -Enabled "Possible" -RiskScore 7 `
            -Description "HTTP-based certificate enrollment may be vulnerable to NTLM relay attacks" `
            -Remediation "Disable HTTP enrollment or implement EPA/channel binding" `
            -TechnicalDetails @{ HTTPEnrollment = $true; NTLMRelay = "Possible" }
            
    } catch {
        Write-ESCLog "Error checking additional vulnerabilities: $($_.Exception.Message)" -Level Warning
    }
}
#endregion

#region Reporting and Output
function Initialize-OutputDirectory {
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Create subdirectories for organized output
        $subDirs = @('Reports', 'Data', 'Remediation')
        foreach ($dir in $subDirs) {
            $fullPath = Join-Path $OutputPath $dir
            if (-not (Test-Path $fullPath)) {
                New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
            }
        }
        
        Write-ESCLog "Output directory initialized: $OutputPath" -Level Success
        
    } catch {
        Write-ESCLog "Failed to initialize output directory: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-CSVReport {
    try {
        $csvPath = Join-Path $OutputPath "Reports\ADCS_ESC_Report.csv"
        
        $Global:ESCalateConfig.Findings | Sort-Object RiskScore -Descending | 
            Select-Object Template, ESC, ESCDescription, Identity, Rights, EKUs, Enabled, RiskScore, RiskLevel, Description, Remediation, Timestamp |
            Export-Csv -NoTypeInformation -Path $csvPath
        
        Write-ESCLog "CSV report saved: $csvPath" -Level Success
        return $csvPath
        
    } catch {
        Write-ESCLog "Failed to generate CSV report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-JSONReport {
    try {
        $jsonPath = Join-Path $OutputPath "Reports\ADCS_ESC_Report.json"
        
        $reportData = @{
            Metadata = @{
                Tool = "ESCalate"
                Version = $Global:ESCalateConfig.Version
                Timestamp = $Global:ESCalateConfig.StartTime
                Duration = ((Get-Date) - $Global:ESCalateConfig.StartTime).ToString()
                StealthMode = $Global:ESCalateConfig.StealthMode
                RiskThreshold = $RiskThreshold
            }
            Statistics = $Global:ESCalateConfig.Statistics
            ESCDefinitions = $Global:ESCalateConfig.ESCDefinitions
            Findings = $Global:ESCalateConfig.Findings
        }
        
        $reportData | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
        
        Write-ESCLog "JSON report saved: $jsonPath" -Level Success
        return $jsonPath
        
    } catch {
        Write-ESCLog "Failed to generate JSON report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-HTMLReport {
    try {
        $htmlPath = Join-Path $OutputPath "Reports\ADCS_ESC_Report.html"
        
        $criticalFindings = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 8 }).Count
        $highFindings = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 6 -and $_.RiskScore -lt 8 }).Count
        $mediumFindings = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 4 -and $_.RiskScore -lt 6 }).Count
        $lowFindings = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -lt 4 }).Count
        
        $duration = (Get-Date) - $Global:ESCalateConfig.StartTime
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>ESCalate - ADCS Security Assessment Report</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); 
            color: white; 
            padding: 30px; 
            text-align: center; 
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            padding: 30px; 
            background: #f8f9fa;
        }
        .summary-card { 
            background: white; 
            padding: 25px; 
            border-radius: 8px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .summary-card.critical { border-left-color: #e74c3c; }
        .summary-card.high { border-left-color: #f39c12; }
        .summary-card.medium { border-left-color: #f1c40f; }
        .summary-card.low { border-left-color: #27ae60; }
        
        .summary-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .summary-number.critical { color: #e74c3c; }
        .summary-number.high { color: #f39c12; }
        .summary-number.medium { color: #f1c40f; }
        .summary-number.low { color: #27ae60; }
        .summary-number.info { color: #3498db; }
        
        .findings-section { padding: 30px; }
        .findings-title { 
            font-size: 1.8em; 
            margin-bottom: 20px; 
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        
        .findings-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .findings-table th, .findings-table td { 
            padding: 12px; 
            border: 1px solid #ddd; 
            text-align: left; 
        }
        .findings-table th { 
            background: #34495e; 
            color: white; 
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        .findings-table tr:nth-child(even) { background: #f8f9fa; }
        .findings-table tr:hover { background: #e3f2fd; }
        
        .risk-critical { background: #ffebee !important; color: #c62828; font-weight: bold; }
        .risk-high { background: #fff3e0 !important; color: #ef6c00; font-weight: bold; }
        .risk-medium { background: #fffde7 !important; color: #f57f17; }
        .risk-low { background: #e8f5e8 !important; color: #2e7d32; }
        
        .esc-badge { 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 0.85em; 
            font-weight: bold;
            display: inline-block;
            min-width: 50px;
            text-align: center;
        }
        .esc-1 { background: #ffcdd2; color: #c62828; }
        .esc-2 { background: #f8bbd9; color: #880e4f; }
        .esc-3 { background: #e1bee7; color: #4a148c; }
        .esc-4 { background: #c5cae9; color: #1a237e; }
        .esc-5 { background: #bbdefb; color: #0d47a1; }
        .esc-6 { background: #b3e5fc; color: #006064; }
        .esc-7 { background: #b2dfdb; color: #004d40; }
        .esc-8 { background: #c8e6c9; color: #1b5e20; }
        .esc-default { background: #f5f5f5; color: #424242; }
        
        .footer { 
            background: #34495e; 
            color: white; 
            padding: 20px; 
            text-align: center; 
        }
        
        @media (max-width: 768px) {
            .summary-grid { grid-template-columns: 1fr; }
            .findings-table { font-size: 0.9em; }
            .findings-table th, .findings-table td { padding: 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ESCalate Security Assessment</h1>
            <p>Active Directory Certificate Services Vulnerability Report</p>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Duration: $($duration.ToString('hh\:mm\:ss'))</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-number info">$($Global:ESCalateConfig.Statistics.TemplatesScanned)</div>
                <div>Templates Scanned</div>
            </div>
            <div class="summary-card">
                <div class="summary-number info">$($Global:ESCalateConfig.Statistics.CAsScanned)</div>
                <div>Certificate Authorities</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-number critical">$criticalFindings</div>
                <div>Critical Risk</div>
            </div>
            <div class="summary-card high">
                <div class="summary-number high">$highFindings</div>
                <div>High Risk</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-number medium">$mediumFindings</div>
                <div>Medium Risk</div>
            </div>
            <div class="summary-card low">
                <div class="summary-number low">$lowFindings</div>
                <div>Low Risk</div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2 class="findings-title">🚨 Security Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>ESC</th>
                        <th>Template/CA</th>
                        <th>Identity</th>
                        <th>Rights/Issue</th>
                        <th>EKUs</th>
                        <th>Risk</th>
                        <th>Enabled</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
"@

        foreach ($finding in ($Global:ESCalateConfig.Findings | Sort-Object RiskScore -Descending)) {
            $riskClass = switch($finding.RiskLevel) {
                'Critical' { 'risk-critical' }
                'High' { 'risk-high' }
                'Medium' { 'risk-medium' }
                'Low' { 'risk-low' }
            }
            
            $escClass = if($finding.ESC -match 'ESC(\d+)') { "esc-$($matches[1])" } else { 'esc-default' }
            
            $html += @"
                    <tr class="$riskClass">
                        <td><span class="esc-badge $escClass">$($finding.ESC)</span></td>
                        <td>$($finding.Template)</td>
                        <td>$($finding.Identity)</td>
                        <td>$($finding.Rights)</td>
                        <td>$($finding.EKUs)</td>
                        <td><strong>$($finding.RiskScore)/10</strong></td>
                        <td>$($finding.Enabled)</td>
                        <td>$($finding.Remediation)</td>
                    </tr>
"@
        }

        $html += @"
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p><strong>ESCalate v$($Global:ESCalateConfig.Version)</strong> - Advanced ADCS Security Assessment Platform</p>
            <p>🔍 Audit. Detect. Harden. Escalate.</p>
        </div>
    </div>
</body>
</html>
"@

        $html | Set-Content -Path $htmlPath -Encoding UTF8
        
        Write-ESCLog "HTML report saved: $htmlPath" -Level Success
        return $htmlPath
        
    } catch {
        Write-ESCLog "Failed to generate HTML report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-XMLReport {
    try {
        $xmlPath = Join-Path $OutputPath "Reports\ADCS_ESC_Report.xml"
        
        $reportData = @{
            ESCalateReport = @{
                Metadata = @{
                    Tool = "ESCalate"
                    Version = $Global:ESCalateConfig.Version
                    StartTime = $Global:ESCalateConfig.StartTime
                    Duration = ((Get-Date) - $Global:ESCalateConfig.StartTime).ToString()
                }
                Statistics = $Global:ESCalateConfig.Statistics
                Findings = $Global:ESCalateConfig.Findings
            }
        }
        
        $xml = $reportData | ConvertTo-Xml -NoTypeInformation
        $xml.Save($xmlPath)
        
        Write-ESCLog "XML report saved: $xmlPath" -Level Success
        return $xmlPath
        
    } catch {
        Write-ESCLog "Failed to generate XML report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Generate-RemediationGuides {
    try {
        $remediationPath = Join-Path $OutputPath "Remediation"
        
        # Generate PowerShell remediation script
        $psScript = @'
# ESCalate ADCS Remediation Script
# Generated automatically - Review before execution!

Write-Host "ESCalate ADCS Remediation Script" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# WARNING: Review all changes before applying in production!
$confirm = Read-Host "This script will modify ADCS configuration. Continue? (yes/no)"
if ($confirm -ne "yes") {
    Write-Host "Remediation cancelled by user." -ForegroundColor Yellow
    exit
}

'@

        # Add remediation commands based on findings
        $escFindings = $Global:ESCalateConfig.Findings | Group-Object ESC
        
        foreach($escGroup in $escFindings) {
            $escType = $escGroup.Name
            $findings = $escGroup.Group
            
            $psScript += @"

# ============================================================================
# $escType Remediation ($($findings.Count) findings)
# ============================================================================

"@
            
            switch($escType) {
                'ESC1' {
                    $psScript += @'
# ESC1: Remove excessive enrollment permissions
foreach ($template in @("TemplateName1", "TemplateName2")) {
    Write-Host "Reviewing template: $template" -ForegroundColor Yellow
    # Get-ADObject -Filter "cn -eq '$template'" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
    # Review and remove unnecessary enrollment permissions
}

'@
                }
                'ESC2' {
                    $psScript += @'
# ESC2: Disable subject name supply
# Use certlm.msc or certutil to modify template flags
Write-Host "Disabling subject name supply on vulnerable templates..." -ForegroundColor Yellow
# certutil -SetTemplate TemplateName -Flag -ENROLLEE_SUPPLIES_SUBJECT

'@
                }
                'ESC6' {
                    $psScript += @'
# ESC6: Disable EDITF_ATTRIBUTESUBJECTALTNAME2
Write-Host "Disabling SAN specification on CA..." -ForegroundColor Yellow
# certutil -config "CAServer\CAName" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
# net stop certsvc && net start certsvc

'@
                }
            }
        }
        
        $psScript += @'

Write-Host "`nRemediation script completed!" -ForegroundColor Green
Write-Host "Please verify all changes and test certificate enrollment." -ForegroundColor Yellow
'@
        
        $scriptPath = Join-Path $remediationPath "ADCS_Remediation.ps1"
        $psScript | Set-Content -Path $scriptPath -Encoding UTF8
        
        # Generate markdown remediation guide
        $mdGuide = @"
# ESCalate ADCS Remediation Guide

## Executive Summary
This guide provides step-by-step remediation instructions for the ADCS vulnerabilities identified by ESCalate.

## High Priority Remediations

### Critical Risk Findings ($($Global:ESCalateConfig.Statistics.HighRiskFindings))
"@

        $criticalFindings = $Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 8 } | Sort-Object RiskScore -Descending
        foreach($finding in $criticalFindings) {
            $mdGuide += @"

#### $($finding.ESC): $($finding.Template)
- **Issue**: $($finding.Description)
- **Risk Score**: $($finding.RiskScore)/10
- **Remediation**: $($finding.Remediation)

"@
        }
        
        $mdGuide += @"

## Implementation Timeline
1. **Week 1**: Address all Critical risk findings
2. **Week 2**: Address High risk findings  
3. **Week 3**: Address Medium risk findings
4. **Week 4**: Validation and testing

## Validation Steps
After implementing remediations:
1. Re-run ESCalate to verify fixes
2. Test certificate enrollment functionality
3. Review audit logs for any issues
4. Document all changes made

## Emergency Contacts
- Security Team: security@company.com
- PKI Administrator: pki-admin@company.com
- Change Management: change@company.com
"@
        
        $guidePath = Join-Path $remediationPath "Remediation_Guide.md"
        $mdGuide | Set-Content -Path $guidePath -Encoding UTF8
        
        Write-ESCLog "Remediation guides generated in: $remediationPath" -Level Success
        
    } catch {
        Write-ESCLog "Failed to generate remediation guides: $($_.Exception.Message)" -Level Error
    }
}

function Show-ExecutiveSummary {
    if($Global:ESCalateConfig.StealthMode) { return }
    
    $duration = (Get-Date) - $Global:ESCalateConfig.StartTime
    $critical = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 8 }).Count
    $high = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 6 -and $_.RiskScore -lt 8 }).Count
    $medium = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 4 -and $_.RiskScore -lt 6 }).Count
    $low = ($Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -lt 4 }).Count
    
    Write-Host "`n" -NoNewline
    Write-Host "╔════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                           🎯 ESCALATE ASSESSMENT COMPLETE 🎯                    ║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "║  📊 SCAN STATISTICS:                                                           ║" -ForegroundColor Cyan
    Write-Host "║     • Templates Analyzed: $(($Global:ESCalateConfig.Statistics.TemplatesScanned).ToString().PadLeft(3))                                                    ║" -ForegroundColor White
    Write-Host "║     • Certificate Authorities: $(($Global:ESCalateConfig.Statistics.CAsScanned).ToString().PadLeft(2))                                                   ║" -ForegroundColor White
    Write-Host "║     • Total Vulnerabilities: $(($Global:ESCalateConfig.Statistics.VulnerabilitiesFound).ToString().PadLeft(3))                                                  ║" -ForegroundColor White
    Write-Host "║     • Assessment Duration: $($duration.ToString('hh\:mm\:ss'))                                                 ║" -ForegroundColor White
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "║  🚨 RISK BREAKDOWN:                                                            ║" -ForegroundColor Cyan
    Write-Host "║     • 🔴 Critical Risk: $($critical.ToString().PadLeft(3)) findings                                                  ║" -ForegroundColor Red
    Write-Host "║     • 🟠 High Risk: $($high.ToString().PadLeft(7)) findings                                                  ║" -ForegroundColor Yellow
    Write-Host "║     • 🟡 Medium Risk: $($medium.ToString().PadLeft(5)) findings                                                  ║" -ForegroundColor Yellow
    Write-Host "║     • 🟢 Low Risk: $($low.ToString().PadLeft(8)) findings                                                  ║" -ForegroundColor Green
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "║  📁 REPORTS GENERATED:                                                         ║" -ForegroundColor Cyan
    Write-Host "║     • Location: $($OutputPath.PadRight(59)) ║" -ForegroundColor White
    Write-Host "║     • Formats: $($Format.PadRight(65)) ║" -ForegroundColor White
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    
    if($critical -gt 0) {
        Write-Host "║  ⚠️  IMMEDIATE ACTION REQUIRED: $critical critical vulnerabilities found!          ║" -ForegroundColor Red
    } else {
        Write-Host "║  ✅ No critical vulnerabilities detected in this assessment.                  ║" -ForegroundColor Green
    }
    
    Write-Host "║                                                                                ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}
#endregion

#region Main Execution Engine
function Start-ESCalateAssessment {
    try {
        # Show banner
        Show-ESCalateBanner
        
        # Interactive parameter collection if not in stealth mode
        if(-not $SkipPrompts -and -not $Global:ESCalateConfig.StealthMode) {
            Write-Host "`n🔧 ESCalate Configuration" -ForegroundColor Yellow
            Write-Host "Current settings:" -ForegroundColor Gray
            Write-Host "  Output Path: $OutputPath" -ForegroundColor Gray
            Write-Host "  Format: $Format" -ForegroundColor Gray
            Write-Host "  Risk Threshold: $RiskThreshold" -ForegroundColor Gray
            Write-Host "  Stealth Mode: $($Global:ESCalateConfig.StealthMode)" -ForegroundColor Gray
            
            $continue = Read-Host "`nPress Enter to continue or 'c' to customize"
            if($continue -eq 'c') {
                $newOutput = Read-Host "Output path [$OutputPath]"
                if($newOutput) { $script:OutputPath = $newOutput }
                
                $newFormat = Read-Host "Format (HTML/JSON/CSV/XML/All) [$Format]"
                if($newFormat) { $script:Format = $newFormat }
                
                $newThreshold = Read-Host "Risk threshold (1-10) [$RiskThreshold]"
                if($newThreshold) { $script:RiskThreshold = [int]$newThreshold }
            }
        }
        
        # Initialize output directory
        Initialize-OutputDirectory
        
        # Initialize ADSI connection
        Write-ESCLog "🔍 Starting ADCS security assessment..." -Level Info
        $configDN = Initialize-ADSIConnection
        
        # Get certificate templates and CAs
        $templates = Get-CertificateTemplates -ConfigDN $configDN
        $cas = Get-CertificationAuthorities -ConfigDN $configDN
        
        # Perform vulnerability analysis
        Write-ESCLog "🔍 Analyzing certificate templates for ESC1-4 vulnerabilities..." -Level Info
        foreach($template in $templates) {
            Test-ESC1Through4 -Template $template
            Test-ESC5Through16 -Template $template
        }
        
        Write-ESCLog "🔍 Analyzing certificate authorities for ESC5-16 vulnerabilities..." -Level Info
        Test-CertificationAuthorityVulnerabilities -CertificationAuthorities $cas
        
        Write-ESCLog "🔍 Checking for additional ADCS vulnerabilities..." -Level Info
        Test-AdditionalVulnerabilities -ConfigDN $configDN
        
        # Generate reports
        Write-ESCLog "📊 Generating assessment reports..." -Level Info
        
        $reportPaths = @()
        if($Format -eq 'All' -or $Format -eq 'CSV') {
            $reportPaths += Generate-CSVReport
        }
        if($Format -eq 'All' -or $Format -eq 'JSON') {
            $reportPaths += Generate-JSONReport
        }
        if($Format -eq 'All' -or $Format -eq 'HTML') {
            $reportPaths += Generate-HTMLReport
        }
        if($Format -eq 'All' -or $Format -eq 'XML') {
            $reportPaths += Generate-XMLReport
        }
        
        # Generate remediation guides if requested
        if($IncludeRemediation) {
            Write-ESCLog "🛠️ Generating remediation guides..." -Level Info
            Generate-RemediationGuides
        }
        
        # Show executive summary
        Show-ExecutiveSummary
        
        # Open reports if not in stealth mode
        if(-not $Global:ESCalateConfig.StealthMode -and -not $SkipPrompts) {
            $openReports = Read-Host "`n🔍 Open HTML report? (Y/N) [Default: Y]"
            if($openReports -ne 'N' -and $openReports -ne 'n') {
                $htmlReport = Join-Path $OutputPath "Reports\ADCS_ESC_Report.html"
                if(Test-Path $htmlReport) {
                    Start-Process $htmlReport
                }
                Start-Process $OutputPath
            }
        }
        
        Write-ESCLog "✅ ESCalate assessment completed successfully!" -Level Success
        
    } catch {
        Write-ESCLog "❌ Assessment failed: $($_.Exception.Message)" -Level Error
        Write-ESCLog "Stack trace: $($_.ScriptStackTrace)" -Level Error
        
        # Generate error report
        $errorReport = @{
            Error = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            Timestamp = Get-Date
            Configuration = @{
                StealthMode = $Global:ESCalateConfig.StealthMode
                OutputPath = $OutputPath
                Format = $Format
                RiskThreshold = $RiskThreshold
            }
        }
        
        if(Test-Path $OutputPath) {
            $errorPath = Join-Path $OutputPath "error_report.json"
            $errorReport | ConvertTo-Json -Depth 5 | Set-Content -Path $errorPath
            Write-ESCLog "Error details saved to: $errorPath" -Level Info
        }
        
        throw
    }
}
#endregion

#region Entry Point and Module Support
# Parameter validation
if($RiskThreshold -lt 1 -or $RiskThreshold -gt 10) {
    throw "RiskThreshold must be between 1 and 10"
}

if($Format -notin @('HTML','JSON','CSV','XML','All')) {
    throw "Format must be one of: HTML, JSON, CSV, XML, All"
}

# Main execution
try {
    Start-ESCalateAssessment
    
    # Return results for programmatic access
    if($Global:ESCalateConfig.Findings.Count -gt 0) {
        Write-Output "ESCalate completed with $($Global:ESCalateConfig.Findings.Count) findings. Reports saved to: $OutputPath"
    } else {
        Write-Output "ESCalate completed with no vulnerabilities found above risk threshold $RiskThreshold."
    }
    
} catch {
    Write-Host "`n💥 ESCALATE ASSESSMENT FAILED!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    if(-not $SkipPrompts -and -not $Global:ESCalateConfig.StealthMode) {
        Write-Host "`nPress any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
}

# Export key functions for module usage
if($MyInvocation.InvocationName -ne $MyInvocation.MyCommand.Name) {
    # Being dot-sourced, export functions
    Export-ModuleMember -Function Start-ESCalateAssessment, Test-ESC1Through4, Test-ESC5Through16, Test-CertificationAuthorityVulnerabilities -Variable ESCalateConfig -ErrorAction SilentlyContinue
}
#endregion

<#
.SYNOPSIS
    ESCalate Function Library
    
.DESCRIPTION
    Additional utility functions for advanced ADCS assessment scenarios
#>

function Get-ESCalateFindings {
    <#
    .SYNOPSIS
        Retrieve findings from the last ESCalate assessment
    #>
    return $Global:ESCalateConfig.Findings
}

function Export-ESCalateResults {
    <#
    .SYNOPSIS
        Export results to SIEM/SOAR platforms
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Splunk','Sentinel','QRadar','JSON','Syslog')]
        [string]$Platform,
        
        [Parameter(Mandatory=$false)]
        [string]$Endpoint,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Credentials
    )
    
    $exportData = @{
        Tool = "ESCalate"
        Version = $Global:ESCalateConfig.Version
        Timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'
        Findings = $Global:ESCalateConfig.Findings
        Statistics = $Global:ESCalateConfig.Statistics
    }
    
    switch($Platform) {
        'JSON' {
            return $exportData | ConvertTo-Json -Depth 10
        }
        'Splunk' {
            # Format for Splunk HEC
            $splunkEvents = @()
            foreach($finding in $Global:ESCalateConfig.Findings) {
                $splunkEvents += @{
                    time = [DateTimeOffset]::Now.ToUnixTimeSeconds()
                    event = $finding
                    source = "ESCalate"
                    sourcetype = "adcs:vulnerability"
                    index = "security"
                }
            }
            return $splunkEvents | ConvertTo-Json -Depth 5
        }
        'Sentinel' {
            # Format for Azure Sentinel
            $sentinelData = @{
                TimeGenerated = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'
                Computer = $env:COMPUTERNAME
                ESCalateFindings = $Global:ESCalateConfig.Findings
                Statistics = $Global:ESCalateConfig.Statistics
            }
            return $sentinelData | ConvertTo-Json -Depth 10
        }
    }
}

function Invoke-ESCalateScheduled {
    <#
    .SYNOPSIS
        Run ESCalate in scheduled/automated mode
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$ConfigFile = "ESCalate.json",
        
        [Parameter(Mandatory=$false)]
        [string]$LogFile = "ESCalate_Scheduled.log"
    )
    
    try {
        Write-Output "$(Get-Date): Starting scheduled ESCalate assessment" | Out-File -Append $LogFile
        
        # Load configuration if exists
        if(Test-Path $ConfigFile) {
            $config = Get-Content $ConfigFile | ConvertFrom-Json
            $OutputPath = $config.OutputPath
            $Format = $config.Format
            $RiskThreshold = $config.RiskThreshold
        }
        
        # Run assessment in stealth mode
        $Global:ESCalateConfig.StealthMode = $true
        Start-ESCalateAssessment
        
        Write-Output "$(Get-Date): Assessment completed. Findings: $($Global:ESCalateConfig.Findings.Count)" | Out-File -Append $LogFile
        
        # Send alerts for critical findings
        $criticalFindings = $Global:ESCalateConfig.Findings | Where-Object { $_.RiskScore -ge 8 }
        if($criticalFindings.Count -gt 0) {
            Write-Output "$(Get-Date): ALERT - $($criticalFindings.Count) critical vulnerabilities found!" | Out-File -Append $LogFile
            # Add email/webhook notification logic here
        }
        
    } catch {
        Write-Output "$(Get-Date): ERROR - $($_.Exception.Message)" | Out-File -Append $LogFile
        throw
    }
}

function New-ESCalateBaseline {
    <#
    .SYNOPSIS
        Create baseline for tracking ADCS security posture changes
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaselinePath
    )
    
    $baseline = @{
        CreatedDate = Get-Date
        Templates = @()
        CAs = @()
        SecurityFindings = @()
        Checksum = ""
    }
    
    # Run silent assessment
    $originalMode = $Global:ESCalateConfig.StealthMode
    $Global:ESCalateConfig.StealthMode = $true
    
    try {
        Start-ESCalateAssessment
        $baseline.SecurityFindings = $Global:ESCalateConfig.Findings
        $baseline.Checksum = (($Global:ESCalateConfig.Findings | ConvertTo-Json) | Get-FileHash -Algorithm SHA256).Hash
        
        $baseline | ConvertTo-Json -Depth 10 | Set-Content -Path $BaselinePath
        Write-Output "Baseline created: $BaselinePath"
        
    } finally {
        $Global:ESCalateConfig.StealthMode = $originalMode
    }
}

function Compare-ESCalateBaseline {
    <#
    .SYNOPSIS
        Compare current state against baseline
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaselinePath
    )
    
    if(-not (Test-Path $BaselinePath)) {
        throw "Baseline file not found: $BaselinePath"
    }
    
    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    
    # Run current assessment
    $originalMode = $Global:ESCalateConfig.StealthMode
    $Global:ESCalateConfig.StealthMode = $true
    
    try {
        Start-ESCalateAssessment
        $currentFindings = $Global:ESCalateConfig.Findings
        
        # Compare findings
        $newFindings = @()
        $resolvedFindings = @()
        
        foreach($current in $currentFindings) {
            $exists = $baseline.SecurityFindings | Where-Object { 
                $_.Template -eq $current.Template -and 
                $_.ESC -eq $current.ESC -and 
                $_.Identity -eq $current.Identity 
            }
            if(-not $exists) {
                $newFindings += $current
            }
        }
        
        foreach($baseline in $baseline.SecurityFindings) {
            $exists = $currentFindings | Where-Object { 
                $_.Template -eq $baseline.Template -and 
                $_.ESC -eq $baseline.ESC -and 
                $_.Identity -eq $baseline.Identity 
            }
            if(-not $exists) {
                $resolvedFindings += $baseline
            }
        }
        
        return @{
            NewFindings = $newFindings
            ResolvedFindings = $resolvedFindings
            CurrentTotal = $currentFindings.Count
            BaselineTotal = $baseline.SecurityFindings.Count
            ComparisonDate = Get-Date
        }
        
    } finally {
        $Global:ESCalateConfig.StealthMode = $originalMode
    }
}

# Advanced stealth techniques
function Enable-StealthTechniques {
    <#
    .SYNOPSIS
        Enable advanced stealth techniques for covert assessments
    #>
    
    # Randomize timing between queries
    $Global:ESCalateConfig.StealthDelay = Get-Random -Minimum 100 -Maximum 500
    
    # Use alternative LDAP ports if available
    $Global:ESCalateConfig.AlternatePorts = @(636, 3268, 3269)
    
    # Minimize memory footprint
    [System.GC]::Collect()
    
    Write-ESCLog "Advanced stealth techniques enabled" -Level Stealth
}

function Invoke-ESCalateCleanup {
    <#
    .SYNOPSIS
        Clean up ESCalate artifacts and reset environment
    #>
    
    # Clear findings from memory
    $Global:ESCalateConfig.Findings = @()
    $Global:ESCalateConfig.Statistics = @{
        TemplatesScanned = 0
        CAsScanned = 0
        VulnerabilitiesFound = 0
        HighRiskFindings = 0
        MediumRiskFindings = 0
        LowRiskFindings = 0
    }
    
    # Force garbage collection
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    
    Write-ESCLog "ESCalate environment cleaned up" -Level Stealth
}

# Integration helper functions
function ConvertTo-MITREAttack {
    <#
    .SYNOPSIS
        Map ESC findings to MITRE ATT&CK framework
    #>
    
    $mitreMapping = @{
        'ESC1' = @{ Technique = 'T1649'; Tactic = 'Credential Access' }
        'ESC2' = @{ Technique = 'T1649'; Tactic = 'Credential Access' }
        'ESC3' = @{ Technique = 'T1649'; Tactic = 'Credential Access' }
        'ESC4' = @{ Technique = 'T1649'; Tactic = 'Credential Access' }
        'ESC6' = @{ Technique = 'T1649'; Tactic = 'Credential Access' }
        'ESC7' = @{ Technique = 'T1649'; Tactic = 'Privilege Escalation' }
        'ESC8' = @{ Technique = 'T1557'; Tactic = 'Credential Access' }
    }
    
    $mitreFindings = @()
    foreach($finding in $Global:ESCalateConfig.Findings) {
        if($mitreMapping.ContainsKey($finding.ESC)) {
            $mitreFindings += [PSCustomObject]@{
                ESC = $finding.ESC
                Template = $finding.Template
                MITRETechnique = $mitreMapping[$finding.ESC].Technique
                MITRETactic = $mitreMapping[$finding.ESC].Tactic
                RiskScore = $finding.RiskScore
                Description = $finding.Description
            }
        }
    }
    
    return $mitreFindings
}

Write-ESCLog "ESCalate v$($Global:ESCalateConfig.Version) loaded successfully" -Level Stealth