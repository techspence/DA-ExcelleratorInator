Function Invoke-ExcelleratorInator {
<# 
    .SYNOPSIS 
        A PowerShell script to find where admin/privileged accounts are running Scheduled Tasks and Services.

    .DESCRIPTION
        A common windows security misconfiguration is running Scheduled Tasks or Services as a highly privileged account.
        This can lead to privilege escalation. This script simplifies searching all servers for Scheduled Tasks and Services 
        running as any account in any of the sensitive Active Directory Groups. E.g.: Domain Admins, Account Operators, etc.

    .PARAMETER NoArt
        A switch allowing you to supress printing of the super cool ASCII art. Why would you ever do this?

    .PARAMETER GetTasks
        A switch that tells the script to find Scheduled Tasks.

    .PARAMETER GetServices
        A switch that tells the script to find Services.
    
    .PARAMETER User
        A specific user.

    .PARAMETER Computer
        A specific computer.

    .EXAMPLE
        PS> Invoke-ExcelleratorInator     
    
        Description
        -----------
        Find all Scheduled Tasks and Services on all enabled and online servers running as a user who is a member of a sensitive group.
        This is the same as running DA-ExcelleratorInator -GetTasks -GetServices

    .EXAMPLE
        PS> Invoke-ExcelleratorInator -GetTasks
    
        Description
        -----------
        Find all Scheduled Tasks on all enabled and online servers running as a user who is a member of a sensitive group

    .EXAMPLE
        PS> Invoke-ExcelleratorInator -GetServices

        Description
        -----------
        Find all Services on all enabled and online servers running as a user who is a member of a sensitive group

    .EXAMPLE
        PS> Invoke-ExcelleratorInator -GetServices -User itadmin -Computer SRV01

        Description
        -----------
        Find all Services running as a specific user on a specific server

    .EXAMPLE
        PS> Invoke-ExcelleratorInator -GetTasks -User itadmin -Computer SRV01

        Description
        -----------
        Find all Scheduled Tasks running as a specific user on a specific server
    
    .EXAMPLE
        PS> Invoke-EXcelleratorInator -GetTasks -GetServices -User itadmin

        Description
        -----------
        Find all Scheduled Tasks and Services running as a specific user

    .EXAMPLE
        PS> Invoke-EXcelleratorInator -GetTasks -GetServices -Computer SRV01

        Description
        -----------
        Find all Scheduled Tasks and Services running as a member of any sensitive group on a specific server

    .LINK
        https://github.com/techspence/DA-ExcelleratorInator

    .NOTES
        Inspiration for the name is from: Inspiration for the name: https://www.youtube.com/watch?v=UHnVVEqKmYA. Thanks Brad! :D
        Find-ServiceUser, Find-TaskUser and Invoke-SCHTasks is from https://github.com/voytas75/Find-TaskServiceUser. I've modified
        those functions slightly to fit my needs.
        
        ToDo:
            - Add aditional groups/accounts to sensitive groups list:
                - groups with admin in their name
                - accounts with admin in their name
            - Add ParameterSets to the main function
#>
 
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False, HelpMessage = 'Hide art when running. Why would you even think of doing this?!')]
            [switch]$NoArt,

        [Parameter(Mandatory = $False, HelpMessage = 'Get Scheduled Tasks')]
            [switch]$GetTasks = $True,

        [Parameter(Mandatory = $False, HelpMessage = 'Get Services')]
            [switch]$GetServices = $True,

        [Parameter(Mandatory = $False, HelpMessage = 'A specific user')]
            [string]$User,

        [Parameter(Mandatory = $False, HelpMessage = 'A specific computer')]
            [string]$Computer
    )


$Art = @"
 
██████╗  █████╗       ███████╗██╗  ██╗ ██████╗███████╗██╗     ██╗     ███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ ██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗      ██╔════╝╚██╗██╔╝██╔════╝██╔════╝██║     ██║     ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██║  ██║███████║█████╗█████╗   ╚███╔╝ ██║     █████╗  ██║     ██║     █████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝
██║  ██║██╔══██║╚════╝██╔══╝   ██╔██╗ ██║     ██╔══╝  ██║     ██║     ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗
██████╔╝██║  ██║      ███████╗██╔╝ ██╗╚██████╗███████╗███████╗███████╗███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═════╝ ╚═╝  ╚═╝      ╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝                                                                                                                                                                                                                                                                         
"@

$Author = "Written by: Spencer Alessi (@techspence)"

function Get-SensitiveGroupMembers {
    [cmdletbinding()]
    Param()
    $SensitiveGroups = 'Account Operators','Administrators','Backup Operators','Domain Admins','Domain Controllers','Enterprise Admins','Enterprise Read-only Domain Controllers','Group Policy Creator Owners','Incoming Forest Trust Builders','Microsoft Exchange Servers','Network Configuration Operators','Power Users','Print Operators','Read-only Domain Controllers','Replicators','Schema Admins','Server Operators'
    $SensitiveGroupMembers = @()
    foreach ($Group in $SensitiveGroups){
        $GroupSID = ($wellknownsidinfo | Where-Object {$_.name -match $Group}).SID
        Write-Verbose "Checking '$Group' for members and nested group members"
        $GroupMembers = try { Get-ADGroupMember -Identity $Group -Recursive | Where-Object {$_.objectClass -eq "user"} } catch { Write-Verbose "The group '$Group' was not found" }
        $SensitiveGroupMembers += $GroupMembers
    }
    $SensitiveGroupMembers
}


Function Find-ServiceUser {
    # from https://github.com/voytas75/Find-TaskServiceUser
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true, position = 0)]
        [string[]]
        $computer,

        [parameter(mandatory = $false, position = 1)]
        [string]
        $user,

        [parameter(Mandatory = $false, HelpMessage = 'Turns on the search after the exact username.')]
        [switch]
        $Strict
    )
    $user = $user.trim()
    $computer = $computer.trim()
    $service_ = $false

    try {
        Write-Verbose -Message "Test connection to computer $computer"
        Test-Connection -ComputerName $computer -Count 1 -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Verbose -Message "Error testing connection to computer $($computer.toupper()). Offline?"
        return $null
    }
    if ($Strict) {
        $filter = "startname = '$($user)'"
    }
    else {
        $filter = "startname LIKE '%$($user)%'"
    }
    Write-Verbose -Message "WMI query for system services."
    if ($computer -match $env:COMPUTERNAME) {
        try {
            $service_ = Get-CimInstance -classname win32_service -filter "$filter" -ErrorAction Stop
        } 
        catch {
            Write-Error -Message "Failed local WMI query for system services with Service Logon Account as ""$user"": $_"
        }
        if ($service_) {
            Write-Verbose -Message "Return local WMI query data."
            return $service_
        } else {
            Write-Verbose -Message "NO local WMI query data."
            $out_variable = (Get-Variable service_).Value
            Write-Debug -message "Return data from inside 'Find-ServiceUser': $out_variable" -InformationAction Continue
        }
    }  else {
        try {
            $service_ = Get-CimInstance -classname win32_service -filter "$filter" -ComputerName $computer -ErrorAction Stop
        } 
        catch {
            Write-Error -Message "Failed WMI query for system services with Service Logon Account as ""$user"": $_"
        }
        if ($service_) {
            Write-Verbose -Message "Return WMI query data"
            return $service_
        } else {
            Write-Verbose -Message "NO WMI query data"
            $out_variable = (Get-Variable service_).Value
            Write-Debug -message "Return data from inside 'Find-ServiceUser': $out_variable" -InformationAction Continue
        }
    }
}


Function Find-TaskUser {
    # from https://github.com/voytas75/Find-TaskServiceUser
    [CmdletBinding()]
    param(
        [string]$server,

        [string]$user,

        [switch]$Strict
    )
    process {
        $server = $server.trim()
        $user = $user.trim()
        if ($server -match $env:COMPUTERNAME) {
            Write-Verbose -Message "$server`: Local computer."
            try {
                Write-Verbose -Message "$server`: Try use Get-ScheduledTask."
                if ($Strict) {
                    return Get-ScheduledTask -CimSession $server -ErrorAction stop | Where-Object {$_.Principal.userid -eq $user } | Select-Object @{Name = "Hostname"; Expression = { $_.PSComputerName } }, taskname, @{Name = "Run As User"; Expression = { $_.Principal.userid } }, Author, URI
                }
                return Get-ScheduledTask -CimSession $server -ErrorAction stop | Where-Object {$_.Principal.userid -match $user } | Select-Object @{Name = "Hostname"; Expression = { $_.PSComputerName } }, taskname, @{Name = "Run As User"; Expression = { $_.Principal.userid } }, Author, URI
            }
            catch {
                Write-Verbose -Message "$server`: Get-ScheduledTask error: $_"
                Write-Verbose -Message "$servercls`: Switching to schtasks command."
                if ($Strict) {
                    Invoke-SCHTasks -server $server -user $user -Strict
                } else {
                    Invoke-SCHTasks -server $server -user $user
                }
            }   
        }
        else {
            Write-Verbose -Message "$server`: Remote computer."
            try {
                Write-Verbose -Message "$server`: Test-connection."
                Test-Connection -ComputerName $server -Count 1 -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Verbose -Message "$server`: Test-Connection error: $_"
                return $null
            }
            try {
                Write-Verbose -Message "$server`: No local command Get-ScheduledTask."
                try {
                    Write-Verbose -Message "$server`: Is remote command Get-ScheduledTask ?"
                    Invoke-Command -ComputerName $server -EnableNetworkAccess -ScriptBlock { Get-Command Get-ScheduledTask -ErrorAction stop } -ErrorAction stop | Out-Null
                    try {
                        Write-Verbose -Message "$server`: Try use remote command Get-ScheduledTask."
                        if ($Strict) {
                            $remote_data = Invoke-Command -ComputerName $server -EnableNetworkAccess -ScriptBlock { Get-ScheduledTask -erroraction stop } -erroraction stop | Where-Object {$_.Principal.userid -eq $user } | Select-Object @{Name = "Hostname"; Expression = { $_.PSComputerName } }, taskname, @{Name = "Run As User"; Expression = { $_.Principal.userid } }, Author
                        } else {
                            $remote_data = Invoke-Command -ComputerName $server -EnableNetworkAccess -ScriptBlock { Get-ScheduledTask -erroraction stop } -erroraction stop | Where-Object {$_.Principal.userid -match $user } | Select-Object @{Name = "Hostname"; Expression = { $_.PSComputerName } }, taskname, @{Name = "Run As User"; Expression = { $_.Principal.userid } }, Author
                        }
                        if ($remote_data) {
                            Write-Verbose -Message "$server`: return data from remote command Get-ScheduledTask."
                            return $remote_data
                        }
                        else {
                            Write-Verbose -Message "$server`: NULL."
                            return $null
                        }                        
                    }
                    catch {
                        Write-Verbose -Message "$server`: Error useing remote command Get-ScheduledTask: $_"
                        Write-Verbose -Message "$server`: Switch to SCHTASK."
                        if ($Strict) {
                            $remote_schtask_data = Invoke-SCHTasks -server $server -user $user -Strict
                        } else {
                            $remote_schtask_data = Invoke-SCHTasks -server $server -user $user
                        }
                        return $remote_schtask_data
                    }
                }
                catch {
                    Write-Verbose -Message "$server`: No remote command Get-ScheduledTask: $_"
                    Write-Verbose -Message "$server`: Switch to SCHTASK."
                    if ($Strict) {
                        $remote_schtask_data = Invoke-SCHTasks -server $server -user $user -Strict
                    } else {
                        $remote_schtask_data = Invoke-SCHTasks -server $server -user $user
                    }
                    return $remote_schtask_data
                }
            }
            catch {
                Write-Verbose -Message $_
                return $null
            }
        }
    }
}


Function Invoke-SCHTasks {
    # from https://github.com/voytas75/Find-TaskServiceUser
    [CmdletBinding()]
    param(
        [string]$server,

        [string]$user,

        [switch]$Strict
    )
    process {
        if ($server -match $env:COMPUTERNAME) {
            Write-Verbose -Message "$server : Try use schtasks on local computer"
            try {
                $tasks = Invoke-Expression "schtasks /query /fo csv /v" -ErrorAction Stop
            }
            catch {
                Write-Error -Message "Failed to invoke ""schtasks"": $_"
            }
        }
        else {
            Write-Verbose -Message "$server : Try use schtasks on remote computer"
            $exp_schtasks = "schtasks /Query /S $server /FO CSV /V"
            Write-Verbose $exp_schtasks
            try {
                $tasks = Invoke-Expression $exp_schtasks -ErrorAction Stop
            }
            catch {
                Write-Error -Message "Failed to invoke ""schtasks"": $_"
            }
        } 
        Write-Verbose -Message "$server : Filtering scheduled tasks"
        $header = "HostName", "TaskName", "Next Run Time", "Status", "Logon Mode", "Last Run Time", "Last Result", "Author", "Task To Run", "Start In", "Comment", "Scheduled Task State", "Idle Time", "Power Management", "Run As User", "Delete Task If Not Rescheduled", "Stop Task If Runs X Hours and X Mins", "Schedule", "Schedule Type", "Start Time", "Start Date", "End Date", "Days", "Months", "Repeat: Every", "Repeat: Until: Time", "Repeat: Until: Duration", "Repeat: Stop If Still Running"
        if ($Strict) {
            return $tasks | ConvertFrom-Csv -Header $header | Where-Object { $_."Run As User" -eq $user } | Select-Object hostname, @{Name = "taskname"; Expression = { ($_.TaskName).split("\")[-1] } }, "run as user", author, @{Name = "URI"; Expression = { $_.TaskName } } -Unique
        }
        return $tasks | ConvertFrom-Csv -Header $header | Where-Object { $_."Run As User" -match $user } | Select-Object hostname, @{Name = "taskname"; Expression = { ($_.TaskName).split("\")[-1] } }, "run as user", author, @{Name = "URI"; Expression = { $_.TaskName } } -Unique
    }
}


function Get-Servers {
    [cmdletbinding()]
    Param()
    $Servers = (Get-ADComputer -Filter {Enabled -eq "True" -and OperatingSystem -like "*Server*"} -Properties DNSHostName).DNSHostName
    $OnlineServers = @()
    Foreach ($Server in $Servers){
        $Connect = Test-Connection -ComputerName $Server -Count 1 -Quiet
        if ($Connect){
            Write-Verbose "Testing connection to $Server"
            $OnlineServers += $Server
        }
    }
    $OnlineServers
}


function Find-Tasks {
    [cmdletbinding()]
    Param(
        $CurrentUser,
        $CurrentServer
    )
    $Results = Find-TaskUser -server $CurrentServer -user $CurrentUser
    $Results | Select Hostname, Taskname, Author, 'Run as User'
}


function Find-Services {
    [cmdletbinding()]
    Param(
        $CurrentUser,
        $CurrentServer
    )
    $Results = Find-ServiceUser -computer $CurrentServer -user $CurrentUser
    $Results | Select Name, State, Started, PathName, StartName, PSComputerName
}

if (!$NoArt) {
    Write-Host $Art -ForegroundColor Magenta -NoNewline; Write-Host $Author
}

if ($User) {
    $UserList = $User
} else {
    Write-Host "`n[i] Getting sensitive user list.."
    $UserList = (Get-SensitiveGroupMembers | Sort-Object -Unique).SamAccountName
    Write-Host "[+] Sensitive user list: Done"
}

if ($Computer) {
    $Servers = $Computer
} else {
    Write-Host "`n[i] Getting online server list.."
    $Servers = Get-Servers
    Write-Host "[+] Server list: Done"
}

if ($GetTasks){
    $AllTasks = @()
    Write-Host "`n[i] Getting scheduled task data.."
    foreach ($User in $UserList){
        foreach ($Server in $Servers){
            Write-Verbose "Checking for scheduled tasks on $Server running as $User"
            $TaskList = Find-Tasks -CurrentUser $User -CurrentServer $Server | sort -Property Name -Unique
            $AllTasks += $TaskList
        }
    }
    Write-Host "`n#### TASKS ####"
    $AllTasks | ft -AutoSize
}


if ($GetServices) {
    $AllServices = @()
    Write-Host "`n[i] Getting services data.."
    foreach ($User in $UserList){
        foreach ($Server in $Servers){
            Write-Verbose "Checking for services on $Server running as  $User"
            $ServiceList = Find-Services -CurrentUser $User -CurrentServer $Server | sort -Property Name -Unique
            $AllServices += $ServiceList
        }
    }
    Write-Host "`n#### SERVICES ####"
    $AllServices | ft -AutoSize
}

}