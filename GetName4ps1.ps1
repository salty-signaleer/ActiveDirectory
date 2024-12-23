# Import the Active Directory module
Import-Module ActiveDirectory

# Function to get valid AD user
function Get-ValidADUser {
    param (
        [string]$Domain
    )
    do {
        $userName = Read-Host "Enter the username to manage this computer (or press Enter to skip)"
        if ($userName -eq "") { return $null }
        try {
            $user = Get-ADUser -Identity $userName -Server $Domain -ErrorAction Stop
            return $user
        } catch {
            Write-Host "User not found. Please try again." -ForegroundColor Yellow
        }
    } while ($true)
}

# Function to get all usernames from full name in the selected domain
function Get-AllUsernames {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FullName,
        [string]$Domain
    )

    # Search for users in the selected domain
    $users = Get-ADUser -Filter "Name -like '*$FullName*' -or DisplayName -like '*$FullName*'" -Properties SamAccountName, UserPrincipalName, DisplayName -Server $Domain -SearchScope Subtree

    if ($users) {
        return $users | Select-Object Name, DisplayName, SamAccountName, UserPrincipalName
    } else {
        return $null
    }
}

# Get the current forest
$forest = Get-ADForest

# Get all domains in the forest
$domains = $forest.Domains

# Display the list of domains
Write-Host "Domains found in the local network:"
$domains | ForEach-Object { Write-Host "- $_" }

# Prompt the user to select a domain
$selectedDomain = $domains | Out-GridView -Title "Select a domain" -OutputMode Single

# Check if a domain was selected
if ($selectedDomain) {
    do {
        Write-Host "`nPlease select an option:"
        Write-Host "1. Search for a user"
        Write-Host "2. Query a computer object"
        Write-Host "3. Exit"
        $choice = Read-Host "Enter your choice (1, 2, or 3)"

        switch ($choice) {
            "1" {
                # User search functionality
                $fullName = Read-Host "Enter the user's full name or part of the name"
                $accounts = Get-AllUsernames -FullName $fullName -Domain $selectedDomain

                if ($accounts) {
                    Write-Host "Found the following accounts in $selectedDomain :"
                    $accounts | Format-Table -AutoSize

                    if ($accounts.Count -eq 1) {
                        $copyToClipboard = Read-Host "Do you want to copy the SamAccountName to clipboard? (Y/N)"
                        if ($copyToClipboard -eq 'Y' -or $copyToClipboard -eq 'y') {
                            $accounts.SamAccountName | Set-Clipboard
                            Write-Host "SamAccountName copied to clipboard: $($accounts.SamAccountName)"
                        }
                    }
                    elseif ($accounts.Count -gt 1) {
                        $copyToClipboard = Read-Host "Do you want to copy a SamAccountName to clipboard? (Y/N)"
                        if ($copyToClipboard -eq 'Y' -or $copyToClipboard -eq 'y') {
                            $selectedAccount = $accounts | Out-GridView -Title "Select an account to copy SamAccountName" -OutputMode Single
                            if ($selectedAccount) {
                                $selectedAccount.SamAccountName | Set-Clipboard
                                Write-Host "SamAccountName copied to clipboard: $($selectedAccount.SamAccountName)"
                            }
                            else {
                                Write-Host "No account selected for copying."
                            }
                        }
                    }
                } else {
                    Write-Host "No users found matching '$fullName' in $selectedDomain"
                }
            }
            "2" {
                # Computer query functionality
                $computerName = Read-Host "Enter the computer name you want to query"

                try {
                    $computer = Get-ADComputer -Identity $computerName -Properties * -Server $selectedDomain -ErrorAction Stop

                    Write-Host "Computer Details:" -ForegroundColor Cyan
                    Write-Host "------------------------"
                    Write-Host "Computer Name: $($computer.Name)"
                    Write-Host "Domain: $selectedDomain"
                    Write-Host "Distinguished Name: $($computer.DistinguishedName)"
                    Write-Host "Operating System: $($computer.OperatingSystem)"
                    Write-Host "Last Logon Date: $($computer.LastLogonDate)"
                    Write-Host "Enabled: $($computer.Enabled)"
                    Write-Host "Created: $($computer.Created)"
                    Write-Host "Modified: $($computer.Modified)"
                    Write-Host "Description: $($computer.Description)"
                    Write-Host "DNS Hostname: $($computer.DNSHostName)"

                    if ($computer.ManagedBy) {
                        $managedBy = Get-ADObject -Identity $computer.ManagedBy -Properties DisplayName -Server $selectedDomain
                        Write-Host "Managed By: $($managedBy.DisplayName)"
                    } else {
                        Write-Host "Managed By: Not specified"
                    }

                    Write-Host "------------------------"

                    $updateDesc = Read-Host "Do you want to update the Description? (Y/N)"
                    if ($updateDesc -eq "Y") {
                        $newDesc = Read-Host "Enter new Description"
                        Set-ADComputer -Identity $computerName -Description $newDesc -Server $selectedDomain
                        Write-Host "Description updated successfully." -ForegroundColor Green
                    }

                    $updateManaged = Read-Host "Do you want to update the Managed By field? (Y/N)"
                    if ($updateManaged -eq "Y") {
                        $newManager = Get-ValidADUser -Domain $selectedDomain
                        if ($newManager) {
                            Set-ADComputer -Identity $computerName -ManagedBy $newManager -Server $selectedDomain
                            Write-Host "Managed By updated successfully to $($newManager.Name)." -ForegroundColor Green
                        } else {
                            Write-Host "Managed By field not updated." -ForegroundColor Yellow
                        }
                    }

                    $updatedComputer = Get-ADComputer -Identity $computerName -Properties Description, ManagedBy -Server $selectedDomain
                    Write-Host "`nUpdated Computer Details:" -ForegroundColor Cyan
                    Write-Host "------------------------"
                    Write-Host "Description: $($updatedComputer.Description)"
                    if ($updatedComputer.ManagedBy) {
                        $updatedManagedBy = Get-ADObject -Identity $updatedComputer.ManagedBy -Properties DisplayName -Server $selectedDomain
                        Write-Host "Managed By: $($updatedManagedBy.DisplayName)"
                    } else {
                        Write-Host "Managed By: Not specified"
                    }
                    Write-Host "------------------------"
                }
                catch {
                    Write-Host "Error: Unable to find computer '$computerName' in the selected domain ($selectedDomain)." -ForegroundColor Red
                    Write-Host "Please check the computer name and ensure you have the necessary permissions." -ForegroundColor Yellow
                }
            }
            "3" {
                Write-Host "Exiting script." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Yellow
            }
        }

        $continue = Read-Host "`nDo you want to perform another action? (Y/N)"
    } while ($continue -eq "Y" -or $continue -eq "y")
} else {
    Write-Host "No domain selected. Exiting script." -ForegroundColor Yellow
}
