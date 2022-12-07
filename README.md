![image](https://user-images.githubusercontent.com/7014376/206213652-7abb362b-8253-4be4-9fc1-b94d7b6c1bbc.png)

# DA-ExcelleratorInator
A common windows security misconfiguration is running Scheduled Tasks or Services as a highly privileged account. This can lead to privilege escalation. This script simplifies searching all servers for Scheduled Tasks and Services running as any account in any of the sensitive Active Directory Groups. E.g.: Domain Admins, Account Operators, etc.



## Example 1 - All Tasks and Services and all sensitive accounts
```PowerShell
Invoke-DAExcelleratorInator
```

Find all Scheduled Tasks and Services on all enabled and online servers running as a user who is a member of a sensitive group. This is the same as running Invoke-DAExcelleratorInator -GetTasks -GetServices.

## Example 2 - All Tasks and services for a specific account

```PowerShell
Invoke-DAExcelleratorInator -GetTasks -GetServices -User Admin
```

