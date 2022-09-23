# Event Log Load Test

When incident happen, huge Event Log generated, your SIEM / log collector can catch all of them?

You may need the PowerShell code below to simulate and verify it

===============================================

#create log source name

New-EventLog -LogName 'Application' -Source 'loadtest' -ErrorAction Stop

#prepare long content

1..100 | Foreach-Object {
	$logcontent += "long message "
}

#generate Event Log

for ($num = 1; $num -le 10; $num++)
{
  $logjson = [PSCustomObject]@{
    LoadTestString = "$logcontent part4"
    LoadTestDate = Get-Date
    LoadTestArray = "$logcontent part5"
  } | ConvertTo-Json

  $logjsonbytes = [System.Text.Encoding]::Unicode.GetBytes($logjson)
  $logmessage = "$num - $logcontent part1 `n $logcontent part2 `n $logcontent part3"
  Write-EventLog -LogName Application -Source loadtest -Message $logmessage -EventId 9001 -RawData $logjsonBytes
}

===============================================

#count Event Log in the system

(Get-WinEvent -FilterHashTable @{LogName="Application";id=9001}).count
