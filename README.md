# Windows Event Log Load Test

When incident happen, huge Event Log generated, your SIEM / log collector can catch all of them?

![alt text](https://github.com/eddiechu/Event-Log-Load-Test/blob/main/eventlog.gif?raw=true)

If the log collector read Event Log, it may not able to catch all log when huge log generated and over Event Log max log size.

If the log collector work with EntryWrittenEventHandler, all log can be catched even over Event Log max log size.

You can try:

### 1. Load Event Log EntryWrittenEventHandler (in PowerShell) - View all generated Event Log

```
$code = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Security.Cryptography;

namespace EntryWritten1
{
    public class Program
    {
        public static void Main()
        {
            EventLog myNewLog = new EventLog();
            myNewLog.Log = "Application";
            myNewLog.EntryWritten += new EntryWrittenEventHandler(MyOnEntryWritten);
            myNewLog.EnableRaisingEvents = true;
            Console.WriteLine("Press \'q\' to quit.");
            while (Console.Read() != 'q')
            {
            }
        }
        public static void MyOnEntryWritten(Object source, EntryWrittenEventArgs e)
        {
            Console.WriteLine("Written: " + e.Entry.Message.Substring(0,30) + " ... " + e.Entry.Message.Substring(e.Entry.Message.Length-10));
        }
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp	
iex "[EntryWritten1.Program]::Main()"

```

### 2. Generate huge Event Log (in PowerShell (Admin)), over your Event Log max log size

Create Event Source
```
#create event source
New-EventLog -LogName 'Application' -Source 'loadtest' -ErrorAction Stop
```

Generate logs
You can tune the number of log, ``for ($num = 1; $num -le **2000**; $num++)``
```
#prepare long content
$logcontent=""
1..1000 | Foreach-Object {
  $logcontent += "long message "
}

$logsubcontent=""
1..100 | Foreach-Object {
  $logsubcontent += "sub content "
}

#special character
$specialcharacter=""
#$specialcharacter = "`0 Null, `a Alert, `b Backspace, `e Escape, `f Form feed, `n New line, `r Carriage return, `t Horizontal tab, `u{2195} Unicode escape sequence, `v Vertical tab"

#prepare batch label
$batchlabel = "batch-"
$batchlabel += Get-Date -Format "MMddHHmmss"

#generate Event Log
for ($num = 1; $num -le 2000; $num++)
{
  $sublog = [PSCustomObject]@{
    SublogString = "$logsubcontent part2"
    SublogDate = Get-Date
    SublogArray = "$logsubcontent part3"
  } | ConvertTo-Json

  $sublogbytes = [System.Text.Encoding]::Unicode.GetBytes($sublog)
  $logmessage = "$num - $batchlabel - $logcontent $specialcharacter part1"
  Write-EventLog -LogName Application -Source "loadtest" –EntryType Information -Message $logmessage -EventId 9001 -RawData $sublogbytes
}

Write-Host "batchlabel=$batchlabel"

#count Event Log in the system
(Get-WinEvent -FilterHashTable @{LogName="Application";id=9001} | Where-Object{$_.Message -like "*$batchlabel*"}).count
```

Delete Event Source
```
#count Event Log in the system
(Get-WinEvent -FilterHashTable @{LogName="Application";id=9001}).count
```

### 3. Compare the results among Windows Event Log Viewer, your SIEM received log and EntryWrittenEventHandler console




#security #siem #log #eventlog #windows #collector #logcollector #loadtest #windowseventlog #syslog
