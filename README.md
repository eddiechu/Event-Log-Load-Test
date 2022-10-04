# Windows Event Log Load Test

When incident happen, huge Event Log generated, your SIEM / log collector can catch all of them?

![alt text](https://github.com/eddiechu/Event-Log-Load-Test/blob/main/eventlog4.gif?raw=true)

There are few factors

1. How to collect the Event Log, by GetEventLogs, EntryWrittenEventHandler or others

2. By which protocal, UDP or TCP

You can verify it with the PowerShell code below.

How it works:

### 1. Load Event Log EntryWrittenEventHandler (in PowerShell) - Catch all generated Event Log

```
$code = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Globalization;
using System.Net.NetworkInformation;

namespace EntryWritten1
{
    public static class GlobalVar
    {
        // UDP client source port
        public static UdpClient udpClient = new UdpClient(65524);
        public static int messagecount = 0;
    }
	
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
            Console.WriteLine("Written: " + e.Entry.Message.Substring(0,42) + " ... " + e.Entry.Message.Substring(e.Entry.Message.Length-22));
			
	    // send to syslog server, udp or tcp
	    // String syslogserver = "172.16.0.100";
	    // Int32 syslogport = 514;
	    // GlobalVar.messagecount = GlobalVar.messagecount + 1;
	    // SendUDP(e.Entry.Message, syslogserver, syslogport);
	    // SendTCP(e.Entry.Message, syslogserver, syslogport);
        }

	public static void SendUDP(String logmessage, String syslogserver, Int32 syslogport)
	{
	    Console.WriteLine("SendUDP to " + syslogserver + " port " + syslogport + " ...");
	    GlobalVar.udpClient.Connect(syslogserver, syslogport);
	    String message="<14>" + DateTime.Now.ToString("MMM d HH:mm:ss") + " " + Dns.GetHostName() + "." + IPGlobalProperties.GetIPGlobalProperties().DomainName + " " + "EntryWrittenEventHandler" + " 1 " + logmessage + " " + GlobalVar.messagecount;
	    Byte[] sendBytes = Encoding.ASCII.GetBytes(message);
	    GlobalVar.udpClient.Send(sendBytes, sendBytes.Length);
	    Console.WriteLine(message.Substring(0,20));
	}

	public static void SendTCP(String logmessage, String syslogserver, Int32 syslogport)
	{
	    Console.WriteLine("SendTCP to " + syslogserver + " port " + syslogport + " ...");
	    TcpClient client = new TcpClient(syslogserver, syslogport);
	    String message="<14>" + DateTime.Now.ToString("MMM d HH:mm:ss") + " " + Dns.GetHostName() + "." + IPGlobalProperties.GetIPGlobalProperties().DomainName + " " + "EntryWrittenEventHandler" + " 1 " + logmessage + " " + GlobalVar.messagecount;
	    Byte[] data = System.Text.Encoding.ASCII.GetBytes(message);
	    NetworkStream stream = client.GetStream();
	    stream.Write(data, 0, data.Length);
	    stream.Close();
	    client.Close();
	    Console.WriteLine(message.Substring(0,20));
	}
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp
iex "[EntryWritten1.Program]::Main()"

```

### 2. Generate huge Event Log (in PowerShell (Admin))

Create test Event Source
```
#create event source name
New-EventLog -LogName 'Application' -Source 'loadtest' -ErrorAction Stop
```

Generate logs

You can adjust the number of log, `$total=1000`
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
Write-Host "batchlabel = $batchlabel"

#generate Event Log
$total=1000
for ($num = 1; $num -le $total; $num++)
{
  $sublog = [PSCustomObject]@{
    SublogString = "$logsubcontent part2"
    SublogDate = Get-Date
    SublogArray = "$logsubcontent part3"
  } | ConvertTo-Json

  $sublogbytes = [System.Text.Encoding]::Unicode.GetBytes($sublog)
  $logmessage = "$num of $total - $batchlabel - $logcontent $specialcharacter part1"
  Write-EventLog -LogName Application -Source "loadtest" –EntryType Information -Message $logmessage -EventId 9001 -RawData $sublogbytes
}

#count Event Log stored in Windows
(Get-WinEvent -FilterHashTable @{LogName="Application";id=9001} | Where-Object{$_.Message -like "*$batchlabel*"}).count

```

Delete test Event Source
```
#delete event source name
[System.Diagnostics.EventLog]::DeleteEventSource("loadtest")
```

### 3. Compare the results among Windows Event Log Viewer, your SIEM received log and EntryWrittenEventHandler console






#security #siem #log #eventlog #windows #collector #logcollector #loadtest #windowseventlog #syslog
