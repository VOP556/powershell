param (
    #the networkid to scan
    $Network = "192.168.5.0/24"
)

#region helper functions
function ConvertTo-BinaryIP {
  <#
    .Synopsis
      Converts a Decimal IP address into a binary format.
    .Description
      ConvertTo-BinaryIP uses System.Convert to switch between decimal and binary format. The output from this function is dotted binary.
    .Parameter IPAddress
      An IP Address to convert.
  #>
 
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Net.IPAddress]$IPAddress
  )
 
  process {  
    return [String]::Join('.', $( $IPAddress.GetAddressBytes() |
      ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') } ))
  }
}

function ConvertTo-DecimalIP {
  <#
    .Synopsis
      Converts a Decimal IP address into a 32-bit unsigned integer.
    .Description
      ConvertTo-DecimalIP takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
    .Parameter IPAddress
      An IP Address to convert.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Net.IPAddress]$IPAddress
  )
 
  process {
    $i = 3; $DecimalIP = 0;
    $IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }
 
    return [UInt32]$DecimalIP
  }
}

function ConvertTo-DottedDecimalIP {
  <#
    .Synopsis
      Returns a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.
    .Description
      ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
    .Parameter IPAddress
      A string representation of an IP address from either UInt32 or dotted binary.
  #>
 
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [String]$IPAddress
  )
  
  process {
    Switch -RegEx ($IPAddress) {
      "([01]{8}.){3}[01]{8}" {
        return [String]::Join('.', $( $IPAddress.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))
      }
      "\d" {
        $IPAddress = [UInt32]$IPAddress
        $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
          $Remainder = $IPAddress % [Math]::Pow(256, $i)
          ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
          $IPAddress = $Remainder
         } )
       
        return [String]::Join('.', $DottedIP)
      }
      default {
        Write-Error "Cannot convert this format"
      }
    }
  }
}

function ConvertTo-MaskLength {
  <#
    .Synopsis
      Returns the length of a subnet mask.
    .Description
      ConvertTo-MaskLength accepts any IPv4 address as input, however the output value 
      only makes sense when using a subnet mask.
    .Parameter SubnetMask
      A subnet mask to convert into length
  #>
 
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]
    [Alias("Mask")]
    [Net.IPAddress]$SubnetMask
  )
 
  process {
    $Bits = "$( $SubnetMask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2) } )" -replace '[\s0]'
 
    return $Bits.Length
  }
}

function ConvertTo-Mask {
  <#
    .Synopsis
      Returns a dotted decimal subnet mask from a mask length.
    .Description
      ConvertTo-Mask returns a subnet mask in dotted decimal format from an integer value ranging 
      between 0 and 32. ConvertTo-Mask first creates a binary string from the length, converts 
      that to an unsigned 32-bit integer then calls ConvertTo-DottedDecimalIP to complete the operation.
    .Parameter MaskLength
      The number of bits which must be masked.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Alias("Length")]
    [ValidateRange(0, 32)]
    $MaskLength
  )
  
  Process {
    return ConvertTo-DottedDecimalIP ([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
  }
}

function Get-NetworkAddress {
  <#
    .Synopsis
      Takes an IP address and subnet mask then calculates the network address for the range.
    .Description
      Get-NetworkAddress returns the network address for a subnet by performing a bitwise AND 
      operation against the decimal forms of the IP address and subnet mask. Get-NetworkAddress 
      expects both the IP address and subnet mask in dotted decimal format.
    .Parameter IPAddress
      Any IP address within the network range.
    .Parameter SubnetMask
      The subnet mask for the network.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Net.IPAddress]$IPAddress,
    
    [Parameter(Mandatory = $true, Position = 1)]
    [Alias("Mask")]
    [Net.IPAddress]$SubnetMask
  )
 
  process {
    return ConvertTo-DottedDecimalIP ((ConvertTo-DecimalIP $IPAddress) -band (ConvertTo-DecimalIP $SubnetMask))
  }
}

function Get-BroadcastAddress {
  <#
    .Synopsis
      Takes an IP address and subnet mask then calculates the broadcast address for the range.
    .Description
      Get-BroadcastAddress returns the broadcast address for a subnet by performing a bitwise AND 
      operation against the decimal forms of the IP address and inverted subnet mask. 
      Get-BroadcastAddress expects both the IP address and subnet mask in dotted decimal format.
    .Parameter IPAddress
      Any IP address within the network range.
    .Parameter SubnetMask
      The subnet mask for the network.
  #>
  
  [CmdLetBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [Net.IPAddress]$IPAddress, 
    
    [Parameter(Mandatory = $true, Position = 1)]
    [Alias("Mask")]
    [Net.IPAddress]$SubnetMask
  )
 
  process {
    return ConvertTo-DottedDecimalIP $((ConvertTo-DecimalIP $IPAddress) -bor `
      ((-bnot (ConvertTo-DecimalIP $SubnetMask)) -band [UInt32]::MaxValue))
  }
}

function Get-NetworkSummary ( [String]$IP, [String]$Mask ) {
  if ($IP.Contains("/")) {
    $Temp = $IP.Split("/")
    $IP = $Temp[0]
    $Mask = $Temp[1]
  }
 
  if (!$Mask.Contains(".")) {
    $Mask = ConvertTo-Mask $Mask
  }
 
  $DecimalIP = ConvertTo-DecimalIP $IP
  $DecimalMask = ConvertTo-DecimalIP $Mask
  
  $Network = $DecimalIP -band $DecimalMask
  $Broadcast = $DecimalIP -bor `
    ((-bnot $DecimalMask) -band [UInt32]::MaxValue)
  $NetworkAddress = ConvertTo-DottedDecimalIP $Network
  $RangeStart = ConvertTo-DottedDecimalIP ($Network + 1)
  $RangeEnd = ConvertTo-DottedDecimalIP ($Broadcast - 1)
  $BroadcastAddress = ConvertTo-DottedDecimalIP $Broadcast
  $MaskLength = ConvertTo-MaskLength $Mask
  
  $BinaryIP = ConvertTo-BinaryIP $IP; $Private = $False
  switch -regex ($BinaryIP) {
    "^1111"  { $Class = "E"; $SubnetBitMap = "1111"; break }
    "^1110"  { $Class = "D"; $SubnetBitMap = "1110"; break }
    "^110"   { 
      $Class = "C"
      if ($BinaryIP -match "^11000000.10101000") { $Private = $true }
      break
    }
    "^10"    { 
      $Class = "B"
      if ($BinaryIP -match "^10101100.0001") { $Private = $true }
      break
    }
    "^0"     { 
      $Class = "A" 
      if ($BinaryIP -match "^0000101") { $Private = $true }
    }
  }   
   
  $NetInfo = New-Object Object
  Add-Member NoteProperty "Network" -Input $NetInfo -Value $NetworkAddress
  Add-Member NoteProperty "Broadcast" -Input $NetInfo -Value $BroadcastAddress
  Add-Member NoteProperty "Range" -Input $NetInfo -Value "$RangeStart - $RangeEnd"
  Add-Member NoteProperty "Mask" -Input $NetInfo -Value $Mask
  Add-Member NoteProperty "MaskLength" -Input $NetInfo -Value $MaskLength
  Add-Member NoteProperty "Hosts" -Input $NetInfo -Value $($Broadcast - $Network - 1)
  Add-Member NoteProperty "Class" -Input $NetInfo -Value $Class
  Add-Member NoteProperty "IsPrivate" -Input $NetInfo -Value $Private
  
  return $NetInfo
}

function Get-NetworkRange( [String]$IP, [String]$Mask ) {
  if ($IP.Contains("/")) {
    $Temp = $IP.Split("/")
    $IP = $Temp[0]
    $Mask = $Temp[1]
  }
 
  if (!$Mask.Contains(".")) {
    $Mask = ConvertTo-Mask $Mask
  }
 
  $DecimalIP = ConvertTo-DecimalIP $IP
  $DecimalMask = ConvertTo-DecimalIP $Mask
  
  $Network = $DecimalIP -band $DecimalMask
  $Broadcast = $DecimalIP -bor ((-bnot $DecimalMask) -band [UInt32]::MaxValue)
 
  for ($i = $($Network + 1); $i -lt $Broadcast; $i++) {
    ConvertTo-DottedDecimalIP $i
  }
}




#region workflow functions


function test-IPAddresses{
    <#
    .Author
      Jörg Zimmermann www.burningmountain.de
    .Synopsis
      Does a icmp ping for all IPs in Network
    .Description
      Scans the arguments multithreaded 
    .Parameter IPAddress
      A range of IPAddresses to scan as [String[]]
    .Parameter maxthreads
      The maximum threads to do the work as Integer - Default = 5
    .Parameter showOffline
      doesn't filter out the offline IPAddresses
    .Parameter showNames
      will resolve the IPAddresses to Names (with -showOffline Offline IPs too)
    .Example
      test-IPAddresses -IPAddresses [String[]] 
      will test all the IPAddresses in the StringArray
      
      [Array[String[]]] | test-IPAddresses 
      will test every StringArray in Pipeline multithreaded
    #>
    [CmdLetBinding()]
    param(
        [Parameter( Mandatory=$true,
                    ValueFromPipeline=$true)]
        [String[]]$IPAddresses,
        [int]$maxthreads = 5,
        [switch]$showOffline = $false,
        [switch]$showNames = $false
    )

    Begin {
      $RunspacePool = [Runspacefactory]::CreateRunspacePool(1,$maxthreads)
      $RunspacePool.open()
      #the job that has to be done
      $ScriptBlock = {
         param (
          [STRING]$IPAddress,
          [bool]$showNames
          )
          $ICMP = " " 
          $Test = Test-Connection -Count 1 -ComputerName $IPAddress -ErrorAction SilentlyContinue
          if ( $Test) {
            $ICMP = "success"
          } 
          $result = New-Object psobject -Property @{
            IPAddress = $IPAddress
            ICMP      = $ICMP
          }
          
          if ($showNames) {
            $NameHost = (Resolve-DnsName -Name $IPAddress -NoHostsFile -Type PTR).NameHost
            $result | Add-Member -MemberType NoteProperty -Name NameHost -Value $NameHost
          }
          return $result
      }
      #the job array
      $Jobs = @()
    }
    Process {
      #the magic
      $IPAddresses | ForEach-Object {
          $Job = [powershell]::Create().addscript($ScriptBlock).addargument($_).addargument($showNames)
          $Job.RunSpacePool = $RunspacePool
          $Jobs += New-Object PSObject -Property @{
              Pipe = $Job
              Result = $Job.BeginInvoke()
          }
      }


    }
    End {
      
      #wait for completion
      Write-Verbose "Waiting.." 
      Do {
          Start-Sleep -Seconds 1
          } While ( $Jobs.Result.IsCompleted -contains $false )
      Write-Verbose "All jobs completed!"

      #get your results
      $Results = @()
      ForEach ($Job in $Jobs){   
          $Results += $Job.pipe.EndInvoke($Job.result)
      }

      
      #check your results
      if ($showOffline) {
        if ($showNames) {
          Write-Output ($Results | Select-Object IPAddress,ICMP,NameHost)
        }else {
          Write-Output ($Results | Select-Object IPAddress,ICMP)
        }
      }
      elseif ($showNames) {
        ($Results.where({$_.ICMP -eq "success"})  | Select-Object IPAddress,ICMP,NameHost)
      }
      else {
        Write-Output ($Results.where({$_.ICMP -eq "success"})  | Select-Object IPAddress,ICMP)
      }
      

      $RunspacePool.close()
    }
}