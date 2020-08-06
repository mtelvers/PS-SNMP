
#$data = [byte[]]@(0x3f, 130, 130, 55, 0x83, 0x1, 0x1, 0x1, 0xf)
#$data = [byte[]]@(0x3f, 130, 130, 55, 0x03, 0xf)
#$data = [byte[]]@(0x30, 0x17, 0x2, 0x1, 0x0, 0x4, 0x6, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0xa, 0x2, 0x2, 0x65, 0x2e, 0x2, 0x1, 0x0, 0x2, 0x1, 0x0)

#$data = [Byte[]]@(0x30, 0x27, 0x02, 0x01, 0x00, 0x04,
#    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0,  0x1a, 0x02, 0x02, 0x65, 0x2e, 0x02, 0x01, 0x00,
#    0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06,  0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
#    0x00, 0x05, 0x00)

#$data = [Byte[]]@(0x30, 0x30, 0x02, 0x01, 0x00, 0x04,
#    0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2,  0x23, 0x02, 0x02, 0x65, 0x2e, 0x02, 0x01, 0x00,
#    0x02, 0x01, 0x00, 0x30, 0x17, 0x30, 0x15, 0x06,  0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
#    0x00, 0x04, 0x09, 0x4e, 0x50, 0x49, 0x46, 0x30,  0x30, 0x46, 0x45, 0x34)

Add-Type -TypeDefinition @"
       public enum asn1tag
       {
               asn1_eoc,
               asn1_boolean,
               asn1_integer,
               asn1_bit_string,
               asn1_octet_string,
               asn1_null,
               asn1_oid,
               asn1_object_descriptor,
               asn1_external,
               asn1_real,
               asn1_enumerated,
               asn1_embedded_pdv,
               asn1_utf8string,
               asn1_relative_oid,
               asn1_time,
               asn1_reserved,
               asn1_sequence,
               asn1_set,
               asn1_numeric_string,
               asn1_printable_string,
       }
"@

Add-Type -TypeDefinition @"
       public enum asn1class
       {
               asn1_universal,
               asn1_application,
               asn1_context_specific,
               asn1_private,
       }
"@

Function DecodeBER {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[byte[]] 
		$berInput
	)

	$ret = [PSObject[]]@()
	$length = 0

	for ($i = 0; $i -lt $berInput.length; $i += $length) {
		$tag = [asn1tag]($berInput[$i] -band 0x1f)
		$constructed = [boolean]($berInput[$i] -band 0x20)
		$class = [asn1class](($berInput[$i] -band 0xc0) -shr 6)

		$i++

		if ($tag -eq 31) {
			$tag = 0
			do {
				$tag = ($tag -shl 7) -bor ($berInput[$i] -band 0x7f)
			} while ($berInput[$i++] -band 0x80)
		}

		$length = $berInput[$i] -band 0x7f
		if ($berInput[$i++] -band 0x80) {
			$end = $i + $length
			$length = 0
			for (; $i -lt $end; $i++) {
				$length = ($length -shl 8) -bor $berInput[$i]
			}
		}

		$content = $berInput[$i..($i + $length - 1)]

		if ($constructed) {
			$ret += New-Object PSObject -Property @{class=$class; constructed=$constructed; tag=$tag; content=$content; inner=(DecodeBER $content)}
		} else {
			$ret += New-Object PSObject -Property @{class=$class; constructed=$constructed; tag=$tag; content=$content}
		}
	}

	return ,$ret
}


Function ByteArrayToUInt {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[byte[]] 
		$bytes
	)

	$ret = 0
	for ($i = 0; $i -lt $bytes.length; $i++) {
		$ret = ($ret -shl 8) -bor $bytes[$i]
	}
	return $ret
}

Function UIntToByteArray {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Int] 
		$num
	)

	$ret = [byte[]]@()
	do {
		$ret += [byte]($num -band 0xff)
		$num = $num -shr 8
	} while ($num -gt 0)

	return ,$ret[-1..-($ret.length)]
}

Function ByteArrayToOID {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[byte[]] 
		$bytes
	)

	$ret = ""
	if ($bytes.length -gt 0) {
		$ret += "{0}.{1}" -f [Int]($bytes[0] / 40), [Int]($bytes[0] % 40)
	}

	for ($i = 1; $i -lt $bytes.length;) {
		$arc = 0
		do {
			$arc = ($arc -shl 7) -bor ($bytes[$i] -band 0x7f)
		} while ($bytes[$i++] -band 0x80)
		$ret += "." + $arc.ToString()
	}

	return $ret
}

Function OIDToByteArray {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string] 
		$oid
	)

	$ret = [byte[]]@()
	$split = $oid.split('.');

	if ($split.length -gt 0) {
		$ret += 40 * [byte]$split[0]
	}

	if ($split.length -gt 1) {
		$ret[0] += [byte]$split[1]
	}

	for ($i = 2; $i -lt $split.length; $i++) {
		$arc = [int]$split[$i]
		$tmp = @()
		do {
			if ($tmp.length -eq 0) {
				$tmp += [byte]($arc -band 0x7f)
			} else {
				$tmp += [byte](($arc -band 0x7f) -bor 0x80)
			}
			$arc = $arc -shr 7
		} while ($arc -gt 0)
		$ret += $tmp[-1..-($tmp.length)]
	}

	return $ret
}


Function BERtoSNMP {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[PSObject] 
		$berObj
	)

	if (($berObj[0].class -ne [asn1class]::asn1_universal) -or ($berObj[0].tag -ne [asn1tag]::asn1_sequence) -or ($berObj[0].inner -eq $null)) {
		return $null
	}

	if ( ($berObj[0].inner[0].class -ne [asn1class]::asn1_universal) -or ($berObj[0].inner[0].tag -ne [asn1tag]::asn1_integer) -or
		($berObj[0].inner[1].class -ne [asn1class]::asn1_universal) -or ($berObj[0].inner[1].tag -ne [asn1tag]::asn1_octet_string) -or
		($berObj[0].inner[2].class -ne [asn1class]::asn1_context_specific) -or ($berObj[0].inner[2].tag -gt 4) -or ($berObj[0].inner[2].inner -eq $null)) {
		return $null
	}

	$version = ByteArrayToUInt $berObj[0].inner[0].content
	$community = [System.Text.Encoding]::ASCII.GetString($berObj[0].inner[1].content)
	$pdu = $berObj[0].inner[2].tag

	switch ($pdu) {
		{($_ -eq 0) -or ($_ -eq 2)} {
			$request_id = ByteArrayToUInt $berObj[0].inner[2].inner[0].content
			$error_status = ByteArrayToUInt $berObj[0].inner[2].inner[1].content
			$error_index = ByteArrayToUInt $berObj[0].inner[2].inner[2].content

			if ($berObj[0].inner[2].inner[3].inner -eq $null) {
				return $null
			}

			$values = @{}
			foreach ($varbind in $berObj[0].inner[2].inner[3].inner) {
				if ($varbind.tag -eq [asn1tag]::asn1_sequence) {
					$oid = ByteArrayToOID $varbind.inner[0].content
					switch ($varbind.inner[1].class) {
						"asn1_universal" {
							switch ($varbind.inner[1].tag) {
								"asn1_null" { $values.$oid = $null }
								"asn1_integer" { $values.$oid = ByteArrayToUInt $varbind.inner[1].content }
								"asn1_octet_string" {
									if (($varbind.inner[1].content -gt 128).count -gt 0) {
										$values.$oid = [System.BitConverter]::ToString($varbind.inner[1].content)
									} else {
										$values.$oid = [System.Text.Encoding]::ASCII.GetString($varbind.inner[1].content)
									}
								}
								"asn1_bit_string" { $values.$oid = $varbind.inner[1].content }
								"asn1_oid" { $values.$oid = ByteArrayToOID $varbind.inner[1].content }
								default { Write-Host "Unhandled universal $($varbind.inner[1].tag)" }
							}
						}
						"asn1_application" {
							switch ($varbind.inner[1].tag.value__) {
								0 { $values.$oid = "{0}.{1}.{2}.{3}" -f $varbind.inner[1].content } # IP Address
								1 { $values.$oid = ByteArrayToUInt $varbind.inner[1].content } # Counter32
								2 { $values.$oid = ByteArrayToUInt $varbind.inner[1].content } # Gauge32
								3 { $values.$oid = ByteArrayToUInt $varbind.inner[1].content } # Ticks
								default { Write-Host "Unhandled application $($varbind.inner[1].tag.value__)" [System.BitConverter]::ToString($varbind.inner[1].content) }
							}
						}
						default { Write-Host "Unhandled class" }
					}
				}
			}
			return New-Object PSObject -Property @{version=$version; community=$community; pdu=[Int]$pdu; request_id=$request_id; varbind=$values}
		}
		default { return $null }
	}
}

Function SNMPGetRequesttoBER {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[PSObject] 
		$snmpData
	)

	$ret = [PSObject[]]@()
	foreach ($key in $snmpData.varbind.keys) {
		$tmp = @()
		$tmp += New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_oid; content=(OIDToByteArray $key)}
		$tmp += New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_null; content=$null}
		$ret += New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$true; tag=[asn1tag]::asn1_sequence; content=$null; inner=$tmp}
	}
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$true; tag=[asn1tag]::asn1_sequence; content=$null; inner=$ret})
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_integer; content=(UIntToByteArray 0)}) + $ret
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_integer; content=(UIntToByteArray 0)}) + $ret
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_integer; content=(UIntToByteArray $snmpData.request_id)}) + $ret
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_context_specific; constructed=$true; tag=[asn1tag]0; content=$null; inner=$ret})
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_octet_string; content=[System.Text.Encoding]::ASCII.GetBytes($snmpData.community)}) + $ret
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$false; tag=[asn1tag]::asn1_integer; content=(UIntToByteArray $snmpData.version)}) + $ret
	$ret = ,(New-Object PSObject -Property @{class=[asn1class]::asn1_universal; constructed=$true; tag=[asn1tag]::asn1_sequence; content=$null; inner=$ret})
	return ,$ret
}

Function EncodeBER {
	Param (
		[Parameter(mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[PSObject[]] 
		$berObj
	)

	$bytes = [byte[]]@()
	foreach ($b in $berObj) {

		$bits = (($b.class.value__ -band 0x3) -shl 6)
		if ($b.constructed) {
			$bits = $bits -bor 0x20
		}
		if ($b.tag -lt 31) {
			$bytes += $bits -bor $b.tag.value__
		} else {
			$bytes += $bits -bor 0x1f
			$num = $b.tag
			$tmp = @()
			do {
				$bits = [byte]($num -band 0x7f)
				if ($tmp.length -gt 0) {
					$bits = $bits -bor 0x80
				}
				$tmp += $bits
				$num = $num -shr 7
			} while ($num -gt 0)
			$bytes += $ret[-1..-($ret.length)]
		}

		if ($b.constructed) {
			$content = EncodeBER $b.inner
		} else {
			$content = $b.content
		}

		if ($content.length -lt 127) {
			$bytes += $content.length
		} else {
			$len = UIntToByteArray $content.length
			$bytes += $len.length -band 0x80
			$bytes += $len
		}

		if ($content.length -gt 0) {
			$bytes += $content
		}

	}
	return ,$bytes
}

#$x = DecodeBER $data
#$s = BERtoSNMP $x
#$s
#
#$q = SNMPGetRequesttoBER (New-Object PSObject -Property @{version=0; community="public"; pdu=0; request_id=(Get-Random -Maximum 65535); varbind=@{'1.3.6.1.2.1.1.5.0'=$null} })
#$w = EncodeBER $q
#[System.BitConverter]::ToString($w)


function Get-SNMP {
	<#
		.SYNOPSIS
		Sends a SNMP request

		.EXAMPLE
		Get-SNMP -Server 172.29.0.89 -OIDs @('1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.25.3.2.1.3.1', '1.3.6.1.2.1.43.5.1.1.17.1')
	#>
	Param
	(
		# SNMP server to query
		[Parameter(mandatory = $true,
				HelpMessage = 'Server to query')]
		[ValidateNotNullOrEmpty()]
		[String] 
		$Server,

		# OID
		[Parameter(mandatory = $true,
				HelpMessage = 'Array of OID values to query')]
		[ValidateNotNullOrEmpty()]
		[String[]] 
		$OIDs,

		#SNMP UDP port to send message to. Defaults to 161 if not specified.
		[Parameter(mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1,65535)]
		[UInt16]
		$UDPPort = 161,

		# UDP Timeout in milliseconds.  Defaults to 3000ms
		[Parameter(mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[UInt32]
		$Timeout = 3000
	)

	$ret = $null

	# Convert the string into an IP Address
	$serverIPAddress = [IPAddress]$Server

	# Create an IP End Point
	$serverEndPoint = New-Object System.Net.IPEndPoint($serverIPAddress, $UDPPort)

	# Create a UDP Client Object based upon the endpoint
	$UDPClient = New-Object -TypeName System.Net.Sockets.UdpClient
	$UDPClient.Connect($serverEndPoint);

	# Create a message
	$oidhash = @{}
	$OIDs |% { $oidhash[$_] = $null }
	$getrequest = SNMPGetRequesttoBER (New-Object PSObject -Property @{version=0; community="public"; pdu=0; request_id=(Get-Random -Maximum 65535); varbind=,$oidhash})
	$messsage = EncodeBER $getrequest

	# Send the Message
	$null = $UDPClient.Send($messsage, $messsage.Length)

	$asyncResult = $UDPCLient.BeginReceive($null, $null)
	if ($asyncResult.AsyncWaitHandle.WaitOne($Timeout)) {
		$reply = DecodeBER $UDPClient.EndReceive($asyncResult, [ref]$serverEndPoint)
		$ret = BERtoSNMP $reply
	}

	#Close the connection
	$UDPClient.Close()

	return $ret
}


