// Note: This variant can also be found in SharpSploit, including the non-base64 encoded variant.
rule Covenant_Base64_Reflection
{ 
	meta:
		description = "Detects a Base64 encoded payload being loaded using reflection (https://github.com/cobbr/Covenant/blob/5b90f203c2e42c0f0e5607653c71f6fc452adaab/Covenant/Data/Grunt/GruntBridge/GruntBridge.cs#L230)."
	
	strings:
		$start = "System.Convert.FromBase64String"
		$s1 = "System.Reflection.Assembly.Load"

		// Loaded assembly is executed on the same thread (singular and plural):	
		$xa2 = "System.Reflection.Assembly.GetType"
		$xb2 = "System.Reflection.Assembly.GetTypes"
		$xa3 = "System.Type.GetMethod"
		$xb3 = "System.Type.GetMethods"
		$x4 = "System.Reflection.RuntimeMethodInfo.Invoke"
		
		// Loaded assembly is executed on a new thread:
		// Note: There should be another thread in the log containing the same code as above.
		// Checking this using YARA regex can not work as it does not support capture groups.
		$y2 = "System.Threading.Thread..ctor"
	
	condition:
		all of ($s*) // Decoding and Assembly.Load
		and 
		(
			(
				(
					all of ($xa*) // Singular methods
					or 
					all of ($xb*) // Plural methods
				)
				and
				$x4 // The in combination with singular OR plural methods
			)
			or
			all of ($y*) // New thread creation after Load
		)
}

rule Covenant_SharpSploit
{ 
	meta:
		description = "Detects (unobfuscated) general usage of SharpSploit."
	
	strings:
		$start = "SharpSploit" fullword
	
	condition:
		all of them
}

rule Covenant_Rubeus
{ 
	meta:
		description = "Detects (unobfuscated) general usage of Rubeus."
	
	strings:
		$start = "Rubeus" fullword
	
	condition:
		all of them
}
