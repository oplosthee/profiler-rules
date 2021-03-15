rule Base64_Reflection
{ 
	meta:
		description = "Detect a Base64 encoded payload being loaded using reflection."
	
	strings:
		$start = "System.Convert.FromBase64String"
		$s1 = "System.Reflection.Assembly.Load"
		$s2 = "System.Reflection.Assembly.GetType"
		$s3 = "System.Type.GetMethod"
		$s4 = "System.Reflection.RuntimeMethodInfo.Invoke"
	
	condition:
		all of ($s*)
}