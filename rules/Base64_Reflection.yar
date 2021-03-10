rule Base64_Reflection
{ 
	meta:
		description = "Detect a Base64 encoded payload being loaded using reflection."
	
	strings:
		$start = "System.Reflection.Assembly.GetType"
		$s1 = "System.Convert.FromBase64String"
		$s2 = "System.Reflection.RuntimeMethodInfo.Invoke"
		$s3 = "System.Reflection.Assembly.Load"
	
	condition:
		all of ($s*)
}