rule SilentTrinity_NagaStager
{ 
	meta:
		description = "Detects the presence of the C# stager for Silent Trinity, Naga (unobfuscated)."
	
	strings:
		$start = "Naga.ST" fullword
	
	condition:
		all of them
}

rule SilentTrinity_BooRuntime
{
	meta:
		description = "Detects the presence of the Boo Runtime invoking code."

	strings:
		$start = "Boo.Lang.Compiler.CompilerContext.get_GeneratedAssembly"
		$s1 = "Boo.Lang.Runtime.RuntimeServices.Invoke"
		$s2 = "System.Reflection.Emit.DynamicResolver"

	condition:
		all of them
}