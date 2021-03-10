// ShellCode.cs
rule SharpSploit_ShellCode
{ 
	meta:
		description = "Detects ShellCode being loaded in memory using SharpSploit (https://github.com/cobbr/SharpSploit/blob/eb58caaba734de9b18450dab493b41d5a9b5464e/SharpSploit/Execution/ShellCode.cs)."
	
	strings:
		$start = "System.Runtime.InteropServices.GCHandle.Alloc"
		$s1 = "System.Runtime.InteropServices.GCHandle.AddrOfPinnedObject"
		$s2 = "System.Runtime.InteropServices.Marshal.Copy"
		$s3 = "System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer"
	
	condition:
		all of ($s*)
}

// Shell.cs
rule SharpSploit_PowerShell
{
    meta:
        description = "Detects PowerShell code being executed by SharpSploit (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Shell.cs)"

    strings:
        $start = "System.Management.Automation.PowerShell..ctor"
        $s1 = "System.Management.Automation.PowerShell.AddScript"
        $s2 = "System.Management.Automation.PowerShell.Invoke"

    condition:
        all of ($s*)
}

rule SharpSploit_PowerShell_BypassGeneric
{
    meta:
        description = "Detects PowerShell code being executed by SharpSploit (including AMSI/ScriptBlock logging bypasses) (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Shell.cs)"

    strings:
        $start = "System.Management.Automation.PowerShell..ctor"
        
        // Bypasses
        $s1 = "System.RuntimeType.get_Assembly"
        $s2 = "System.Reflection.Assembly.GetType"
        $s3 = "System.RuntimeType.GetField"
        $s4 = "System.Reflection.RtFieldInfo.SetValue"
        $s5 = "System.Management.Automation.PowerShell.AddScript"
        $s6 = "System.Management.Automation.PowerShell.Invoke"

    condition:
        all of ($s*)
}

rule SharpSploit_PowerShell_BypassScriptBlockLogging
{
    meta:
        description = "Detects PowerShell code being executed by SharpSploit, specifically including the ScriptBlock Logging bypass (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Shell.cs)"

    strings:
        $start = "System.Management.Automation.PowerShell..ctor"
        
        // Bypasses
        $s1 = "System.RuntimeType.get_Assembly"
        $s2 = "System.Reflection.Assembly.GetType"
        $s3 = "System.RuntimeType.GetField"

        // ScriptBlock Logging bypass specific calls
        $s4 = "System.Guid.NewGuid"
        $s5 = "System.Diagnostics.Eventing.EventProvider..ctor"
        
        $s6 = "System.Reflection.RtFieldInfo.SetValue"
        $s7 = "System.Management.Automation.PowerShell.AddScript"
        $s8 = "System.Management.Automation.PowerShell.Invoke"

    condition:
        all of ($s*)
}

// PE.cs
// Covered in Covenant.yar (Covenant_SharpSploit_PELoad)

// Assembly.cs
// https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Assembly.cs

// AssemblyExecute(byte[])
rule SharpSploit_AssemblyExecute
{
    meta:
        description = "Detects a .NET assembly's EntryPoint being executed by SharpSploit (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Assembly.cs#L22)"

    strings:
        $start = "System.Reflection.Assembly.Load"
        $s1 = "System.Reflection.RuntimeAssembly.get_EntryPoint"
        $s2 = "System.Reflection.RuntimeMethodInfo.Invoke"

    condition:
        all of ($s*)
}

// AssemblyExecute(String)
rule SharpSploit_AssemblyExecute_Base64
{
    meta:
        description = "Detects an encoded .NET assembly's EntryPoint being executed by SharpSploit (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Assembly.cs#L69)"

    strings:
        $start = "System.Convert.FromBase64String"
        $s1 = "System.Reflection.Assembly.Load"
        $s2 = "System.Reflection.RuntimeAssembly.get_EntryPoint"
        $s3 = "System.Reflection.RuntimeMethodInfo.Invoke"

    condition:
        all of ($s*)
}

// AssemblyExecute(byte[], String, String, Object[])
// NOTE: The Base64-encoded variant is defined in Covenant.yar.
rule SharpSploit_AssemblyExecute_Parameters
{ 
	meta:
		description = "Detects a .NET assembly with specified method being executed by SharpSploit (https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/Assembly.cs#L41)."
	
	strings:
		$start = "System.Reflection.Assembly.Load"

		// Loaded assembly is executed on the same thread (singular and plural):	
		$xa2 = "System.Reflection.Assembly.GetType"
		$xb2 = "System.Reflection.Assembly.GetTypes"
		$xa3 = "System.Type.GetMethod"
		$xb3 = "System.Type.GetMethods"
		$x4 = "System.Reflection.RuntimeMethodInfo.Invoke"
		
		// Loaded assembly is executed on a new thread:
        // This does not occur in SharpSploit, Covenant however can do this.
		$y2 = "System.Threading.Thread..ctor"
	
	condition:
		all of ($s*) // Assembly.Load
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

// ------------------

// DynamicInvoke/Generic.cs
// Note: Most methods call unmanaged code which cannot be logged in the tracer's current state.
// The CorProfiler API does however support tracking the transition between managed/unmanaged code.

// https://github.com/cobbr/SharpSploit/blob/c1a4943505ab59ae3ce9857c8182bb186ecff502/SharpSploit/Execution/DynamicInvoke/Generic.cs#L32
// System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer
// System.Delegate.DynamicInvoke

// ------------------

// Injection/Allocation.cs
rule SharpSploit_AllocatePayload
{
    meta:
        description = "Detects a payload being allocated in a process by SharpSploit (https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Execution/Injection/Allocation.cs#L163)"

    strings:
        $start = "System.Diagnostics.Process.GetCurrentProcess"
        $s1 = "System.Diagnostics.Process.get_Handle"
        $s2 = "System.Convert.ToUInt32"
        $s3 = "System.Runtime.InteropServices.Marshal.Copy"

    condition:
        all of ($s*)
}

// Injection/Execution.js
// Note: Expected to see GetType() in logs, but can't be seen. Possibly optimized out.
// Might be too general and result in false positives.
rule SharpSploit_Reflection_MethodInvoke
{
    meta:
        description = "Detects a method being executed using reflection (https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/Execution/Injection/Execution.cs#L66)"

    strings:
        $start = "System.Type.GetMethod"
        $s1 = "System.Reflection.MethodBase.Invoke"

    condition:
        all of ($s*)
}