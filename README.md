# profiler-rules
A list of YARA rules written for the output of my .NET profiler (https://github.com/oplosthee/dotnet-profiler)

The Python wrapper script should be used when executing these rules on the output. The Python script ensures that the rules are applied to the correct scopes within the output. In case this is not done, the YARA rules will be applied across the entire output.
