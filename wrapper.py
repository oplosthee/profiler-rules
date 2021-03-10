import re, yara, argparse

DEPTH_SIZE = 4 # Tabs are used for indenting and set to 4 spaces

parser = argparse.ArgumentParser()
parser.add_argument("-l", "-log", help = "the log file to input to yara", required = True)
parser.add_argument("-r", "-rule", help = "the yara rule to execute on the log file", required = True)
args = parser.parse_args()

yar = None
start_calls = None
log = None

# First, we load the yara rule and the logfile.
with open(args.r, 'r') as file:
    yar = file.read()
    # Find the string marked as $start.
    start_calls = re.findall(r'\$start = "([^\n\r]*)"', yar)

with open(args.l, 'r', encoding='utf-8') as log_file:
    log = [line.rstrip() for line in log_file]

# Next, find all calls in the same scope as $start.
start_depth = -1
found = False
scope = ""
in_tree = False

i = 0
DEBUG_COUNT = 0
DEBUG_MATCHES = []

# Keep track of the index after a $start call so we can continue where we left.
next_index = 0
while i < len(log):
    line = log[i]
    i += 1

    # Gets the indentation (depth) of the current line.
    depth = len(line) - len(line.lstrip())
    
    # Ignore the call summary and other logs outside the tree.
    if "Printing logs" in line:
        in_tree = True

    if "ROOT" in line and not "calls" in line:
        in_tree = False

    # Ignore the call summary and other logs outside the tree.
    #if depth == 0:
    #    continue

    # Find the $start call and store the scope.
    if any(call in line for call in start_calls) and not found:
        found = True
        start_depth = depth
        next_index = i

    # Log all the calls in the same scope (or one level difference, for inlined functions).
    if found and (depth == start_depth or depth == start_depth - DEPTH_SIZE or depth == start_depth + DEPTH_SIZE):
        scope = scope + line.lstrip() + "\n"

    # If we went out of scope, start over.
    if depth < start_depth - DEPTH_SIZE and found and in_tree:
        found = False
        i = next_index

        print(scope)
        # Run the yara rule on the captured scope.
        rule = yara.compile(source=yar)
        matches = rule.match(data=scope)
        print(matches)

        DEBUG_MATCHES = DEBUG_MATCHES + matches
        DEBUG_COUNT = DEBUG_COUNT + len(matches)

        scope = ""
        print("-" * 100)
        print("\n" * 5)

print("Total matches: " + str(DEBUG_COUNT))
print("Matches: " + str(DEBUG_MATCHES))