// ESL-001 pypi-install-exec: network access or download-and-run in setup.py.
// The engine applies this namespace only to the setup.py pip would run
// (normalised path 'setup.py' or '<top dir>/setup.py', name not rewritten,
// PyPI only); everywhere else these matches are dropped.
// Python prefix (^|[^.\w]): a bare name, not a method or a longer identifier.
// urlopen/urlretrieve use \b instead, so a dotted module call still fires.
// Modules count only when imported or used (module.attr, import ...,
// from ... import), not when merely named in a comment or a doc.
// Download-and-run: the tool or URL must sit INSIDE the call's parentheses on
// one line: after '(' a run of at most 20 whitespace/bracket bytes (so a
// black-style split such as '(' NL '[' NL still fits), then the first
// argument character, then at most 200 items, each a byte that is not '(',
// ')' or a line break, or one balanced '(...)' of at most 40 such bytes
// (shutil.which('x'), str(x)). So a metadata url='https://' after the call
// closes, or a few lines below it, never completes the match.
// The window excludes '(' on purpose: with only ')' excluded, 10 MiB of
// " os.system(' " made every hit scan 200 bytes of the next ones and YARA
// timed out at 10 s. Now a hit stops at the next call's '('.
// curl/wget need a quote or whitespace after them (curl-config is pycurl's
// build helper, not a download); PowerShell is matched in any case, pwsh as
// a word. The run class and the first-argument class are disjoint, which
// keeps regex fibers linear on padded input.

rule esl001_py_network
{
    meta:
        esl_id = "ESL-001"
        description = "setup.py uses a network primitive at install time"
    strings:
        $call = /\burl(open|retrieve)\s{0,10}\(/
        $mod_use = /(^|[^.\w])(urllib\.request|http\.client)(\.[A-Za-z_]|[ \t]{1,10}import[ \t])/
        $mod_imp = /\bimport[ \t][ \t\w.,]{0,80}\b(urllib\.request|http\.client)\b/
        $requests = /(^|[^.\w])requests\.(get|post)\s{0,10}\(/
        $socket = /(^|[^.\w])socket\.(socket|create_connection)\s{0,10}\(/
    condition:
        any of them
}

rule esl001_py_spawn_download
{
    meta:
        esl_id = "ESL-001"
        description = "setup.py runs a process whose arguments carry a download tool or URL"
    strings:
        $spawn = /(^|[^.\w])(subprocess\.\w{1,20}|os\.(system|popen))\s{0,10}\([\[(\s]{0,20}["'\w]([^()\n]|\([^()\n]{0,40}\)){0,200}(\b(curl|wget)["'\s]|[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]|\bpwsh\b|https?:\/\/)/
    condition:
        $spawn
}
