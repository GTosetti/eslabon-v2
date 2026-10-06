// ESL-002 npm-install-script-exec: a lifecycle script that downloads, pipes
// to a shell, evaluates inline code or carries a URL.
// This namespace is compiled SEPARATELY (yara_engine.compile_script_rules)
// and matched only against the decoded preinstall/install/postinstall
// strings of package.json, never against archive members: a URL in a JS
// file or in "repository"/"homepage" must not fire.
// All strings are nocase: Windows runs CURL.EXE and NODE -E just the same.
// Tool names need a boundary that is not a word byte, '.' or '-' on both
// sides (node-curl, scripts/curl.js, curl-config stay silent), but '/' and
// '\' before them are fine (/usr/bin/curl). '.exe' is allowed after them.
// The pipe must be a single '|' ('a || b' is a fallback, not a pipe).
// Every window is bounded and each token run is followed by a disjoint
// class (\S then \s), so 10 MiB newline-free scripts stay linear.
// PowerShell: an -e/-ec/-enc.../-EncodedCommand flag (or /e...) anywhere
// after the first powershell/pwsh word. A token window between the two cost
// 4-9 s on 10 MiB of 'powershell a ', so the order is checked in the
// condition instead of in one regex: the LAST flag after the FIRST word.
// Flag strings are split by separator: a single '\s[-/]' class left too
// short an atom (YARA's "may slow down scanning" warning). The flag must
// follow a space: a TAB before it is a documented gap. npm_scripts does not
// count $enc_* instances in match_count.
// npx is not matched: 'npx only-allow pnpm' is a common benign preinstall.

rule esl002_download_tool
{
    meta:
        esl_id = "ESL-002"
        description = "install script runs a download tool"
    strings:
        $dl = /(^|[^\w.-])(curl|wget|invoke-webrequest|iwr|certutil|bitsadmin)(\.exe)?([^\w.-]|$)/ nocase
    condition:
        $dl
}

rule esl002_pipe_to_shell
{
    meta:
        esl_id = "ESL-002"
        description = "install script pipes into a shell"
    strings:
        $pipe = /(^|[^|])\|\s{0,10}(sudo\s{1,10})?([\w.\/-]{0,40}\/)?(sh|bash|zsh|dash|ksh|powershell|pwsh|cmd)(\.exe)?([^\w.-]|$)/ nocase
    condition:
        $pipe
}

rule esl002_inline_eval
{
    meta:
        esl_id = "ESL-002"
        description = "install script evaluates inline code (node -e, powershell -enc)"
    strings:
        $node = /(^|[^\w.-])node(js)?(\.exe)?(\s{1,10}-\S{1,40}){0,3}\s{1,10}(-[ep]{1,2}|--eval|--print)([^\w-]|$)/ nocase
        $ps = /(^|[^\w.-])(powershell|pwsh)(\.exe)?([^\w.-]|$)/ nocase
        $enc_dash = / -e(c|n[a-z]{0,12})?([^\w-]|$)/ nocase
        $enc_slash = / \/e(c|n[a-z]{0,12})?([^\w-]|$)/ nocase
    condition:
        $node or ($ps and (
            @enc_dash[#enc_dash] > @ps[1] or
            @enc_slash[#enc_slash] > @ps[1]))
}

rule esl002_url
{
    meta:
        esl_id = "ESL-002"
        description = "install script carries a URL"
    strings:
        $url = /https?:\/\// nocase
    condition:
        $url
}
