// ESL-002 npm-install-script-exec: a lifecycle script that downloads, pipes
// to a shell, evaluates inline code or carries a URL.
// This namespace is compiled SEPARATELY (yara_engine.compile_script_rules)
// and matched only against the decoded preinstall/install/postinstall
// strings of package.json, never against archive members: a URL in a JS
// file or in "repository"/"homepage" must not fire.
// npm_scripts collapses every whitespace run of a script (any Unicode
// whitespace, TAB and line breaks included) to ONE space before matching, so
// separators here are a literal ' ' and padding cannot push a token out of a
// window. Single spaces also keep the regexes cheap: '\s{1,10}' windows made
// 10 MiB bombs 3-5x slower.
// All strings are nocase: Windows runs CURL.EXE and NODE -E just the same.
// Tool names need a boundary that is not a word byte, '.' or '-' on both
// sides (node-curl, scripts/curl.js, curl-config stay silent), but '/' and
// '\' before them are fine (/usr/bin/curl). '.exe' is allowed after them.
// The pipe must be a single '|' ('a || b' is a fallback, not a pipe). Pipe
// targets include node/nodejs ('base64 -d | node' runs stdin as code);
// 'node < file' (stdin redirection) is a documented gap.
// Every window is bounded and each token run is followed by a disjoint
// class ([^ ] then ' '), so 10 MiB newline-free scripts stay linear.
// node -e / -p / --eval / --print is NOT matched here: npm_scripts applies a
// token rule (a node word, then an eval flag word anywhere later in the same
// script string), because node options take values of any shape and number,
// and a value window in a regex let every 'node' hit chain over the next ones
// (20 s on 10 MiB of 'node -r '). That rule emulates no shell: it
// ignores separators and quoting, so it may over-fire when the -e/-p belongs
// to a later command ('node install.js && echo -e done').
// PowerShell: a flag that is a prefix of -EncodedCommand (-e, -ec, -en,
// -enc, ...) or of -EncodedArguments, introduced by '-', '/' or an en dash,
// em dash or horizontal bar (U+2013..U+2015, matched as UTF-8 bytes),
// anywhere after the first powershell/pwsh word. -Encoding and -Environment
// do not fire. A token window between the two cost 4-9 s on 10 MiB of
// 'powershell a ', so the order is checked in the condition instead of in
// one regex: the LAST flag after the FIRST word. Flag strings are split by
// introducer: a '[-/]' class left too short an atom (YARA's "may slow down
// scanning" warning). npm_scripts does not count $enc_* in match_count.
// Documented gaps: npx (not matched: 'npx only-allow pnpm' is a common
// benign preinstall); inline code of other interpreters (python -c, perl -e,
// bun -e, deno eval); sh -c / bash -c without a download tool or URL; shell
// quoting tricks that split a word (c''url, c\url, $'\x63url', n''ode,
// -''e); node reading code from stdin ('node < file').

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
        $pipe = /(^|[^|])\| ?(sudo )?([\w.\/-]{0,40}\/)?(sh|bash|zsh|dash|ksh|powershell|pwsh|cmd|node|nodejs)(\.exe|\.cmd)?([^\w.-]|$)/ nocase
    condition:
        $pipe
}

rule esl002_powershell_encoded
{
    meta:
        esl_id = "ESL-002"
        description = "install script runs PowerShell with an encoded command"
    strings:
        $ps = /(^|[^\w.-])(powershell|pwsh)(\.exe)?([^\w.-]|$)/ nocase
        $enc_dash = / -e(c|n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?|a(r(g(u(m(e(n(t(s)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?([^\w-]|$)/ nocase
        $enc_slash = / \/e(c|n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?|a(r(g(u(m(e(n(t(s)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?([^\w-]|$)/ nocase
        $enc_udash = / \xe2\x80[\x93-\x95]e(c|n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?|a(r(g(u(m(e(n(t(s)?)?)?)?)?)?)?)?)?)?)?)?)?)?)?([^\w-]|$)/ nocase
    condition:
        $ps and (
            @enc_dash[#enc_dash] > @ps[1] or
            @enc_slash[#enc_slash] > @ps[1] or
            @enc_udash[#enc_udash] > @ps[1])
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
