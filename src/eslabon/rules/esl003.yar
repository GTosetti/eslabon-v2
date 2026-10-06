// ESL-003 encoded-exec: an evaluator applied directly to decoded data.
// Gaps are bounded ({0,50}); '.' never crosses a newline, so evaluator and
// decoder must sit on the same line, except for one line break right after
// the '(' (black-style call split). Multi-line staging is a documented gap.
// The leading \b keeps safe or unrelated names out (ast.literal_eval, myexec).
// No \s* between '(' and the gap: '.' already absorbs whitespace, and that
// overlap multiplied regex fibers (10 MiB of 'eval(' + spaces took > 20 s).
// For the same reason the indent after the optional line break is left to
// .{0,50}; whitespace before '(' is bounded ({0,10}).

rule esl003_py_encoded_exec
{
    meta:
        esl_id = "ESL-003"
        description = "Python exec/eval/compile wrapping a base/hex/compression/codecs decoder"
    strings:
        $py = /\b(exec|eval|compile)\s{0,10}\((\r?\n)?.{0,50}(b(16|32|64|85)decode|a85decode|decodebytes|a2b_base64|unhexlify|bytes\.fromhex|(zlib|lzma|bz2|gzip)\.decompress|codecs\.decode)/
    condition:
        $py
}

rule esl003_js_encoded_exec
{
    meta:
        esl_id = "ESL-003"
        description = "JavaScript eval/Function wrapping atob or Buffer.from (any encoding)"
    strings:
        $js = /\b(eval|Function)\s{0,10}\((\r?\n)?.{0,50}(atob\s{0,10}\(|Buffer\.from\s{0,10}\()/
    condition:
        $js
}
