// ESL-003 encoded-exec: an evaluator applied directly to decoded data.
// Gaps are bounded ({0,50}); '.' never crosses a newline, so evaluator and
// decoder must sit on the same line (multi-line staging is a documented gap).
// The leading \b keeps safe or unrelated names out (ast.literal_eval, myexec).
// No \s* between '(' and the gap: '.' already absorbs whitespace, and that
// overlap multiplied regex fibers (10 MiB of 'eval(' + spaces took > 20 s).
// Whitespace runs are bounded too ({0,10}).

rule esl003_py_encoded_exec
{
    meta:
        esl_id = "ESL-003"
        description = "Python exec/eval/compile wrapping a base64/hex/zlib decoder"
    strings:
        $py = /\b(exec|eval|compile)\s{0,10}\(.{0,50}(b64decode|decodebytes|bytes\.fromhex|zlib\.decompress)/
    condition:
        $py
}

rule esl003_js_encoded_exec
{
    meta:
        esl_id = "ESL-003"
        description = "JavaScript eval/Function wrapping atob or a base64 Buffer"
    strings:
        $js = /\b(eval|Function)\s{0,10}\(.{0,50}(atob\s{0,10}\(|Buffer\.from\([^)]{0,50}['"]base64)/
    condition:
        $js
}
