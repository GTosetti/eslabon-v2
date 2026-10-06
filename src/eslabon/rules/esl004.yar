// ESL-004 secret-exfil: one file that names a credential source AND an
// exfiltration sink. Applied to every member of both ecosystems.
// Credential sources: well-known secret files, as a path (a separator may be
// '/' or one or two backslashes) or as quoted path segments joined by ',' or
// '/' (path.join(h, '.ssh', 'id_rsa'), Path.home() / '.aws' / 'credentials'),
// and serialisation of the WHOLE environment, also when wrapped:
// JSON.stringify of process.env, {...process.env}, Object.entries(process.env)
// or Object.assign({}, process.env); json.dumps of os.environ, dict(os.environ)
// or {**os.environ}; str(os.environ).
// A single variable (JSON.stringify(process.env.NODE_ENV), in every webpack
// bundle) is not a dump: process.env must be followed by ')', '}' or ','. Python
// json.dumps(os.environ[...]) still counts on purpose: one secret is enough.
// Left out deliberately: bare {...process.env}, {**os.environ} and
// Object.entries(process.env) iteration, the idioms that copy the environment
// for a child process.
// Sinks: webhook, paste, tunnel and OAST/interaction hosts, and an http(s)
// URL whose host is an IPv4 literal. The IP string only NOMINATES: the engine
// keeps an instance only if the address is global (no loopback, RFC 1918,
// link-local such as the cloud metadata address, CGNAT, documentation or
// reserved ranges), and drops the finding when no sink survives.
// OAST hosts need a non-label byte before 'oast' so toast libraries
// (toast.message, react-hot-toast) stay silent, and a word boundary after.
// Every pattern is a literal or a bounded regex; no window crosses lines.
// Gaps: a host built by concatenation, an ordinary domain, an integer, hex or
// four-digit IP, a raw socket, a path built from variables.

rule esl004_secret_exfil
{
    meta:
        esl_id = "ESL-004"
        description = "A credential source and an exfiltration sink in the same file"
    strings:
        $cred_ssh = /\.ssh(\/|\\{1,2})id_(rsa|ed25519|ecdsa|dsa)/ nocase
        $cred_aws = /\.aws(\/|\\{1,2})credentials/ nocase
        $cred_npmrc = ".npmrc" nocase
        $cred_pypirc = ".pypirc" nocase
        $cred_git = ".git-credentials" nocase
        $cred_docker = /\.docker(\/|\\{1,2})config\.json/ nocase
        $cred_kube = /\.kube(\/|\\{1,2})config/ nocase
        $cred_ssh_seg = /['"]\.ssh['"]\s{0,10}[,\/]\s{0,10}['"]id_(rsa|ed25519|ecdsa|dsa)/ nocase
        $cred_aws_seg = /['"]\.aws['"]\s{0,10}[,\/]\s{0,10}['"]credentials/ nocase
        $cred_js_env = /JSON\.stringify\(\s{0,10}(\{\s{0,10}\.\.\.\s{0,10}|Object\.entries\(\s{0,10}|Object\.assign\(\s{0,10}\{\s{0,10}\}\s{0,10},\s{0,10})?process\.env\s{0,10}[)},]/
        $cred_py_env = /json\.dumps\(\s{0,10}(dict\(\s{0,10})?os\.environ/
        $cred_py_env_spread = /json\.dumps\(\s{0,10}\{\s{0,10}\*\*\s{0,10}os\.environ\s{0,10}[},]/
        $cred_py_str = /str\(\s{0,10}os\.environ\s{0,10}\)/
        $sink_discord = /discord(app)?\.com\/api\/webhooks/ nocase
        $sink_telegram = /api\.telegram\.org\/bot/ nocase
        $sink_slack = /hooks\.slack\.com/ nocase
        $sink_pastebin = /pastebin\.com/ nocase
        $sink_ngrok = /ngrok(-free)?\.(io|app)\b/ nocase
        $sink_oast = /(^|[^\w-])oast\.(fun|pro|live|site|online|me)\b/ nocase
        $sink_interact = /(^|[^\w-])interact\.sh\b/ nocase
        $sink_burp = /burpcollaborator\.net/ nocase
        $sink_webhook_site = /webhook\.site\b/ nocase
        $sink_requestbin = /requestbin\.(com|net|io|org|fullcontact\.com)\b/ nocase
        $sink_pipedream = /pipedream\.net/ nocase
        $sink_ip = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/ nocase
    condition:
        any of ($cred*) and any of ($sink*)
}
