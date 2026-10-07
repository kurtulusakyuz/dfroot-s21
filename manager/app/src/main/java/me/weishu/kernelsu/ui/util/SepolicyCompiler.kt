package me.weishu.kernelsu.ui.util

import java.io.ByteArrayOutputStream
import me.weishu.kernelsu.Natives

// o1s: magiskpolicy-subset compiler. ksud `profile set-sepolicy`
// does not exist here (ksudshim is shell, cannot ioctl); Manager
// compiles rules and issues SET_SEPOLICY directly.
// Encoding (kernel uapi/supercall.h): [u32 cmd][u32 subcmd], then per
// arg [u32 len][bytes][\0] (len==0 means ALL, NUL still emitted).
// Supported: allow/deny/auditallow/dontaudit (single perms; brace
// groups expanded, * is ALL), permissive/enforce, type/typeattribute.
// Unsupported statement -> null (caller shows an honest error).
object SepolicyCompiler {
    private const val CMD_NORMAL_PERM = 1
    private const val SUB_ALLOW = 1
    private const val SUB_DENY = 2
    private const val SUB_AUDITALLOW = 3
    private const val SUB_DONTAUDIT = 4
    private const val CMD_TYPE_STATE = 3
    private const val SUB_PERMISSIVE = 1
    private const val SUB_ENFORCE = 2
    private const val CMD_TYPE = 4
    private const val CMD_TYPE_ATTR = 5

    private fun ByteArrayOutputStream.w32(v: Int) {
        write(v and 0xFF)
        write((v shr 8) and 0xFF)
        write((v shr 16) and 0xFF)
        write((v shr 24) and 0xFF)
    }

    private fun ByteArrayOutputStream.wstr(s: String) {
        // "*" (ALL) encodes as len 0, but the kernel reader always
        // consumes the trailing NUL, so it must still be emitted.
        if (s == "*") {
            w32(0)
            write(0)
            return
        }
        val b = s.toByteArray(Charsets.UTF_8)
        w32(b.size)
        write(b)
        write(0)
    }

    fun compile(rules: String): ByteArray? {
        val out = ByteArrayOutputStream()
        var count = 0
        // Statements are line-based (';' also splits); a brace group
        // may span lines ({read\nwrite}) -> join by balance.
        val text = rules.replace(';', '\n')
        val stmts = mutableListOf<String>()
        val cur = StringBuilder()
        var depth = 0
        for (rawLine in text.lines()) {
            var line = rawLine
            val ci = line.indexOf('#')
            if (ci >= 0) line = line.substring(0, ci)
            line = line.trim()
            if (line.isEmpty()) continue
            depth += line.count { it == '{' } - line.count { it == '}' }
            cur.append(line).append(' ')
            if (depth <= 0) {
                if (cur.toString().isNotBlank()) stmts.add(cur.toString())
                cur.clear()
                depth = 0
            }
        }
        if (cur.toString().isNotBlank()) stmts.add(cur.toString())
        for (stmt in stmts) {
            val tok = mergeGroups(
                stmt.split(Regex("\\s+")).filter { it.isNotEmpty() })
            if (tok.isEmpty()) continue
            if (!compileStmt(out, tok)) return null
            count++
        }
        if (count == 0) return null
        return out.toByteArray()
    }

    // Compiles one statement (true/false); multi-perm allow
    // produces several records.
    private fun compileStmt(out: ByteArrayOutputStream, tok: List<String>): Boolean {
            val verb = tok[0]
            val sub = when (verb) {
                "allow" -> SUB_ALLOW
                "deny", "neverallow" -> SUB_DENY
                "auditallow" -> SUB_AUDITALLOW
                "dontaudit" -> SUB_DONTAUDIT
                "permissive", "enforce" -> -1
                "type", "typeattribute" -> -2
                else -> return false
            }
            if (sub == -1) {
                // permissive/enforce TYPE
                if (tok.size != 2) return false
                val tsub = if (verb == "permissive") SUB_PERMISSIVE else SUB_ENFORCE
                out.w32(CMD_TYPE_STATE)
                out.w32(tsub)
                out.wstr(tok[1])
                return true
            }
            if (sub == -2) {
                // type NAME ATTR | typeattribute TYPE ATTR
                // (trailing commas are magiskpolicy residue)
                val args = tok.subList(1, tok.size)
                    .map { it.trimEnd(',') }
                    .filter { it.isNotEmpty() }
                if (args.size != 2) return false
                out.w32(if (verb == "type") CMD_TYPE else CMD_TYPE_ATTR)
                out.w32(0)
                out.wstr(args[0])
                out.wstr(args[1])
                return true
            }
            // allow SRC TGT:CLASS PERM... or SRC TGT CLASS PERM...
            // Brace groups expand in EVERY position ({a b} -> cartesian).
            if (tok.size < 4) return false
            val srcs = expandBraces(tok[1])
            val tgt: String
            val cls: String
            val permStart: Int
            val tc = tok[2]
            val ci = tc.indexOf(':')
            if (ci > 0 && ci < tc.length - 1) {
                tgt = tc.substring(0, ci)
                cls = tc.substring(ci + 1)
                permStart = 3
            } else {
                if (tok.size < 5) return false
                tgt = tc
                cls = tok[3]
                permStart = 4
            }
            val tgts = expandBraces(tgt)
            val clss = expandBraces(cls)
            val perms = tok.subList(permStart, tok.size)
                .flatMap { expandBraces(it) }
                .filter { it.isNotEmpty() }
            if (srcs.isEmpty() || tgts.isEmpty() || clss.isEmpty() || perms.isEmpty()) return false
            for (s in srcs) for (t in tgts) for (c in clss) for (p in perms) {
                out.w32(CMD_NORMAL_PERM)
                out.w32(sub)
                out.wstr(s)
                out.wstr(t)
                out.wstr(c)
                out.wstr(p)
            }
            return true
    }

    // "{a b}" -> [a, b]; attached braces stripped; plain token as-is.
    private fun expandBraces(tok: String): List<String> {
        var t = tok.trim()
        if (t.startsWith("{") && t.endsWith("}") && t.length > 2) {
            t = t.substring(1, t.length - 1)
        }
        return t.split(Regex("\\s+"))
            .map { it.trim('{', '}') }
            .filter { it.isNotEmpty() }
    }

    // Space-separated tokens with brace groups merged:
    // [allow, "{a", "b}", x, ...] -> [allow, "{a b}", x, ...].
    private fun mergeGroups(tok: List<String>): List<String> {        val out = mutableListOf<String>()
        var i = 0
        while (i < tok.size) {
            val t = tok[i]
            if (t.startsWith("{") && !t.endsWith("}")) {
                val sb = StringBuilder(t)
                i++
                while (i < tok.size) {
                    sb.append(' ').append(tok[i])
                    if (tok[i].endsWith("}")) break
                    i++
                }
                out.add(sb.toString())
            } else {
                out.add(t)
            }
            i++
        }
        return out
    }
}

fun setSepolicy(pkg: String, rules: String): Boolean {
    // o1s: ksud CLI path is dead (shim cannot ioctl); direct ioctl.
    // pkg signature kept (caller unchanged); rules apply globally.
    android.util.Log.i("SepolicyCompiler", "pkg=$pkg rules=" + rules.take(300))
    val batch = SepolicyCompiler.compile(rules)
    if (batch == null) {
        android.util.Log.i("SepolicyCompiler", "compile FAILED (unsupported statement?)")
        return false
    }
    android.util.Log.i("SepolicyCompiler", "compiled ${batch.size} bytes, ioctling")
    val ret = Natives.setSepolicy(batch)
    android.util.Log.i("SepolicyCompiler", "ioctl ret=$ret")
    return ret >= 0
}
