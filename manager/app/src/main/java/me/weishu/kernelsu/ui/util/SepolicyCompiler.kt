package me.weishu.kernelsu.ui.util

import java.io.ByteArrayOutputStream
import me.weishu.kernelsu.Natives

// o1s: magiskpolicy-altkume derleyici. ksud `profile set-sepolicy`
// bizde yok (ksudshim shell'dir, ioctl yapamaz); Manager kurallari
// burada derleyip SET_SEPOLICY ioctl'na dogrudan verir.
// Bicim (kernel uapi/supercall.h): [u32 cmd][u32 subcmd] + her arg
// icin [u32 len][baytlar][\0] (len==0 ALL demek).
// Desteklenen: allow/deny/auditallow/dontaudit (tekil izinler;
// kume {} acilir, * ALL olur), permissive/enforce.
// Desteklenmeyen cumle -> null (cagiran duzguncel hata gosterir).
object SepolicyCompiler {
    private const val CMD_NORMAL_PERM = 1
    private const val SUB_ALLOW = 1
    private const val SUB_DENY = 2
    private const val SUB_AUDITALLOW = 3
    private const val SUB_DONTAUDIT = 4
    private const val CMD_TYPE_STATE = 3
    private const val SUB_PERMISSIVE = 1
    private const val SUB_ENFORCE = 2

    private fun ByteArrayOutputStream.w32(v: Int) {
        write(v and 0xFF)
        write((v shr 8) and 0xFF)
        write((v shr 16) and 0xFF)
        write((v shr 24) and 0xFF)
    }

    private fun ByteArrayOutputStream.wstr(s: String) {
        // "*" (ALL) bos arguman olur
        if (s == "*") {
            w32(0)
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
        // '#' yorumlari at, ';' ile bol
        val noComments = rules.lines().joinToString("\n") {
            val i = it.indexOf('#')
            if (i >= 0) it.substring(0, i) else it
        }
        for (raw in noComments.split(';')) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            val tok = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (tok.isEmpty()) continue
            val verb = tok[0]
            val sub = when (verb) {
                "allow" -> SUB_ALLOW
                "deny", "neverallow" -> SUB_DENY
                "auditallow" -> SUB_AUDITALLOW
                "dontaudit" -> SUB_DONTAUDIT
                "permissive", "enforce" -> -1
                else -> return null
            }
            if (sub == -1) {
                // permissive/enforce TYPE;
                if (tok.size != 2) return null
                val tsub = if (verb == "permissive") SUB_PERMISSIVE else SUB_ENFORCE
                out.w32(CMD_TYPE_STATE)
                out.w32(tsub)
                out.wstr(tok[1])
                count++
                continue
            }
            // allow SRC TGT:CLASS PERM... (kume {} acilir)
            if (tok.size < 4) return null
            val src = tok[1]
            val tc = tok[2]
            val ci = tc.indexOf(':')
            if (ci <= 0 || ci == tc.length - 1) return null
            val tgt = tc.substring(0, ci)
            val cls = tc.substring(ci + 1)
            val perms = tok.subList(3, tok.size)
                .filter { it != "{" && it != "}" }
            if (perms.isEmpty()) return null
            for (p in perms) {
                if (p.isEmpty() || p == "{" || p == "}") return null
                out.w32(CMD_NORMAL_PERM)
                out.w32(sub)
                out.wstr(src)
                out.wstr(tgt)
                out.wstr(cls)
                out.wstr(p)
                count++
            }
        }
        if (count == 0) return null
        return out.toByteArray()
    }
}

fun setSepolicy(pkg: String, rules: String): Boolean {
    // o1s: ksud CLI yolu olu (shim ioctl yapamaz); dogrudan ioctl.
    // pkg imzayla ayni kalir (cagiran degismedi), kurallar global uygulanir.
    android.util.Log.i("SepolicyCompiler", "pkg=$pkg rules=" + rules.take(300))
    val batch = SepolicyCompiler.compile(rules)
    if (batch == null) {
        android.util.Log.i("SepolicyCompiler", "compile FAILED (unsupported statement?)")
        return false
    }
    android.util.Log.i("SepolicyCompiler", "compiled ${batch.size} bytes, ioctling")
    val ok = Natives.setSepolicy(batch)
    android.util.Log.i("SepolicyCompiler", "ioctl result=$ok")
    return ok
}
