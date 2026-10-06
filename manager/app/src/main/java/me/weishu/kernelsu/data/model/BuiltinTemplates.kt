package me.weishu.kernelsu.data.model

import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.profile.Capabilities

// o1s: yerlesik sablonlar. ksud `profile` komutlari bizde yok
// (shim ioctl yapamaz), o yuzden liste dogrudan buradan gelir.
// NO_NEW_PRIVS YOK (ozel sablon varsayilani root'u olduruyordu).
object BuiltinTemplates {
    private val allCaps: List<Int> = Capabilities.entries.map { it.cap }

    val all: List<TemplateInfo> = listOf(
        TemplateInfo(
            id = "o1s.fullroot",
            name = "Full root",
            description = "uid/gid 0, all capabilities, ksu domain, inherit ns",
            author = "o1s",
            local = true,
            namespace = Natives.Profile.Namespace.INHERITED.ordinal,
            uid = Natives.ROOT_UID,
            gid = Natives.ROOT_GID,
            groups = emptyList(),
            capabilities = allCaps,
            context = Natives.KERNEL_SU_DOMAIN,
            rules = emptyList(),
            flags = emptyList()
        ),
        TemplateInfo(
            id = "o1s.fullroot.global",
            name = "Full root (global ns)",
            description = "same as Full root with global mount namespace",
            author = "o1s",
            local = true,
            namespace = Natives.Profile.Namespace.GLOBAL.ordinal,
            uid = Natives.ROOT_UID,
            gid = Natives.ROOT_GID,
            groups = emptyList(),
            capabilities = allCaps,
            context = Natives.KERNEL_SU_DOMAIN,
            rules = emptyList(),
            flags = emptyList()
        )
    )

    fun byId(id: String): TemplateInfo? = all.find { it.id == id }
}
