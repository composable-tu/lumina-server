package org.lumina.utils

import java.security.MessageDigest
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

/**
 * 将用户提交的对象中所有字符串 `trim()` 化
 */
fun <T : Any> T.normalized(): T {
    val obj = this
    val kClass = obj::class

    if (obj is Map<*, *>) {
        return obj.mapValues { (_, value) ->
            when (value) {
                is String -> value.trim()
                is Map<*, *> -> value.normalized()
                is List<*> -> value.normalized()
                else -> value
            }
        } as? T ?: throw LuminaIllegalArgumentException("服务端错误")
    }

    if (obj is List<*>) {
        return obj.map { item ->
            when (item) {
                is String -> item.trim()
                is Map<*, *> -> item.normalized()
                is List<*> -> item.normalized()
                else -> item
            }
        } as? T ?: throw LuminaIllegalArgumentException("服务端错误")
    }

    kClass.memberProperties.forEach { property ->
        property.isAccessible = true
        if (property is kotlin.reflect.KMutableProperty<*>) {
            val value = property.getter.call(obj)
            if (value is String) {
                property.setter.call(obj, value.trim())
            } else if (value is Map<*, *> || value is List<*>) {
                property.setter.call(obj, value.normalized())
            }
        }
    }

    return obj
}

/**
 * 将字节数组转换成十六进制字符串（大写字母）
 */
fun ByteArray.toHashString(): String {
    return joinToString("") { "%02X".format(it) }
}

/**
 * 计算字符串的 SM3 杂凑值并返回杂凑值的 Hex 字符串
 */
fun String.sm3(): String {
    val messageDigest = MessageDigest.getInstance("SM3")
    return messageDigest.digest(this.toByteArray()).toHashString()
}

fun String.base64KeyToHex(): String {
    // 移除 Base64 填充字符
    val base64Clean = this.replace(Regex("=+\$"), "")
    // Base64 查找表
    val lookupTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    // 转换为二进制字符串
    val binaryStr = StringBuilder().apply {
        base64Clean.forEach { char ->
            val pos = lookupTable.indexOf(char)
            if (pos >= 0) {
                append(pos.toString(2).padStart(6, '0'))
            }
        }
    }.toString()

    // 转换为十六进制
    return StringBuilder().apply {
        var i = 0
        while (i + 8 <= binaryStr.length) {
            val byteStr = binaryStr.substring(i, i + 8)
            append(Integer.parseInt(byteStr, 2).toString(16).padStart(2, '0'))
            i += 8
        }
    }.toString().lowercase()
}

// 移除或替换文件名中的非法字符
fun String.sanitizeFilename(): String {
    return this.replace(Regex("[<>:\"/\\\\|?*]"), "_").replace(Regex("\\s+"), " ") // 将多个空格替换为单个空格
        .trim().takeIf { it.isNotEmpty() } ?: "task"
}

