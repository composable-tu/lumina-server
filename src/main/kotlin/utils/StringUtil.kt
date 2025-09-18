/**
 * Copyright (c) 2025 LuminaPJ
 * SM2 Key Generator is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
package org.lumina.utils

import java.security.MessageDigest

/**
 * 将用户提交的对象中所有字符串 `trim()` 化
 */
fun <T : Any> T.normalized(): T {
    return when (this) {
        is String -> this.trim() as T
        is Map<*, *> -> this.mapValues { (_, value) ->
            when (value) {
                is String -> value.trim()
                is Map<*, *> -> value.normalized()
                is List<*> -> value.normalized()
                else -> value
            }
        } as T

        is List<*> -> this.map { item ->
            when (item) {
                is String -> item.trim()
                is Map<*, *> -> item.normalized()
                is List<*> -> item.normalized()
                else -> item
            }
        } as T

        else -> this
    }
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

/**
 * 移除或替换文件名中的非法字符
 */
fun String.sanitizeFilename(): String {
    return this.replace(Regex("[<>:\"/\\\\|?*]"), "_").replace(Regex("\\s+"), " ") // 将多个空格替换为单个空格
        .trim().takeIf { it.isNotEmpty() } ?: "task"
}

/**
 * 语义化签到任务状态
 */
fun String.semanticsCheckInTaskStatus(): String = when (this) {
    "MARK_AS_PARTICIPANT" -> "标记为已参与"
    "MARK_AS_NOT_PARTICIPANT" -> "标记为未参与"
    "MARK_AS_PENDING" -> "标记为待定"
    "PENDING" -> "待参与"
    "STARTED" -> "进行中"
    "PARTICIPATED" -> "已参与"
    "NOT_REQUIRED" -> "无需参与"
    "EXPIRED" -> "已过期"
    else -> ""
}

/**
 * 语义化任务状态
 */
fun String.semanticsTaskStatus(): String = when (this) {
    "PENDING" -> "待参与"
    "STARTED" -> "进行中"
    "PARTICIPATED" -> "已参与"
    "NOT_REQUIRED" -> "无需参与"
    "EXPIRED" -> "已过期"
    else -> ""
}

/**
 * 语义化签到任务类型
 */
fun String.semanticsCheckInTaskType(): String = when (this) {
    "TOKEN" -> "验证码签到"
    "ORDINARY" -> "普通签到"
    else -> ""
}


