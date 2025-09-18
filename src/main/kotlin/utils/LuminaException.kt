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

import io.ktor.server.plugins.*
import javax.security.sasl.AuthenticationException

// 未找到资源异常
class LuminaNotFoundException(message: String): RuntimeException(message)

// 请求参数错误异常
class LuminaBadRequestException(message: String): BadRequestException(message)

// 参数错误异常
class LuminaIllegalArgumentException(s: String): IllegalArgumentException(s)

// 服务端状态异常
class LuminaIllegalStateException(s: String): IllegalStateException(s)

// 安全验证异常
class LuminaAuthenticationException(detail: String): AuthenticationException(detail)


