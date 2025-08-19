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


