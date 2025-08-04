/*
 * Steam Login Helper
 * https://github.com/StefanOltmann/steam-login-helper
 * Copyright (C) 2025 Stefan Oltmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package de.stefan_oltmann.steam

import com.appstractive.jwt.UnsignedJWT
import com.appstractive.jwt.jwt
import com.appstractive.jwt.sign
import com.appstractive.jwt.signatures.rs256
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.operations.Hasher
import io.github.trueangle.knative.lambda.runtime.api.Context
import io.github.trueangle.knative.lambda.runtime.events.apigateway.APIGatewayV2Request
import io.github.trueangle.knative.lambda.runtime.events.apigateway.APIGatewayV2Response
import io.github.trueangle.knative.lambda.runtime.handler.LambdaBufferedHandler
import io.github.trueangle.knative.lambda.runtime.log.Log
import io.github.trueangle.knative.lambda.runtime.log.debug
import io.github.trueangle.knative.lambda.runtime.log.error
import io.github.trueangle.knative.lambda.runtime.log.info
import io.ktor.client.HttpClient
import io.ktor.client.engine.curl.Curl
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.http.ParametersBuilder
import io.ktor.http.decodeURLPart
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import io.ktor.util.encodeBase64
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.getenv
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The main class handling all the logic.
 */
object SteamLoginHandler : LambdaBufferedHandler<APIGatewayV2Request, APIGatewayV2Response> {

    private const val STEAM_LOGIN_URL = "https://steamcommunity.com/openid/login"

    @OptIn(ExperimentalForeignApi::class)
    private val jwtIssuer = getenv("ISSUER")?.toKString() ?: error("ISSUER not set.")

    @OptIn(ExperimentalForeignApi::class)
    private val jwtPrivateKeyBase64 =
        getenv("JWT_PRIVATE_KEY")?.toKString() ?: error("JWT_PRIVATE_KEY not set.")

    @OptIn(ExperimentalEncodingApi::class)
    private val jwtPrivateKey =
        Base64.decode(jwtPrivateKeyBase64)

    @OptIn(ExperimentalForeignApi::class)
    private val salt =
        getenv("SALT")?.toKString() ?: error("SALT not set.")

    @OptIn(ExperimentalForeignApi::class)
    private val allowKeyGeneration =
        getenv("KEY_GENERATION")?.toKString() ?: error("KEY_GENERATION not set.")

    private val httpClient = HttpClient(Curl) {

        // FIXME The call to the Steam server errored
        engine {
            sslVerify = false
        }
    }

    /**
     * This method is called by the AWS Lambda.
     */
    @OptIn(ExperimentalForeignApi::class)
    @Suppress("unused")
    override suspend fun handleRequest(
        input: APIGatewayV2Request,
        context: Context
    ): APIGatewayV2Response {

        try {

            Log.info("Called: ${input.rawPath}")

            if (input.rawPath.startsWith("/login"))
                return handleLogin(input)

            if (input.rawPath.startsWith("/callback"))
                return handleCallback(input)

            if (input.rawPath.startsWith("/keys"))
                return handleGenerateKeys()

            return APIGatewayV2Response(
                statusCode = HttpStatusCode.OK.value,
                body = "Hello from SteamLoginHelper! \uD83D\uDC4B",
                cookies = null,
                headers = null,
                isBase64Encoded = false
            )

        } catch (ex: Throwable) {

            Log.error("An error occurred: " + ex.stackTraceToString())

            return APIGatewayV2Response(
                statusCode = HttpStatusCode.InternalServerError.value,
                body = "Sorry, something went wrong!",
                cookies = null,
                headers = null,
                isBase64Encoded = false
            )
        }
    }

    private fun handleLogin(
        input: APIGatewayV2Request
    ): APIGatewayV2Response {

        /* Case-insensitive header lookup, because API Gateway often lowercases headers. */
        val forwardedHost = input.headers.entries
            .find { it.key.equals("X-Forwarded-Host", ignoreCase = true) }
            ?.value

        val domainName = forwardedHost ?: input.context.domainName

        val redirectUrl = input.queryStringParameters?.get("redirect")

        if (redirectUrl.isNullOrBlank())
            return APIGatewayV2Response(
                statusCode = HttpStatusCode.BadRequest.value,
                headers = null,
                body = "BadRequest: Parameter 'redirect' is missing.",
                isBase64Encoded = false,
                cookies = null
            )

        val redirectUrlEncoded = redirectUrl.encodeURLPathPart()

        val steamLoginUrl = "https://steamcommunity.com/openid/login?" +
            "openid.ns=http://specs.openid.net/auth/2.0" +
            "&openid.mode=checkid_setup" +
            "&openid.return_to=https://$domainName/callback/$redirectUrlEncoded" +
            "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select" +
            "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select"

        /*
         * Respond with a redirect to Steam login
         */
        return APIGatewayV2Response(
            statusCode = HttpStatusCode.Found.value,
            headers = mapOf("Location" to steamLoginUrl),
            body = "Redirecting to Steam login page...",
            isBase64Encoded = false,
            cookies = null
        )
    }

    @OptIn(ExperimentalEncodingApi::class)
    private suspend fun handleCallback(
        input: APIGatewayV2Request
    ): APIGatewayV2Response {

        val stringParams = input.queryStringParameters

        checkNotNull(stringParams) { "queryStringParameters was NULL" }

        val redirectUrl = input.rawPath
            .removePrefix("/callback/")
            .decodeURLPart()

        if (redirectUrl.isBlank())
            error("Invalid redirect URL in path ${input.rawPath}")

        val steamId = validateSteamLogin(stringParams)

        if (steamId == null)
            return APIGatewayV2Response(
                statusCode = HttpStatusCode.Unauthorized.value,
                headers = null,
                body = "Sorry, we couldn't verify your Steam login.",
                isBase64Encoded = false,
                cookies = null
            )

        /*
         * As this point the Steam service confirmed a successful login.
         * We now create a JWT for that.
         */

        val steamIdHash = saltedSha256(steamId)

        val jwt: UnsignedJWT = jwt {
            claims {
                issuer = jwtIssuer
                subject = steamId
                claim("hash", steamIdHash)
            }
        }

        val signedJWT = jwt.sign {
            rs256 {
                der(jwtPrivateKey)
            }
        }

        val jwtString = signedJWT.toString()

        val location = "$redirectUrl?token=$jwtString"

        /*
         * Respond with a redirect to Steam login
         */
        return APIGatewayV2Response(
            statusCode = HttpStatusCode.Found.value,
            headers = mapOf("Location" to location),
            body = "Redirecting to $redirectUrl ...",
            isBase64Encoded = false,
            cookies = null
        )
    }

    private suspend fun handleGenerateKeys(): APIGatewayV2Response {

        if (allowKeyGeneration != "TRUE")
            return APIGatewayV2Response(
                statusCode = HttpStatusCode.NotAcceptable.value,
                headers = null,
                body = "Key generation disabled.",
                isBase64Encoded = false,
                cookies = null
            )

        val keys = CryptographyProvider
            .Default
            .get(RSA.PKCS1)
            .keyPairGenerator(digest = SHA256)
            .generateKey()

        val privateKey = keys.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.Generic)
        val publicKey = keys.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER.Generic)

        Log.info("PRIVATE: " + privateKey.encodeBase64())
        Log.info("PUBLIC: " + publicKey.encodeBase64())

        return APIGatewayV2Response(
            statusCode = HttpStatusCode.OK.value,
            headers = null,
            body = "Generated keys. Check your logs.",
            isBase64Encoded = false,
            cookies = null
        )
    }

    private suspend fun validateSteamLogin(stringParams: Map<String, String>): String? {

        val parametersBuilder = ParametersBuilder()

        for (stringParam in stringParams)
            parametersBuilder.append(stringParam.key, stringParam.value)

        /* Change the openid.mode */
        parametersBuilder["openid.mode"] = "check_authentication"

        val params = parametersBuilder.build()

        val response = httpClient.post(STEAM_LOGIN_URL) {
            setBody(FormDataContent(params))
        }

        if (!response.status.isSuccess()) {

            Log.error("Auth failed: ${response.status} ${response.bodyAsText()}")

            return null
        }

        val responseText = response.bodyAsText()

        return if (responseText.contains("is_valid:true")) {
            params["openid.claimed_id"]?.substringAfterLast("/")
        } else null
    }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun saltedSha256(input: String): String {

        val hasher: Hasher = CryptographyProvider.Default.get(SHA256).hasher()

        val digest = hasher.hash(
            data = (input + salt).encodeToByteArray()
        )

        return digest.toHexString()
    }
}
