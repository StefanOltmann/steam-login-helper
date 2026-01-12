/*
 * Steam Login Helper
 * Copyright (C) 2026 Stefan Oltmann
 * https://github.com/StefanOltmann/steam-login-helper
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
import com.appstractive.jwt.UnsignedJWT
import com.appstractive.jwt.jwt
import com.appstractive.jwt.sign
import com.appstractive.jwt.signatures.es256
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.operations.Hasher
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.ParametersBuilder
import io.ktor.http.isSuccess
import io.ktor.http.withCharset
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.origin
import io.ktor.server.request.header
import io.ktor.server.request.uri
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingContext
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.util.encodeBase64
import kotlinx.serialization.ExperimentalSerializationApi
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import kotlin.uuid.ExperimentalUuidApi
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

private const val STEAM_LOGIN_URL = "https://steamcommunity.com/openid/login"

private const val PRIVACY_ROUTE = "/privacy"
private const val CONSENT_TOKEN_TTL_MS = 10 * 60 * 1000L

private val jwtIssuer: String =
    System.getenv("ISSUER") ?: error("ISSUER not set.")

private val jwtPrivateKeyBase64: String =
    System.getenv("JWT_PRIVATE_KEY") ?: error("JWT_PRIVATE_KEY not set.")

private val jwtPrivateKey: ByteArray =
    Base64.decode(jwtPrivateKeyBase64)

private val apiKey: String? =
    System.getenv("API_KEY")

private val allowKeyGeneration: Boolean =
    System.getenv("ALLOW_KEY_GENERATION").equals("true", ignoreCase = true)

private val salt: String =
    System.getenv("SALT") ?: error("SALT not set.")

private val httpClient = HttpClient()

private val consentTokens = ConcurrentHashMap<String, Long>()

@OptIn(ExperimentalSerializationApi::class)
fun Application.configureRouting() {

    try {

        configureRoutingInternal()

    } catch (ex: Throwable) {

        log("Starting server $VERSION failed.")
        log(ex)
    }
}

@OptIn(ExperimentalSerializationApi::class, ExperimentalTime::class, ExperimentalUuidApi::class)
private fun Application.configureRoutingInternal() {

    val startTime = Clock.System.now().toEpochMilliseconds()

    log("[INIT] Starting Server at version $VERSION")

    /*
     * Wildcard CORS
     */
    install(CORS) {

        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)

        allowHeader(HttpHeaders.AccessControlAllowOrigin)
        allowHeader(HttpHeaders.ContentType)

        anyHost()
    }

    routing {

        get("/") {

            val uptimeMinutes = (Clock.System.now().toEpochMilliseconds() - startTime) / 1000 / 60

            val uptimeHours = uptimeMinutes / 60
            val minutes = uptimeMinutes % 60

            call.respondText("Steam Login Helper $VERSION (up since $uptimeHours hours and $minutes minutes)")
        }

        /*
         * This redirects to the Steam login page
         */
        get("/login") {

            if (!ensureValidApiKey(call))
                return@get

            if (!ensurePrivacyAccepted(call))
                return@get

            /* Case-insensitive header lookup because AWS API Gateway often lowercases headers. */
            val forwardedHost = call.request.headers.entries()
                .find { it.key.equals("X-Forwarded-Host", ignoreCase = true) }
                ?.value
                ?.firstOrNull()

            val domainName = forwardedHost
                ?: (call.request.origin.localAddress + ":" + call.request.origin.localPort)

            /*
             * The redirect parameter is optional.
             * The service can also be called to get a token shown in the browser.
             */

            val redirectUrl = call.request.queryParameters["redirect"] ?: ""

            val redirectUrlEncoded = Base64.UrlSafe.encode(redirectUrl.encodeToByteArray())

            val steamLoginUrl = "$STEAM_LOGIN_URL?" +
                "openid.ns=http://specs.openid.net/auth/2.0" +
                "&openid.mode=checkid_setup" +
                "&openid.return_to=https://$domainName/callback/$redirectUrlEncoded" +
                "&openid.identity=http://specs.openid.net/auth/2.0/identifier_select" +
                "&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select"

            call.respondRedirect(steamLoginUrl)
        }

        get("/privacy") {

            val returnToBase64 = call.request.queryParameters["return_to"] ?: ""

            val language = resolveLanguage(call)

            val isGerman = language == "de"

            call.respondText(
                text = generatePrivacyPolicy(isGerman, returnToBase64).trimIndent(),
                contentType = ContentType.Text.Html.withCharset(Charsets.UTF_8),
                status = HttpStatusCode.OK
            )
        }

        get("/privacy/accept") {

            val returnToBase64 = call.request.queryParameters["return_to"] ?: ""

            val returnTo = decodeReturnToOrDefault(returnToBase64, "/login")

            val token = UUID.randomUUID().toString()

            val expiresAt = Clock.System.now().toEpochMilliseconds() + CONSENT_TOKEN_TTL_MS

            consentTokens[token] = expiresAt

            call.respondRedirect(appendQueryParam(returnTo, "consent_token", token))
        }

        get("/callback/") {
            handleCallback(null)
        }

        get("/callback/{redirectUrl...}") {

            val redirectUrlBase64 = call.request.uri
                .removePrefix("/callback/")
                .substringBefore("?")

            val redirectUrl = Base64.UrlSafe.decode(redirectUrlBase64).decodeToString()

            handleCallback(redirectUrl)
        }

        get("/generate-keys") {

            if (!ensureValidApiKey(call))
                return@get

            if (!allowKeyGeneration) {

                call.respondText(
                    text = "Key generation disabled.",
                    contentType = ContentType.Text.Plain,
                    status = HttpStatusCode.NotAcceptable
                )

                return@get
            }

            val keys = CryptographyProvider
                .Default
                .get(ECDSA)
                .keyPairGenerator(curve = EC.Curve.P256)
                .generateKey()

            val privateKey = keys.privateKey.encodeToByteArray(EC.PrivateKey.Format.DER.Generic)
            val publicKey = keys.publicKey.encodeToByteArray(EC.PublicKey.Format.DER)

            log("PRIVATE: " + privateKey.encodeBase64())
            log("PUBLIC: " + publicKey.encodeBase64())

            call.respondText(
                text = "Generated keys. Check your logs.",
                contentType = ContentType.Text.Plain,
                status = HttpStatusCode.OK
            )
        }
    }
}

private suspend fun RoutingContext.handleCallback(
    redirectUrl: String?
) {

    if (!ensureValidApiKey(call))
        return

    val steamId = requestValidatedSteamId(call.request.queryParameters)

    if (steamId == null) {

        call.respondText(
            status = HttpStatusCode.Unauthorized,
            contentType = ContentType.Text.Plain,
            text = "Sorry, we couldn't verify your Steam ID."
        )

        return
    }

    val steamIdHash = saltedSha256(steamId)

    val jwt: UnsignedJWT = jwt {
        claims {
            issuer = jwtIssuer
            issuedAt = Clock.System.now()
            subject = steamId
            audience = "steam"
            claim("hash", steamIdHash)
        }
    }

    val signedJWT = jwt.sign {
        es256 {
            der(jwtPrivateKey)
        }
    }

    val jwtString = signedJWT.toString()

    return if (!redirectUrl.isNullOrBlank()) {

        val url = "$redirectUrl?token=$jwtString"

        call.respondRedirect(url)

    } else {

        /*
         * Respond with an HTML page displaying the token.
         */
        call.respondText(
            text = generateCodeDisplayPage(jwtString),
            contentType = ContentType.Text.Html.withCharset(Charsets.UTF_8),
            status = HttpStatusCode.OK
        )
    }
}

private fun generatePrivacyPolicy(
    isGerman: Boolean,
    returnToBase64: String
): String {

    val explainText = if (isGerman)
        """
            <h1>Anmeldung mit Steam</h1>

            <p>
                Du wirst zu <strong>Steam (Valve Corporation, USA)</strong> weitergeleitet.
                Durch den Login wird deine <strong>Steam-ID</strong> übermittelt und ein
                <strong>Authentifizierungs-Token</strong> erzeugt, welches lokal in deinem
                Browser gespeichert wird. Dieser Login-Dienst speichert keine Daten.
            </p>

            <p>
                Mit dem Fortfahren willigst du freiwillig in die beschriebene Datenverarbeitung ein.
                Du kannst diese Einwilligung jederzeit widerrufen, indem du die Website-Daten
                in deinem Browser löschst. Weitere Informationen findest du in der Datenschutzerklärung.
            </p>
        """
    else
        """
            <h1>Login with Steam</h1>

            <p>
                You will be redirected to <strong>Steam (Valve Corporation, USA)</strong>.
                By logging in, your <strong>Steam ID</strong> will be transmitted and an
                <strong>authentication token</strong> will be created and stored locally
                in your browser. This login service does not store any data.
            </p>

            <p>
                By continuing, you voluntarily consent to the described data processing.
                You can revoke this consent at any time by deleting the website data
                in your browser. For more information, see the privacy policy.
            </p>
        """

    val acceptButtonText = if (isGerman)
        "Akzeptieren und fortfahren"
    else
        "Accept and continue"

    return """
        <!DOCTYPE html>
        <html lang="${if (isGerman) "de" else "en"}">
        <head>
            <meta charset="UTF-8" />
            <link rel="icon" href="data:,">
            <title>Steam Login</title>
            <style>
                body {
                    font-family: sans-serif;
                    padding: 2em;
                    max-width: 780px;
                    margin: 0 auto;
                    line-height: 1.5;
                }
                h1 {
                    margin-top: 0;
                }
                .card {
                    border: 1px solid #ddd;
                    border-radius: 10px;
                    padding: 1.5em;
                    background: #fafafa;
                }
                .actions {
                    margin-top: 1.5em;
                }
                button {
                    padding: 0.6em 1.2em;
                    font-size: 1rem;
                }
            </style>
        </head>
        <body>
            <div class="card">

                $explainText

                <div class="actions">
                    <form action="/privacy/accept" method="get">
                        <input type="hidden" name="return_to" value="$returnToBase64" />
                        <button type="submit">$acceptButtonText</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
}

private fun generateCodeDisplayPage(
    jwtString: String
) = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <link rel="icon" href="data:,">
        <title>SteamLoginHelper</title>
        <style>
            body {
                font-family: sans-serif;
                padding: 2em;
            }
            pre {
                background-color: #f4f4f4;
                padding: 1em;
                border: 1px solid #ccc;
                border-radius: 8px;
                white-space: pre-wrap;
                word-break: break-all;
            }
            button {
                margin-bottom: 1em;
            }
        </style>
    </head>
    <body>
        <h3>This is your auth token. Keep it a secret!</h3>
        <button onclick="navigator.clipboard.writeText(document.getElementById('token').innerText)">Copy</button>
        <pre id="token">$jwtString</pre>
    </body>
    </html>""".trimIndent()

private suspend fun ensurePrivacyAccepted(
    call: ApplicationCall
): Boolean {

    val token = call.request.queryParameters["consent_token"]
    val accepted = token != null && isConsentTokenValid(token)

    if (!accepted) {

        val returnToBase64 = Base64.UrlSafe.encode(call.request.uri.encodeToByteArray())

        call.respondRedirect("$PRIVACY_ROUTE?return_to=$returnToBase64")

        return false
    }

    return true
}

private fun resolveLanguage(
    call: ApplicationCall
): String {

    val requested = call.request.queryParameters["lang"]?.lowercase()?.trim()

    if (requested == "de")
        return "de"

    if (requested == "en")
        return "en"

    val acceptLanguage = call.request.header(HttpHeaders.AcceptLanguage)?.lowercase()
        ?: return "en"

    val parts = acceptLanguage.split(",")

    return if (parts.any { it.trim().startsWith("de") }) "de" else "en"
}

private fun isConsentTokenValid(
    token: String
): Boolean {

    val expiresAt = consentTokens.remove(token) ?: return false

    return expiresAt >= Clock.System.now().toEpochMilliseconds()
}

private fun decodeReturnToOrDefault(
    base64: String,
    defaultValue: String
): String {

    if (base64.isBlank())
        return defaultValue

    return try {
        val decoded = Base64.UrlSafe.decode(base64).decodeToString()
        if (decoded.startsWith("/")) decoded else defaultValue
    } catch (_: IllegalArgumentException) {
        defaultValue
    }
}

private fun appendQueryParam(
    url: String,
    name: String,
    value: String
): String {

    val separator = if (url.contains("?")) "&" else "?"
    val encodedValue = URLEncoder.encode(value, Charsets.UTF_8)
    return "$url$separator$name=$encodedValue"
}

/**
 * Checks the API key if one is set.
 * Returns "true" when everything is fine, "false" on error.
 */
private suspend fun ensureValidApiKey(
    call: ApplicationCall
): Boolean {

    /*
     * Check the API key if one is required.
     */
    if (!apiKey.isNullOrBlank()) {

        val givenApiKey = call.request.header("x-api-key")

        if (givenApiKey != apiKey) {

            call.respondText(
                status = HttpStatusCode.Unauthorized,
                contentType = ContentType.Text.Plain,
                text = "Please provide an valid API key."
            )

            return false
        }
    }

    return true
}

/**
 * Calls the Steam backend to get a validated Steam ID
 */
private suspend fun requestValidatedSteamId(
    queryParameters: Parameters
): String? {

    val parametersBuilder = ParametersBuilder()

    queryParameters.forEach { key, values ->
        values.forEach { value ->
            parametersBuilder.append(key, value)
        }
    }

    /* Change the openid.mode */
    parametersBuilder["openid.mode"] = "check_authentication"

    val requestParameters = parametersBuilder.build()

    val response = httpClient.post(STEAM_LOGIN_URL) {
        setBody(FormDataContent(requestParameters))
    }

    if (!response.status.isSuccess()) {

        log("Auth failed: ${response.status} ${response.bodyAsText()}")

        return null
    }

    val responseText = response.bodyAsText()

    return if (responseText.contains("is_valid:true")) {
        requestParameters["openid.claimed_id"]?.substringAfterLast("/")
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

private fun log(message: String) =
    println(message)

private fun log(ex: Throwable) =
    ex.printStackTrace()
