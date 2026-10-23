package com.yeboid

import android.content.Context
import android.content.Intent
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import net.openid.appauth.*
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

class YeboIDException(val code: String, val status: Int? = null) : Exception("YeboID: $code")
class Tokens(val accessToken: String, val refreshToken: String?, val expiresAt: Long, val scope: String) {
    val grantedScopes: Set<String> get() = scope.split(" ").filter { it.isNotEmpty() }.toSet()
    internal fun json(): String = JSONObject().put("access", accessToken).put("refresh", refreshToken)
        .put("expires", expiresAt).put("scope", scope).toString()
    companion object {
        internal fun parse(raw: String): Tokens = JSONObject(raw).let {
            Tokens(it.getString("access"), if (it.has("refresh")) it.getString("refresh") else null, it.getLong("expires"), it.getString("scope"))
        }
    }
}

/** Keep one instance per issuer/client. Use only accessToken on product APIs. */
class YeboID(
    context: Context,
    private val clientId: String,
    private val redirectUri: Uri,
    private val issuer: String = "https://api.yeboid.com",
    private val scopes: List<String> = listOf("openid", "profile", "offline_access"),
    private val store: SecureStore = AndroidKeyStore(context, "$issuer|$clientId"),
    private val http: suspend (String, Map<String, String>?, String?) -> JSONObject = ::request
) : AutoCloseable {
    private val service = AuthorizationService(context.applicationContext)
    private val mutex = Mutex()
    private var configuration: AuthorizationServiceConfiguration? = null
    init {
        val origin = Uri.parse(issuer)
        require(secure(origin) && origin.query == null && origin.path.isNullOrEmpty()) { "YeboID: invalid_issuer" }
        require(clientId.isNotBlank() && !redirectUri.scheme.isNullOrBlank() && redirectUri.scheme != "http" &&
            redirectUri.fragment == null && redirectUri.query == null && redirectUri.userInfo == null) { "YeboID: invalid_callback" }
        require("openid" in scopes && scopes.all { it.isNotBlank() && it.none(Char::isWhitespace) }) { "YeboID: invalid_scope" }
    }
    private suspend fun discovery(): AuthorizationServiceConfiguration {
        configuration?.let { return it }
        val data = http("$issuer/.well-known/openid-configuration", null, null)
        if (data.getString("issuer") != issuer || !data.getJSONArray("code_challenge_methods_supported").strings().contains("S256")) throw YeboIDException("invalid_discovery")
        for (key in listOf("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint")) {
            if (!secure(Uri.parse(data.getString(key)))) throw YeboIDException("invalid_endpoint")
        }
        if (!data.getJSONArray("scopes_supported").strings().containsAll(scopes)) throw YeboIDException("invalid_scope")
        return AuthorizationServiceConfiguration(AuthorizationServiceDiscovery(data)).also { configuration = it }
    }
    suspend fun checkRegistration() {
        val encoded = URLEncoder.encode(clientId, "UTF-8").replace("+", "%20")
        val data = http("$issuer/oauth/clients/$encoded/configuration", null, null)
        if (data.getString("client_id") != clientId || !data.getJSONArray("redirect_uris").strings().contains(redirectUri.toString())) throw YeboIDException("invalid_registration")
        if (!data.getJSONArray("scopes").strings().containsAll(scopes)) throw YeboIDException("invalid_scope")
    }
    /** Launch with ActivityResultContracts.StartActivityForResult. Pending PKCE state survives process restart. */
    suspend fun signInIntent(): Intent = mutex.withLock {
        checkRegistration()
        val config = discovery()
        if (store.get("pending") != null) throw YeboIDException("login_in_progress")
        val request = AuthorizationRequest.Builder(config, clientId, ResponseTypeValues.CODE, redirectUri).setScopes(scopes).build()
        val pending = JSONObject().put("request", request.jsonSerialize()).put("created", System.currentTimeMillis())
        store.put("pending", pending.toString())
        service.getAuthorizationRequestIntent(request)
    }
    suspend fun cancelSignIn() = mutex.withLock { store.remove("pending") }
    suspend fun completeSignIn(intent: Intent): Tokens = mutex.withLock {
        val raw = store.get("pending") ?: throw YeboIDException("missing_transaction")
        store.remove("pending") // consume once, including denials and failed exchanges
        val pending = JSONObject(raw)
        val expected = AuthorizationRequest.jsonDeserialize(pending.getJSONObject("request"))
        val age = System.currentTimeMillis() - pending.getLong("created")
        if (age !in 0..600_000) throw YeboIDException("expired_transaction")
        AuthorizationException.fromIntent(intent)?.let { throw it }
        val response = AuthorizationResponse.fromIntent(intent) ?: throw YeboIDException("missing_callback")
        if (response.state != expected.state || response.request.jsonSerializeString() != expected.jsonSerializeString()) throw YeboIDException("state_mismatch")
        if (expected.clientId != clientId || expected.redirectUri != redirectUri || expected.configuration.discoveryDoc?.issuer?.toString() != issuer) throw YeboIDException("transaction_mismatch")
        exchange(response.createTokenExchangeRequest(), rotating = false)
    }
    private suspend fun exchange(request: TokenRequest, rotating: Boolean): Tokens {
        val response: TokenResponse = suspendCoroutine { continuation ->
            service.performTokenRequest(request) { response, error ->
                if (error != null) continuation.resumeWithException(error)
                else if (response != null) continuation.resume(response)
                else continuation.resumeWithException(YeboIDException("invalid_token_response"))
            }
        }
        val access = response.accessToken ?: throw YeboIDException("invalid_token_response")
        val expiry = response.accessTokenExpirationTime ?: throw YeboIDException("invalid_token_response")
        val scope = response.scope ?: throw YeboIDException("missing_granted_scope")
        if (access.isBlank() || !response.tokenType.equals("Bearer", ignoreCase = true) || expiry <= System.currentTimeMillis() ||
            (rotating && response.refreshToken.isNullOrBlank())) throw YeboIDException("invalid_token_response")
        val tokens = Tokens(access, response.refreshToken, expiry, scope)
        store.put("tokens", tokens.json())
        return tokens
    }
    suspend fun tokens(): Tokens? = mutex.withLock { store.get("tokens")?.let(Tokens::parse) }
    suspend fun refresh(): Tokens = mutex.withLock {
        if (store.get("pending") != null) throw YeboIDException("login_in_progress")
        val token = store.get("tokens")?.let(Tokens::parse)?.refreshToken ?: throw YeboIDException("login_required")
        val request = TokenRequest.Builder(discovery(), clientId).setGrantType(GrantTypeValues.REFRESH_TOKEN).setRefreshToken(token).build()
        exchange(request, rotating = true) // one request; never retry a rotating refresh automatically
    }
    suspend fun userInfo(): JSONObject = mutex.withLock {
        val token = store.get("tokens")?.let(Tokens::parse) ?: throw YeboIDException("login_required")
        if (token.expiresAt <= System.currentTimeMillis()) throw YeboIDException("login_required")
        val endpoint = discovery().discoveryDoc!!.userinfoEndpoint!!.toString()
        val user = http(endpoint, null, token.accessToken)
        if (user.optString("sub").isBlank()) throw YeboIDException("invalid_userinfo")
        user
    }
    /** Revoke this app session. Does not clear browser SSO cookies. Failures preserve local state. */
    suspend fun signOut() = mutex.withLock {
        val token = store.get("tokens")?.let(Tokens::parse)?.refreshToken
        if (token != null) {
            val endpoint = discovery().discoveryDoc!!.docJson.getString("revocation_endpoint")
            http(endpoint, mapOf("client_id" to clientId, "token" to token, "token_type_hint" to "refresh_token"), null)
        }
        store.remove("pending"); store.remove("tokens")
    }
    override fun close() { service.dispose() }
    companion object {
        private fun secure(uri: Uri) = uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null
        private fun org.json.JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
        private suspend fun request(url: String, form: Map<String, String>?, token: String?): JSONObject = withContext(Dispatchers.IO) {
            val connection = URL(url).openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = 10_000; connection.readTimeout = 10_000; connection.instanceFollowRedirects = false
                connection.setRequestProperty("Accept", "application/json")
                token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
                if (form != null) {
                    connection.requestMethod = "POST"; connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                    val body = form.entries.joinToString("&") { (key, value) -> URLEncoder.encode(key, "UTF-8") + "=" + URLEncoder.encode(value, "UTF-8") }
                    connection.outputStream.use { it.write(body.toByteArray()) }
                }
                val status = connection.responseCode
                if (status !in 200..299) throw YeboIDException("http_$status", status)
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                if (body.isEmpty() && form?.containsKey("token_type_hint") == true) JSONObject() else JSONObject(body)
            } finally { connection.disconnect() }
        }
    }
}
