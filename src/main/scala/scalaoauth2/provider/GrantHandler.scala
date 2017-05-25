package scalaoauth2.provider

import scala.concurrent.{ ExecutionContext, Future }

case class GrantHandlerResult[U](
  authInfo: AuthInfo[U],
  tokenType: String,
  accessToken: String,
  expiresIn: Option[Long],
  refreshToken: Option[String],
  scope: Option[String],
  params: Map[String, String],
  idToken: Option[String]
)

trait GrantHandler {
  /**
   * Controls whether client credentials are required.  Defaults to true but can be overridden to be false when needed.
   * Per the OAuth2 specification, client credentials are required for all grant types except password, where it is up
   * to the authorization provider whether to make them required or not.
   */
  def clientCredentialRequired = true

  def handleRequest[U](maybeValidatedClientCred: Option[ClientCredential], request: AuthorizationRequest, authorizationHandler: AuthorizationHandler[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]]

  /**
   * Returns valid access token.
   */
  protected def issueAccessToken[U](handler: AuthorizationHandler[U], authInfo: AuthInfo[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]] = {
    for {
      accessToken <- handler.getStoredAccessToken(authInfo).flatMap {
        case Some(token) if shouldRefreshAccessToken(token) => token.refreshToken.map {
          handler.refreshAccessToken(authInfo, _)
        }.getOrElse {
          handler.createAccessToken(authInfo)
        }
        case Some(token) => Future.successful(token)
        case None => handler.createAccessToken(authInfo)
      }
      id <- if(authInfo.scope.isDefined && authInfo.scope.contains("openid")) {
        handler.createIDToken(authInfo, Some(accessToken.token))
      } else Future.successful(None)
    } yield createGrantHandlerResult(authInfo, accessToken, id)
  }

  protected def shouldRefreshAccessToken(token: AccessToken) = token.isExpired

  protected def createGrantHandlerResult[U](authInfo: AuthInfo[U], accessToken: AccessToken, id: Option[String] = None) = GrantHandlerResult(
    authInfo,
    "Bearer",
    accessToken.token,
    accessToken.expiresIn,
    accessToken.refreshToken,
    accessToken.scope,
    accessToken.params,
    id
  )

}

class RefreshToken extends GrantHandler {

  override def handleRequest[U](maybeValidatedClientCred: Option[ClientCredential], request: AuthorizationRequest, handler: AuthorizationHandler[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]] = {
    val clientId = maybeValidatedClientCred.getOrElse(throw new InvalidRequest("Client credential is required")).clientId
    val refreshTokenRequest = RefreshTokenRequest(request)
    val refreshToken = refreshTokenRequest.refreshToken

    handler.findAuthInfoByRefreshToken(refreshToken).flatMap { authInfoOption =>
      val authInfo = authInfoOption.getOrElse(throw new InvalidGrant("Authorized information is not found by the refresh token"))
      if (!authInfo.clientId.contains(clientId)) throw new InvalidClient
      handler.refreshAccessToken(authInfo, refreshToken).map(createGrantHandlerResult(authInfo, _))
    }
  }
}

class Password extends GrantHandler {

  override def handleRequest[U](maybeValidatedClientCred: Option[ClientCredential], request: AuthorizationRequest, handler: AuthorizationHandler[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]] = {
    /**
     * Given that client credentials may be optional, if they are required, they must be fully validated before
     * further processing.
     */
    if (clientCredentialRequired && maybeValidatedClientCred.isEmpty) {
      throw new InvalidRequest("Client credential is required")
    } else {
      val passwordRequest = PasswordRequest(request)
      handler.findUser(maybeValidatedClientCred, passwordRequest).flatMap { maybeUser =>
        val user = maybeUser.getOrElse(throw new InvalidGrant("username or password is incorrect"))
        val scope = passwordRequest.scope
        val authInfo = AuthInfo(user, maybeValidatedClientCred.map(_.clientId), scope, None)

        issueAccessToken(handler, authInfo)
      }
    }
  }
}

class ClientCredentials extends GrantHandler {

  override def handleRequest[U](maybeValidatedClientCred: Option[ClientCredential], request: AuthorizationRequest, handler: AuthorizationHandler[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]] = {
    val clientId = maybeValidatedClientCred.getOrElse(throw new InvalidRequest("Client credential is required")).clientId
    val clientCredentialsRequest = ClientCredentialsRequest(request)
    val scope = clientCredentialsRequest.scope

    handler.findUser(maybeValidatedClientCred, clientCredentialsRequest).flatMap { optionalUser =>
      val user = optionalUser.getOrElse(throw new InvalidGrant("client_id or client_secret or scope is incorrect"))
      val authInfo = AuthInfo(user, Some(clientId), scope, None)

      issueAccessToken(handler, authInfo)
    }
  }

}

class AuthorizationCode extends GrantHandler {

  override def handleRequest[U](maybeValidatedClientCred: Option[ClientCredential], request: AuthorizationRequest, handler: AuthorizationHandler[U])(implicit ctx: ExecutionContext): Future[GrantHandlerResult[U]] = {
    val clientId = maybeValidatedClientCred.getOrElse(throw new InvalidRequest("Client credential is required")).clientId
    val authorizationCodeRequest = AuthorizationCodeRequest(request)
    val code = authorizationCodeRequest.code
    val redirectUri = authorizationCodeRequest.redirectUri

    handler.findAuthInfoByCode(code).flatMap { optionalAuthInfo =>
      val authInfo = optionalAuthInfo.getOrElse(throw new InvalidGrant("Authorized information is not found by the code"))
      if (!authInfo.clientId.contains(clientId)) {
        throw new InvalidClient
      }

      if (authInfo.redirectUri.isDefined && authInfo.redirectUri != redirectUri) {
        throw new RedirectUriMismatch
      }

      val f = issueAccessToken(handler, authInfo)
      for {
        accessToken <- f
        _ <- handler.deleteAuthCode(code)
      } yield accessToken
    }
  }
}