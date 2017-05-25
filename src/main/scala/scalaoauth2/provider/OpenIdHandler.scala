package scalaoauth2.provider

import java.security.KeyPairGenerator

import org.joda.time._
import pdi.jwt.{Jwt, JwtAlgorithm, JwtClaim, JwtHeader}

import scala.concurrent.Future

/**
 *
 * Provide access to <b>Protected Resource</b> phase support for using OAuth 2.0.
 *
 * <h3>[Access to Protected Resource phase]</h3>
 * <ul>
 *   <li>findAccessToken(token)</li>
 *   <li>findAuthInfoByAccessToken(token)</li>
 * </ul>
 */
trait OpenIdHandler[U] {

  /**
    * A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g.,
    * 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
    *
    * @param authInfo This value is already authorized by system
    * @return Subject identifier returned with ID Token
    */
  def getSubjectIdentifier(authInfo: AuthInfo[U]): String

  /**
    *
    * @return Issuer identifier returned with ID Token
    *
    */
  def getIssuerIdentifier: String


  /**
    * Creates a ID Token that contains claims about the Authentication of an End-User
    * represent as a signed JSON Web Token (JWT)
    *
    * @param authInfo This value is already authorized by the system
    * @param accessToken Option access token when using Authorization Code Flow
    * @return Signed JWT returned to client.
    */
  def createIDToken(authInfo: AuthInfo[U], accessToken: Option[String]): String = {
    val idTokenClaimsSet = JwtClaim(
      issuer = Some(getIssuerIdentifier),
      subject = Some(getSubjectIdentifier(authInfo)),
      audience = Some(Set(authInfo.clientId.get))
    ).issuedNow.expiresIn(3600)

    /*
    accessToken match {
      case Some(token) => idTokenClaimsSet.setAccessTokenHash(AccessTokenHash.compute(new BearerAccessToken(token), JWSAlgorithm.RS256))
      case None => // Nop
    }*/

    // @TODO private key should be injected into project
    val keyGenerator = KeyPairGenerator.getInstance("RSA")
    keyGenerator.initialize(1024)

    val kp = keyGenerator.genKeyPair

    Jwt.encode(JwtHeader(JwtAlgorithm.RS256), idTokenClaimsSet, kp.getPrivate)
  }
}
