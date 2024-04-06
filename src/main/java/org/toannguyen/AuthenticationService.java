package org.toannguyen;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
public class AuthenticationService {
    @ConfigProperty(name = "cognito.poolId")
    String poolId;

    @ConfigProperty(name = "cognito.clientSecret")
    String clientSecret;

    @ConfigProperty(name = "cognito.clientId")
    String clientId;

    @Inject
    CognitoIdentityProviderClient cognitoIdentityProviderClient;
    public LoginResponse login(LoginRequest loginRequest) {
        var cognitoLoginResponse = processLogin(loginRequest);
        var loginResponse = new LoginResponse();
        loginResponse.setAccessToken(cognitoLoginResponse.accessToken());
        loginResponse.setIdToken(cognitoLoginResponse.idToken());
        loginResponse.setRefreshToken(cognitoLoginResponse.refreshToken());
        loginResponse.setExpiresIn(cognitoLoginResponse.expiresIn());
        loginResponse.setTokenType(cognitoLoginResponse.tokenType());
        loginResponse.setUsername(loginRequest.getUsername());
        return loginResponse;
    }

    public AuthenticationResultType processLogin(LoginRequest loginRequest) {
        AdminInitiateAuthResponse result = initiateAuthentication(loginRequest);

        if (result.challengeName() != null) {
            RespondToAuthChallengeResponse respondToAuthChallengeResponse = adminRespondToAuthChallenge(loginRequest, result.challengeName(), result.session());

            return respondToAuthChallengeResponse.authenticationResult();
        }

        return result.authenticationResult();
    }

    private AdminInitiateAuthResponse initiateAuthentication(LoginRequest loginRequest) {
        Map<String, String> authParameters = new HashMap<>();
        authParameters.put(AppConstants.AUTH_USERNAME, loginRequest.getUsername());
        authParameters.put(AppConstants.AUTH_PASSWORD, loginRequest.getPassword());

        if (clientSecret != null && !clientSecret.isEmpty()) {
            String secretHash = HashUtils.computeSecretHash(clientId, clientSecret, loginRequest.getUsername());
            authParameters.put(AppConstants.AUTH_SECRET_HASH, secretHash);
        }

        AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                .userPoolId(poolId)
                .clientId(clientId)
                .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .authParameters(authParameters)
                .build();

        try {
            AdminInitiateAuthResponse response = cognitoIdentityProviderClient.adminInitiateAuth(authRequest);
            return response;
        }
        catch (CognitoIdentityProviderException e) {
            throw e;
        }
    }

    private RespondToAuthChallengeResponse adminRespondToAuthChallenge(LoginRequest signInRequest, ChallengeNameType challengeNameType, String session) {
        Map<String, String> challengeResponses = new HashMap<>();
        challengeResponses.put(AppConstants.AUTH_USERNAME, signInRequest.getUsername());
        challengeResponses.put(challengeNameType.name() + "_CODE", signInRequest.getCode());

        if (clientSecret != null && !clientSecret.isEmpty()) {
            String secretHash = HashUtils.computeSecretHash(clientId, clientSecret, signInRequest.getUsername());
            challengeResponses.put(AppConstants.AUTH_SECRET_HASH, secretHash);
        }

        RespondToAuthChallengeRequest respondToAuthChallengeRequest = RespondToAuthChallengeRequest.builder()
                .challengeName(challengeNameType)
                .clientId(clientId)
                .challengeResponses(challengeResponses)
                .session(session)
                .build();

        return cognitoIdentityProviderClient.respondToAuthChallenge(respondToAuthChallengeRequest);
    }
}
