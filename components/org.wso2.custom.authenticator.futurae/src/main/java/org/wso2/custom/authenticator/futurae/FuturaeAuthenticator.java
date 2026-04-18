package org.wso2.custom.authenticator.futurae;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeAuthnFailedException;
import org.wso2.custom.authenticator.futurae.common.model.*;
import org.wso2.custom.authenticator.futurae.common.web.FuturaeAuthenticationAPIClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.custom.authenticator.futurae.FuturaeUtils.*;
import static org.wso2.custom.authenticator.futurae.common.util.FuturaeUtils.getFuturaeAuthnFailedException;

public class FuturaeAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(FuturaeAuthenticator.class);



    /**
     * Returns the authenticator's name.
     *
     * @return String  The identifier of the authenticator.
     */
    @Override
    public String getName() {

        return FuturaeAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Returns authenticator's friendly name.
     *
     * @return String  The display name of the authenticator.
     */
    @Override
    public String getFriendlyName() {

        return FuturaeAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Returns all user input fields of the authenticator.
     *
     * @return List  Returns the federated authenticator properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        // Get the required configuration properties.
        List<Property> configProperties = new ArrayList<>();
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME));
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID));
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY));
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.ADMIN_API_KEY));
        //configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.ENABLE_PROGRESSIVE_ENROLLMENT));

        return configProperties;
    }

    /**
     * Returns a unique string to identify each request and response separately.
     * This contains the session data key, processed by the WSO2 IS.
     *
     * @param request The request that is received by the authenticator.
     * @return String  Returns the state parameter value that is carried by the request.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String sessionDataKey = request.getParameter(FuturaeAuthenticatorConstants.SESSION_DATA_KEY);
        if (StringUtils.isNotBlank(sessionDataKey)) {
            return sessionDataKey;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A unique identifier cannot be issued for both Request and Response. " +
                        "ContextIdentifier is NULL.");
            }
            return null;
        }
    }

    /**
     * Checks whether the request and response can be handled by the authenticator.
     *
     * @param request The request that is received by the authenticator.
     * @return Boolean Whether the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        //TODO: check and verify
        return StringUtils.isNotBlank(request.getParameter(FuturaeAuthenticatorConstants.AUTH_TYPE)) &&
                request.getParameter(FuturaeAuthenticatorConstants.AUTH_TYPE).equals(FuturaeAuthenticatorConstants.AUTH_TYPE_FUTURAE) &&
                StringUtils.isNotBlank(request.getParameter(FuturaeAuthenticatorConstants.SESSION_DATA_KEY));
    }

    /**
     * Redirects the user to the login page for authentication purposes. This authenticator redirects the user to the
     * Futurae login page deployed with the IS.
     *
     * @param request  The request that is received by the authenticator.
     * @param response Appends the authorized URL once a valid authorized URL is built.
     * @param context  The Authentication context received by the authenticator.
     * @throws AuthenticationFailedException Exception thrown while redirecting the user to the login page.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            //redirectFuturaeLoginPage(response, context, null);
            initiateFuturaeAuthenticationRequest(request, response, context);


        } catch (AuthenticationFailedException e) {
            String errorMessage = "Error occurred when trying to redirect user to the login page.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * This method is overridden to authenticate user.
     *
     * @param request  The request that is received by the authenticator.
     * @param response The response that is received to the authenticator.
     * @param context  The Authentication context received by authenticator.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) {

        String username = (String) context.getProperty(FuturaeAuthenticatorConstants.USERNAME);

        //Set the authenticated user.
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
        context.setSubject(authenticatedUser);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully logged in the user " + getMaskedUsername(username));
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (context.getLastAuthenticatedUser() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authenticated user is not found in the context.");
            }
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP);
        }

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);

        String tenantDomain = authenticatedUserFromContext.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            throw new AuthenticationFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_TENANT.getCode(),
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_TENANT.getMessage());
        }

            /*
            The username that the server is using to identify the user, is needed to be identified, as
            for the federated users, the username in the authentication context may not be same as the
            username when the user is provisioned to the server.
             */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

            /*
            If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
            federated user.
             */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(context, authenticatedUserFromContext,
                mappedLocalUsername, tenantDomain, isInitialFederationAttempt);

        context.setProperty(FuturaeAuthenticatorConstants.AUTHENTICATED_USER, authenticatingUser);

        if (context.getProperty(FuturaeAuthenticatorConstants.AUTH_STATUS) != null) {
            // if intermediate authentication request comes, then go through this flow.
            String authStatus = (String) context.getProperty(FuturaeAuthenticatorConstants.AUTH_STATUS);

            if (FuturaeAuthenticatorConstants.AuthenticationStatus.COMPLETED.getName().equals(authStatus)) {
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;

            } else if (FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING.getName().equals(authStatus)) {
                redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING);
                return AuthenticatorFlowStatus.INCOMPLETE;

            } else if (FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED.getName().equals(authStatus)) {
                redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }

        initiateFuturaeAuthenticationRequest(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Redirect the user to the Futurae login page with authentication status and messages, if there is any.
     *
     * @param response             The response that is received to the authenticator.
     * @param context              The Authentication context received by the authenticator.
     * @param authenticationStatus The authentication status of the user when authenticating via Futurae.
     * @throws FuturaeAuthnFailedException Exception thrown while redirecting user to login page.
     */
    private void redirectFuturaeLoginPage(HttpServletResponse response, AuthenticationContext context,
                                          FuturaeAuthenticatorConstants.AuthenticationStatus authenticationStatus)
            throws FuturaeAuthnFailedException {

        try {
            ServiceURLBuilder futuraeLoginPageURLBuilder = ServiceURLBuilder.create()
                    .addPath(FuturaeAuthenticatorConstants.FUTURAE_LOGIN_PAGE)
                    .addParameter(FuturaeAuthenticatorConstants.SESSION_DATA_KEY, context.getContextIdentifier())
                    .addParameter("AuthenticatorName", FuturaeAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME)
                    .addParameter(FuturaeAuthenticatorConstants.TENANT_DOMAIN, context.getTenantDomain());

            if (authenticationStatus != null) {
                futuraeLoginPageURLBuilder.addParameter("status", String.valueOf(authenticationStatus.getName()));
                futuraeLoginPageURLBuilder.addParameter(
                        "message", String.valueOf(authenticationStatus.getMessage()));
            }

            String futuraeLoginPageURL = futuraeLoginPageURLBuilder.build().getAbsolutePublicURL();
            response.sendRedirect(futuraeLoginPageURL);

        } catch (IOException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE, e);
        } catch (URLBuilderException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_BUILDING_LOGIN_URL_FAILURE, e);
        }
    }

    /**
     * Send a push notification to the user-registered devices to start the user authentication process using
     * Futurae, the external identity provider.
     *
     * @param request  The request that is received by the authenticator.
     * @param response The response that is received to the authenticator.
     * @param context  The Authentication context received by the authenticator.
     * @throws FuturaeAuthnFailedException Exception thrown while sending push notification to the registered device.
     */
    private void initiateFuturaeAuthenticationRequest(
            HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatingUser;
        String userId;
        String futuraeId;

        try {
            authenticatingUser = (AuthenticatedUser) context.getProperty(FuturaeAuthenticatorConstants
                    .AUTHENTICATED_USER);

            userId = resolveUserId(authenticatingUser);
            if (StringUtils.isBlank(userId)) {
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
            }

            boolean isUserAccountLocked = Boolean.parseBoolean(getClaimValue(authenticatingUser,
                    FuturaeAuthenticatorConstants.USER_ACCOUNT_LOCKED_CLAIM));
            if (isUserAccountLocked) {
                LOG.error("User account is locked.");
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_ACCOUNT_LOCKED);
            }

            String username = authenticatingUser.getUserName();
            String maskedUsername = getMaskedUsername(username);

            // Extract Futurae authenticator configurations.
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String serviceHostname = authenticatorProperties.get(
                    FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
            String serviceID = authenticatorProperties.get(
                    FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
            String authApiKey = authenticatorProperties.get(
                    FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());
            // TODO : Remove if admin api key is not needed
            String adminApiKey = authenticatorProperties.get(
                    FuturaeAuthenticatorConstants.ConfigProperties.ADMIN_API_KEY.getName());

            // Validate Futurae configurable parameters.
            validateFuturaeConfiguration(serviceHostname, serviceID, authApiKey, adminApiKey);

            //TODO: Check if this is needed
            futuraeId = getClaimValue(authenticatingUser, FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM);

            if (StringUtils.isBlank(futuraeId)) {
                // Step 1 : Search the user in futurae by username
                UserSearchResponse futuraeUser = FuturaeAuthenticationAPIClient.lookupUserByUsername(
                        serviceHostname, serviceID, authApiKey, username);

                // If user exists in Futurae
                if (futuraeUser != null) {
                    String storedFuturaeDeviceId =
                            getClaimValue(authenticatingUser, FuturaeAuthenticatorConstants.FUTURAE_DEVICE_ID_CLAIM);

                    // If there is a stored futurae registered device in WSO2 side. remove it.
                    if (StringUtils.isNotBlank(storedFuturaeDeviceId)) {
                        UnenrollDeviceResponse unenrollResponse = FuturaeAuthenticationAPIClient.unenrollDevice(
                                serviceHostname,
                                serviceID,
                                authApiKey,
                                UnenrollDeviceRequest.byUsername(username, storedFuturaeDeviceId)
                        );

                        if (StringUtils.isNotBlank(unenrollResponse.getResult())
                                && (FuturaeAuthenticatorConstants.UNENROLL_SUCCESS.equals(unenrollResponse.getResult())
                                || FuturaeAuthenticatorConstants.UNENROLL_SUCCESS_2FA.equals(unenrollResponse.getResult()))
                        ) {
                            // Unenroll succeeded
                            // Update the stored Futurae user ID claim with the ser_id returned by the lookup
                            // Reset the Futurae device ID claim
//                            setClaimValue(authenticatingUser,
//                                    FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM,
//                                    futuraeUser.getUser_id());
//                            setClaimValue(authenticatingUser,
//                                    FuturaeAuthenticatorConstants.FUTURAE_DEVICE_ID_CLAIM,
//                                    "");
                            EnrollRequest enrollRequest =
                                    EnrollRequest.forExistingUser(futuraeId);
                            EnrollResponse enrollResponse = FuturaeAuthenticationAPIClient.enrollDevice(
                                    serviceHostname, serviceID, authApiKey, enrollRequest);

                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Successfully enrolled new device for user " + maskedUsername +
                                        ". Enrollment ID: " + enrollResponse.getEnrollment_id());
                            }

                            // Persist the Futurae user ID so future logins go through the auth path.
                            //TODO: Verify if this is the correct place
                            setClaimValue(authenticatingUser,
                                    FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM,
                                    futuraeId);


                            // TODO: Redirect user to scan QR code (enrollResponse.getActivation_qrcode_url())
                        }
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("User " + maskedUsername + " was not found in Futurae. Triggering new user enrollment.");
                    }

                    // User does not exist in Futurae — create and enroll in one call.
                    // forNewUser() + setUsername() tells Futurae to create the user account.
                    EnrollRequest enrollRequest = EnrollRequest.forNewUser().setUsername(username);
                    EnrollResponse enrollResponse = FuturaeAuthenticationAPIClient.enrollDevice(
                            serviceHostname, serviceID, authApiKey, enrollRequest);

                    // Persist the Futurae user ID so future logins go through the auth path.
                    //TODO: Verify if this is the correct place
                    setClaimValue(authenticatingUser,
                            FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM,
                            enrollResponse.getUser_id());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("New Futurae user created and enrollment initiated for " + maskedUsername +
                                ". Enrollment ID: " + enrollResponse.getEnrollment_id());
                    }


                    // TODO: Redirect user to scan QR code (enrollResponse.getActivation_qrcode_url())
                }
            } else {
                PreAuthResponse authenticationOptionsResponse = FuturaeAuthenticationAPIClient.getAuthenticationOptions(
                        serviceHostname, serviceID, authApiKey, username, "");

                // Only "approve" is supported as an authentication method.
                if (authenticationOptionsResponse.getResult() == FuturaeAuthenticatorConstants.PreAuthResult.auth
                        && authenticationOptionsResponse.getAllowed_factors() != null
                        && authenticationOptionsResponse.getAllowed_factors().contains(FuturaeAuthenticatorConstants.APPROVE)) {
                    // This means the user is already enrolled and can use "approve" auth mode
                    // Then send the push notification to the enrolled device
                    AuthResponse futuraeAuthenticationResponse = FuturaeAuthenticationAPIClient.sendAuthRequest(
                            serviceHostname, serviceID, authApiKey, username, FuturaeAuthenticatorConstants.APPROVE
                    );

                    // Extract the session ID from Futurae auth response
                    String futuraeSessionId = futuraeAuthenticationResponse.getSession_id();

                    if (StringUtils.isBlank(futuraeSessionId)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Retrieved session ID for the authentication request for the user " + maskedUsername +
                                    " is either null or empty.");
                        }
                        redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED);
                        return;
                    }

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Successfully sent a push notification for the registered devices of the user " +
                                maskedUsername);
                    }

                    // Store the Futurae context information.
                    context.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS,
                            FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING.getName());
                    context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID, futuraeSessionId);
                    context.setProperty(FuturaeAuthenticatorConstants.USERNAME, username);

                    // Inform the user that the push notification has been sent to the registered device.
                    redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING);
                } else {
                    // TODO: Handle else
                }
            }
        } catch (FuturaeAuthnFailedException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (UserIdNotFoundException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE);
        }
    }
}
