package org.wso2.custom.authenticator.futurae;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
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
import java.util.HashMap;
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
     * Returns all configuration input fields of the authenticator.
     *
     * @return List Returns the custom authenticator properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        // Get the required configuration properties.
        List<Property> configProperties = new ArrayList<>();
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME));
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID));
        configProperties.add(getProperty(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY));
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

        return StringUtils.isNotBlank(request.getParameter(FuturaeAuthenticatorConstants.AUTH_TYPE)) &&
                request.getParameter(FuturaeAuthenticatorConstants.AUTH_TYPE).equals(
                        FuturaeAuthenticatorConstants.AUTH_TYPE_FUTURAE) &&
                StringUtils.isNotBlank(request.getParameter(FuturaeAuthenticatorConstants.SESSION_DATA_KEY));
    }

    /**
     * Redirects the user to the login page for authentication purposes. This authenticator redirects the user to the
     * Futurae login page deployed with the IS.
     *
     * @param request  The request that is received by the authenticator.
     * @param response Appends the authorized URL once a valid authorized URL is built.
     * @param context  The Authentication context received by the authenticator.
     * @throws AuthenticationFailedException Exception thrown during authentication flow.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        initiateFuturaeAuthenticationRequest(request, response, context);
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
            LOG.debug("Authenticated user is not found in the context.");
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .AUTHENTICATED_USER_NOT_FOUND);
        }

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);

        String tenantDomain = authenticatedUserFromContext.getTenantDomain();
        if (StringUtils.isBlank(tenantDomain)) {
            throw new AuthenticationFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.USER_TENANT_NOT_FOUND.getCode(),
                    FuturaeAuthenticatorConstants.ErrorMessages.USER_TENANT_NOT_FOUND.getMessage());
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
            // If an intermediate authentication request comes, then go through this flow.
            String authStatus = (String) context.getProperty(FuturaeAuthenticatorConstants.AUTH_STATUS);

            if (FuturaeAuthenticatorConstants.AuthenticationStatus.COMPLETED.getName().equals(authStatus)) {
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;

            } else if (FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING.getName().equals(authStatus)) {
                // Pending authentication completion at the Futurae side.
                redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING);
                return AuthenticatorFlowStatus.INCOMPLETE;

            } else if (FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED.getName().equals(authStatus)) {
                redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED);
                return AuthenticatorFlowStatus.INCOMPLETE;

            } else if (FuturaeAuthenticatorConstants.AuthenticationStatus.ENROLLMENT_COMPLETED.getName().equals(authStatus)) {
                // Device enrolled successfully. Clear enrollment state and begin authentication.
                completeEnrollmentState(context);
                initiateFuturaeAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }

        initiateFuturaeAuthenticationRequest(request, response, context);
        return AuthenticatorFlowStatus.INCOMPLETE;
    }

    /**
     * Entry point for the Futurae authentication flow. Resolves the authenticating user, then branches on whether
     * a Futurae ID is already stored in WSO2 IS:
     * <ul>
     *   <li>No Futurae ID — delegates to {@link #handleEnrollmentFlow} to enroll a new device.</li>
     *   <li>Futurae ID present — delegates to {@link #handleAuthenticationFlow} to send a push notification.</li>
     * </ul>
     *
     * @param request  The request received by the authenticator.
     * @param response The response used to redirect the user.
     * @param context  The authentication context for the current session.
     * @throws AuthenticationFailedException if user resolution, enrollment, or authentication initiation fails.
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

            // If log masking if enabled, get masked username for logging purposes.
            String maskedUsername = getMaskedUsername(authenticatingUser.getUserName());

            // Extract and validate Futurae authenticator configurations.
            Map<String, String> futuraeConfig = extractAndValidateFuturaeConfig(context);

            // Extract the claim used to store Futurae user id.
            // This is the claim used to decide if the user is already enrolled with Futurae or not.
            // If this value exists, that means the user has already enrolled a device.
            futuraeId = getClaimValue(authenticatingUser, FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM);

            if (StringUtils.isBlank(futuraeId)) {
                handleEnrollmentFlow(authenticatingUser, maskedUsername,
                        futuraeConfig, context, response);
            } else {
                handleAuthenticationFlow(authenticatingUser, maskedUsername,
                        futuraeConfig, context, response);
            }
        } catch (FuturaeAuthnFailedException e) {
            if (FuturaeAuthenticatorConstants.ErrorMessages.PREAUTH_DENIED_FAILURE.getCode().equals(e.getErrorCode())) {
                redirectFuturaeLoginPage(response, context,
                        FuturaeAuthenticatorConstants.AuthenticationStatus.FUTURAE_LOGIN_DENIED);
            } else {
                LOG.error("Authentication failed in Futurae authenticator.", e);
                redirectFuturaeLoginPage(response, context,
                        FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED);
            }
        } catch (UserIdNotFoundException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND, e);
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.REGISTERED_USER_RETRIEVAL_FAILURE, e);
        }
    }

    /**
     * Finalises a successful enrollment: persists the Futurae user ID claim and clears the enrollment-related
     * properties from the authentication context so that the next call to
     * {@link #initiateFuturaeAuthenticationRequest} enters the normal authentication path.
     *
     * @param context The authentication context for the current session.
     * @throws FuturaeAuthnFailedException if the Futurae user ID is missing from the context or the claim
     *                                     cannot be persisted.
     */
    private void completeEnrollmentState(AuthenticationContext context) throws FuturaeAuthnFailedException {

        LOG.debug("Device enrollment completed. Clearing enrollment state and initiating authentication.");

        // Get futuraeId of the enrolled user from context and set it to the claim.
        String futuraeId = (String) context.getProperty(FuturaeAuthenticatorConstants.FUTURAE_USER_ID);
        if (StringUtils.isBlank(futuraeId)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_USER_ID_NOT_FOUND);
        }
        try {
            context.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS, null);
            context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_ENROLLMENT_ID, null);
            AuthenticatedUser authenticatingUser = (AuthenticatedUser) context.getProperty(FuturaeAuthenticatorConstants
                    .AUTHENTICATED_USER);
            setClaimValue(authenticatingUser, FuturaeAuthenticatorConstants.FUTURAE_USER_ID_CLAIM, futuraeId);
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.USER_CLAIM_UPDATE_FAILURE, e);
        }
    }

    /**
     * Extracts the Futurae service configuration from the authenticator properties and validates them.
     *
     * @param context The authentication context.
     * @return Map containing serviceHostname, serviceId, and authApiKey.
     * @throws FuturaeAuthnFailedException if any required configuration is invalid.
     */
    private Map<String, String> extractAndValidateFuturaeConfig(AuthenticationContext context)
            throws FuturaeAuthnFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String serviceHostname = authenticatorProperties.get(
                FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName());
        String serviceID = authenticatorProperties.get(
                FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName());
        String authApiKey = authenticatorProperties.get(
                FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName());

        validateFuturaeConfiguration(serviceHostname, serviceID, authApiKey);

        Map<String, String> config = new HashMap<>();
        config.put(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_HOSTNAME.getName(), serviceHostname);
        config.put(FuturaeAuthenticatorConstants.ConfigProperties.SERVICE_ID.getName(), serviceID);
        config.put(FuturaeAuthenticatorConstants.ConfigProperties.AUTH_API_KEY.getName(), authApiKey);
        return config;
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

        redirectFuturaeLoginPage(response, context, authenticationStatus, null);
    }

    /**
     * Redirects the user to the Futurae login page, optionally including a status message and an enrollment QR code
     * URL as query parameters. Used during the enrollment flow to display the QR code to the user.
     *
     * @param response             The response sent from the authenticator.
     * @param context              The authentication context for the current session.
     * @param authenticationStatus The current authentication status to pass as a query parameter; may be {@code null}.
     * @param enrollmentQrUrl      The Futurae-hosted QR code URL for device enrollment; may be {@code null} or blank.
     * @throws FuturaeAuthnFailedException if the redirect URL cannot be built or the redirect fails.
     */
    private void redirectFuturaeLoginPage(HttpServletResponse response, AuthenticationContext context,
                                          FuturaeAuthenticatorConstants.AuthenticationStatus authenticationStatus,
                                          String enrollmentQrUrl)
            throws FuturaeAuthnFailedException {

        try {
            ServiceURLBuilder futuraeLoginPageURLBuilder = ServiceURLBuilder.create()
                    .addPath(FuturaeAuthenticatorConstants.FUTURAE_LOGIN_PAGE)
                    .addParameter(FuturaeAuthenticatorConstants.SESSION_DATA_KEY, context.getContextIdentifier())
                    .addParameter("AuthenticatorName", FuturaeAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME)
                    .addParameter(FuturaeAuthenticatorConstants.TENANT_DOMAIN, context.getTenantDomain());

            if (authenticationStatus != null) {
                futuraeLoginPageURLBuilder.addParameter("status", authenticationStatus.getName());
                futuraeLoginPageURLBuilder.addParameter("message", authenticationStatus.getMessage());
            }

            if (StringUtils.isNotBlank(enrollmentQrUrl)) {
                futuraeLoginPageURLBuilder.addParameter(
                        FuturaeAuthenticatorConstants.ENROLLMENT_QR_URL_PARAM, enrollmentQrUrl);
            }

            String futuraeLoginPageURL = futuraeLoginPageURLBuilder.build().getAbsolutePublicURL();
            response.sendRedirect(futuraeLoginPageURL);

        } catch (IOException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.LOGIN_REDIRECT_FAILURE, e);
        } catch (URLBuilderException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.LOGIN_URL_BUILD_FAILURE, e);
        }
    }

    /**
     * Determines which enrollment path to take for a user who has no Futurae ID stored in WSO2 IS.
     * Looks up the username in Futurae: if not found, delegates to {@link #enrollNewUser}; if found,
     * delegates to {@link #enrollExistingUser} (re-enrollment after device loss).
     *
     * @param authenticatingUser The WSO2 user being authenticated.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @param context            The authentication context for the current session.
     * @param response           The response used to redirect the user.
     * @throws AuthenticationFailedException if the enrollment initiation fails.
     * @throws UserStoreException            if reading or writing user claims fails.
     */
    private void handleEnrollmentFlow(AuthenticatedUser authenticatingUser, String maskedUsername,
                                      Map<String, String> futuraeConfig, AuthenticationContext context,
                                      HttpServletResponse response)
            throws AuthenticationFailedException, UserStoreException {

        UserSearchResponse futuraeUser = FuturaeAuthenticationAPIClient.lookupUserByUsername(
                futuraeConfig, authenticatingUser.getUserName());

        // The user does not exist in Futurae either. Enroll a device as a new Futurae user.
        if (futuraeUser == null) {
            enrollNewUser(authenticatingUser, maskedUsername, futuraeConfig, context, response);
            return;
        }

        // A user exists in Futurae with the same username.
        // Enroll a new device to that user after deleting any existing devices.
        enrollExistingUser(futuraeUser.getUser_id(), maskedUsername, futuraeConfig, context, response);
    }

    /**
     * Creates a new Futurae user for the given WSO2 user, initiates device enrollment, persists the returned
     * Futurae user ID claim, and redirects the user to the QR code page.
     *
     * @param authenticatingUser The WSO2 user being enrolled.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @param context            The authentication context for the current session.
     * @param response           The response used to redirect the user to the QR code page.
     * @throws AuthenticationFailedException if the enrollment API call or redirect fails.
     */
    private void enrollNewUser(AuthenticatedUser authenticatingUser, String maskedUsername,
                               Map<String, String> futuraeConfig, AuthenticationContext context,
                               HttpServletResponse response)
            throws AuthenticationFailedException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("User " + maskedUsername + " was not found in Futurae. Triggering new user enrollment.");
        }

        EnrollRequest enrollRequest = EnrollRequest.forNewUser().setUsername(authenticatingUser.getUserName());
        EnrollResponse enrollResponse = FuturaeAuthenticationAPIClient.enrollDevice(futuraeConfig, enrollRequest);

        if (LOG.isDebugEnabled()) {
            LOG.debug("New Futurae user created and enrollment initiated for " + maskedUsername + " with Enrollment " +
                    "ID: " + enrollResponse.getEnrollment_id());
        }

        context.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS,
                FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING_ENROLLMENT.getName());
        // Setting the Futurae enrollment id to context so that enrollment state can be polled using it.
        context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_ENROLLMENT_ID,
                enrollResponse.getEnrollment_id());
        // Setting the Futurae user id to context so that it can be persisted after enrollment is completed.
        context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_USER_ID,
                enrollResponse.getUser_id());

        redirectFuturaeLoginPage(response, context,
                FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING_ENROLLMENT,
                enrollResponse.getActivation_qrcode_url());
    }

    /**
     * Re-enrolls a device for a user who already exists in Futurae but has no Futurae ID stored in WSO2 IS.
     * Initiates enrollment using the existing Futurae user ID and redirects the user to the QR code page.
     *
     * @param futuraeId          The existing Futurae user ID returned by the user lookup.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @param context            The authentication context for the current session.
     * @param response           The response used to redirect the user to the QR code page.
     * @throws AuthenticationFailedException if the enrollment API call or redirect fails.
     */
    private void enrollExistingUser(String futuraeId, String maskedUsername,
                                    Map<String, String> futuraeConfig, AuthenticationContext context,
                                    HttpServletResponse response)
            throws AuthenticationFailedException {

        unenrollDevicesIfPresent(futuraeId, maskedUsername, futuraeConfig);

        EnrollRequest enrollRequest = EnrollRequest.forExistingUser(futuraeId);
        EnrollResponse enrollResponse = FuturaeAuthenticationAPIClient.enrollDevice(futuraeConfig, enrollRequest);

        context.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS,
                FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING_ENROLLMENT.getName());
        // Setting the Futurae enrollment id to context so that enrollment state can be polled using it.
        context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_ENROLLMENT_ID,
                enrollResponse.getEnrollment_id());
        // Setting the Futurae user id to context so that it can be persisted after enrollment is completed.
        context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_USER_ID,
                enrollResponse.getUser_id());

        redirectFuturaeLoginPage(response, context,
                FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING_ENROLLMENT,
                enrollResponse.getActivation_qrcode_url());
    }

    /**
     * Unenrolls currently registered devices from Futurae for the given user.
     * This is called before re-enrolling a new device for an existing Futurae user.
     *
     * @param futuraeUserId      User ID in the Futurae side.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @throws AuthenticationFailedException if the unenroll API call or claim update fails.
     */
    private void unenrollDevicesIfPresent(String futuraeUserId, String maskedUsername,
                                          Map<String, String> futuraeConfig)
            throws AuthenticationFailedException {


        UserInfoResponse userInfo = FuturaeAuthenticationAPIClient.getUserInfo(futuraeConfig, futuraeUserId);

        List<Device> devices = userInfo.getDevices();
        if (devices == null || devices.isEmpty()) {
            LOG.debug("No enrolled devices found for user " + maskedUsername + ". Skipping unenrollment.");
            return;
        }

        if (devices.size() > 1) {
            LOG.warn("Multiple enrolled devices found for user " + maskedUsername + ". Only one device is " +
                    "expected. Unenrolling all devices.");
        }

        for (Device device : devices) {
            String deviceId = device.getDevice_id();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Unenrolling device " + deviceId + " for user " + maskedUsername + ".");
            }

            UnenrollDeviceResponse unenrollResponse = FuturaeAuthenticationAPIClient.unenrollDevice(
                    futuraeConfig,
                    UnenrollDeviceRequest.byUserId(futuraeUserId, deviceId)
            );

            String result = unenrollResponse.getResult();

            if (StringUtils.isNotBlank(result) && (FuturaeAuthenticatorConstants.UNENROLL_SUCCESS.equals(result)
                    || FuturaeAuthenticatorConstants.UNENROLL_SUCCESS_2FA.equals(result))) {
                LOG.debug("Successfully unenrolled device " + deviceId + " for user " + maskedUsername + ".");
            } else {
                LOG.error("Unenrollment failed for device " + deviceId + " for user " + maskedUsername +
                        ". Result: " + result);
                throw getFuturaeAuthnFailedException(
                        FuturaeAuthenticatorConstants.ErrorMessages.DEVICE_UNENROLL_FAILURE);
            }
        }
    }

    /**
     * Handles authentication for a user who already has a Futurae ID stored in WSO2 IS. Calls the Futurae
     * pre-auth endpoint to determine whether the user may authenticate, then either sends a push notification
     * via {@link #sendPushAndRedirect} or handles the failure via {@link #handlePreAuthFailure}.
     *
     * @param authenticatingUser The WSO2 user being authenticated.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @param context            The authentication context for the current session.
     * @param response           The response used to redirect the user.
     * @throws FuturaeAuthnFailedException if the pre-auth or authentication request fails.
     */
    private void handleAuthenticationFlow(AuthenticatedUser authenticatingUser, String maskedUsername,
                                          Map<String, String> futuraeConfig, AuthenticationContext context,
                                          HttpServletResponse response) throws FuturaeAuthnFailedException {

        LOG.debug("Futurae Id available in WSO2 IS for user " + maskedUsername + ". " + "Triggering " +
                    "authentication with Futurae.");

        PreAuthResponse authResponse = FuturaeAuthenticationAPIClient.getAuthenticationOptions(futuraeConfig,
                        authenticatingUser.getUserName(), "");

        if (isUserAuthInFuturaeAllowed(authResponse)) {
            sendPushAndRedirect(authenticatingUser, maskedUsername, futuraeConfig, context, response);
        }
    }

    /**
     * Returns {@code true} if the Futurae pre-auth response indicates the user is eligible for
     * "approve" (push notification) authentication.
     *
     * @param preAuthResponse The pre-auth response from Futurae.
     * @return {@code true} when the result is {@code auth} and {@code approve} is in the allowed factors.
     */
    private boolean isUserAuthInFuturaeAllowed(PreAuthResponse preAuthResponse) throws FuturaeAuthnFailedException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Futurae pre-auth response - result: " + preAuthResponse.getResult()
                    + ", allowed_factors: " + preAuthResponse.getAllowed_factors());
        }
        boolean allowed = false;

        if (preAuthResponse.getResult() != null ) {

            if (preAuthResponse.getResult() == FuturaeAuthenticatorConstants.PreAuthResult.auth) {
                if (preAuthResponse.getAllowed_factors() != null &&
                        preAuthResponse.getAllowed_factors().contains(FuturaeAuthenticatorConstants.APPROVE)) {
                    allowed = true;
                } else {
                    LOG.warn("Futurae 'approve' factor is not allowed for this user. result: " +
                            preAuthResponse.getResult() + ", allowed_factors: " + preAuthResponse.getAllowed_factors());
                }

            } else if (preAuthResponse.getResult() == FuturaeAuthenticatorConstants.PreAuthResult.deny) {
                LOG.error("Futurae pre-auth returned 'deny'. User locked or no devices in Futurae.");
                throw getFuturaeAuthnFailedException(
                        FuturaeAuthenticatorConstants.ErrorMessages.PREAUTH_DENIED_FAILURE);

            } else if (preAuthResponse.getResult() == FuturaeAuthenticatorConstants.PreAuthResult.unknown) {
                LOG.error("Futurae pre-auth returned 'unknown'. User not registered in Futurae.");
                throw getFuturaeAuthnFailedException(
                        FuturaeAuthenticatorConstants.ErrorMessages.PREAUTH_UNKNOWN_FAILURE);

            } else if (preAuthResponse.getResult() == FuturaeAuthenticatorConstants.PreAuthResult.allow) {
                LOG.debug("Futurae pre-auth returned 'allow' (state not supported).");
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.PREAUTH_ALLOW_FAILURE);

            } else {
                LOG.debug("Futurae pre-auth returned unsupported factor.");
                throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.PREAUTH_FAILED_FAILURE);
            }
        }

        return allowed;
    }

    /**
     * Sends a Futurae "approve" push notification to the user's registered device, stores the resulting
     * Futurae session ID in the authentication context, and redirects the user to the polling page.
     *
     * @param authenticatingUser The WSO2 user receiving the push notification.
     * @param maskedUsername     A masked version of the username for safe logging.
     * @param futuraeConfig      Futurae service configuration (hostname, service ID, API key).
     * @param context            The authentication context for the current session.
     * @param response           The response used to redirect the user to the pending page.
     * @throws FuturaeAuthnFailedException if the auth request or redirect fails.
     */
    private void sendPushAndRedirect(AuthenticatedUser authenticatingUser, String maskedUsername,
                                     Map<String, String> futuraeConfig, AuthenticationContext context,
                                     HttpServletResponse response)
            throws FuturaeAuthnFailedException {

        String username = authenticatingUser.getUserName();

        AuthResponse futuraeAuthResponse = FuturaeAuthenticationAPIClient.sendAuthRequest(futuraeConfig, username,
                FuturaeAuthenticatorConstants.APPROVE);

        String sessionId = futuraeAuthResponse.getSession_id();

        if (StringUtils.isBlank(sessionId)) {
            LOG.debug("Futurae Session ID is null/empty for user " + maskedUsername);
            redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.FAILED);
            return;
        }

        LOG.debug("Successfully sent Futurae push notification for user " + maskedUsername);

        context.setProperty(FuturaeAuthenticatorConstants.AUTH_STATUS,
                FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING.getName());
        context.setProperty(FuturaeAuthenticatorConstants.FUTURAE_SESSION_ID, sessionId);
        context.setProperty(FuturaeAuthenticatorConstants.USERNAME, username);

        redirectFuturaeLoginPage(response, context, FuturaeAuthenticatorConstants.AuthenticationStatus.PENDING);
    }
}
