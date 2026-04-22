package org.wso2.custom.authenticator.futurae;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.custom.authenticator.futurae.common.constants.FuturaeAuthenticatorConstants;
import org.wso2.custom.authenticator.futurae.common.exception.FuturaeAuthnFailedException;
import org.wso2.custom.authenticator.futurae.internal.FuturaeDataHolder;


import java.util.Map;

import static org.wso2.custom.authenticator.futurae.common.util.FuturaeUtils.getFuturaeAuthnFailedException;

public class FuturaeUtils {

    private static final Log log = LogFactory.getLog(FuturaeUtils.class);

    /**
     * Retrieve the authenticated user from the subject attribute step in the authentication context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser from the subject attribute step.
     * @throws FuturaeAuthnFailedException If no authenticated user is found or the username is blank.
     */
    public static AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws FuturaeAuthnFailedException {

        if (context.getSequenceConfig() != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            // Loop through the authentication steps and find the authenticated user from the subject identifier step.
            if (stepConfigMap != null) {
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    AuthenticatedUser user = stepConfig.getAuthenticatedUser();
                    if (stepConfig.isSubjectAttributeStep()) {
                        if (user == null) {
                            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                                    .USER_NOT_FOUND);
                        }
                        if (StringUtils.isBlank(user.toFullQualifiedUsername())) {
                            log.debug("Username cannot be empty.");
                            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                                    .USER_NOT_FOUND);
                        }
                        return user;
                    }
                }
            }
        }
        // If authenticated user cannot be found from the previous steps.
        throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                .AUTHENTICATED_USER_NOT_FOUND);
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username.
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    public static String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }

        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                    .FEDERATED_USER_NOT_FOUND);
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Resolve the authenticating user for the current step. For local users the authenticated user from context is
     * returned as-is. For federated users, JIT provisioning must be enabled; on the initial federation attempt the
     * federated user is returned directly, and on subsequent attempts an {@link AuthenticatedUser} is built from the
     * mapped local username and provisioned user-store domain.
     *
     * @param context                      AuthenticationContext.
     * @param authenticatedUserInContext   Authenticated user obtained from the authentication context.
     * @param mappedLocalUsername          Local username mapped from the federated user, or {@code null} if not yet
     *                                     provisioned.
     * @param tenantDomain                 Tenant domain of the authenticating user.
     * @param isInitialFederationAttempt   {@code true} if this is the first authentication attempt for the federated
     *                                     user (i.e. the user has not yet been provisioned locally).
     * @return Resolved {@link AuthenticatedUser} for this authentication step.
     * @throws AuthenticationFailedException If JIT provisioning is not enabled or the federated authenticator is
     *                                       invalid.
     */
    public static AuthenticatedUser resolveAuthenticatingUser(AuthenticationContext context,
                                                        AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }

        if (!isJitProvisioningEnabled(authenticatedUserInContext, tenantDomain)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FEDERATED_USER_JIT_DISABLED);
        }

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            context.setProperty(FuturaeAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT, true);
            return authenticatedUserInContext;
        }

        /*
        At this point, the authenticating user is in our system but can have a different mapped username compared to the
        identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
        with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    /**
     * Get the user realm of the logged-in user.
     *
     * @param username Fully qualified username.
     * @return The userRealm.
     * @throws AuthenticationFailedException
     */
    public static UserRealm getUserRealm(String username) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (username != null) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = FuturaeDataHolder.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.USER_STORE_RETRIEVAL_FAILURE, e);
        }
        if (userRealm == null) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.USER_REALM_RETRIEVAL_FAILURE);
        }
        return userRealm;
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    public static UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException, UserStoreException {

        UserRealm userRealm = getUserRealm(authenticatedUser.toFullQualifiedUsername());
        try {
            return userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.REGISTERED_USER_RETRIEVAL_FAILURE, e);
        }
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    public static String getClaimValue(AuthenticatedUser authenticatedUser, String claimUrl)
            throws AuthenticationFailedException, UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUrl}, null);
            return claimValues.get(claimUrl);
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.CLAIM_RETRIEVAL_FAILURE, e);
        }
    }

    /**
     * Set a user claim value in the user store for the given authenticated user.
     *
     * @param authenticatedUser AuthenticatedUser whose claim is to be updated.
     * @param claimUrl          Claim URI.
     * @param claimValue        Value to set for the claim.
     * @throws AuthenticationFailedException If the user store manager cannot be obtained or the user is not found.
     * @throws UserStoreException            If an error occurs while setting the claim value.
     */
    public static void setClaimValue(AuthenticatedUser authenticatedUser, String claimUrl, String claimValue)
            throws AuthenticationFailedException, UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            userStoreManager.setUserClaimValue(
                    MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername()),
                    claimUrl,
                    claimValue,
                    null
            );
        } catch (UserStoreException e) {
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND, e);
        }
    }

    /**
     * Resolve the WSO2 user ID for the given authenticated user.
     *
     * @param authenticatingUser AuthenticatedUser whose ID is to be resolved.
     * @return User ID string, or {@code null} if the claim is not set for a federated user.
     * @throws AuthenticationFailedException If the user store manager cannot be obtained.
     * @throws UserStoreException            If an error occurs while reading claims from the user store.
     * @throws UserIdNotFoundException       If the user ID cannot be found for a local user.
     */
    public static String resolveUserId(AuthenticatedUser authenticatingUser) throws AuthenticationFailedException,
            UserStoreException, UserIdNotFoundException {

        if (authenticatingUser.isFederatedUser()) {
            UserStoreManager userStoreManager = getUserStoreManager(authenticatingUser);
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                                    authenticatingUser.toFullQualifiedUsername()),
                            new String[]{FuturaeAuthenticatorConstants.USER_ID_CLAIM}, null);
            return claimValues.get(FuturaeAuthenticatorConstants.USER_ID_CLAIM);
        }
        return authenticatingUser.getUserId();
    }

    /**
     * Build an {@link Property} instance from a {@link FuturaeAuthenticatorConstants.ConfigProperties} enum value.
     * The property is marked as required and its name, display name, description, and display order are populated
     * from the enum constant.
     *
     * @param configProperties Enum constant describing the authenticator configuration property.
     * @return Populated {@link Property} ready to be returned from
     *         {@link org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator#getConfigurationProperties()}.
     */
    public static Property getProperty(FuturaeAuthenticatorConstants.ConfigProperties configProperties) {

        Property property = new Property();
        property.setName(configProperties.getName());
        property.setDisplayName(configProperties.getDisplayName());
        property.setDescription(configProperties.getDescription());
        property.setDisplayOrder(configProperties.getDisplayOrder());
        property.setRequired(true);
        return property;
    }

    /**
     * Validate the mandatory Futurae authenticator configuration parameters. Throws a
     * {@link FuturaeAuthnFailedException} with a specific error code if any value is blank.
     *
     * @param serviceHostname Futurae service hostname.
     * @param serviceId       Futurae service ID.
     * @param authApiKey      Futurae authentication API key.
     * @throws FuturaeAuthnFailedException If any of the required configuration values is blank.
     */
    public static void validateFuturaeConfiguration(String serviceHostname, String serviceId, String authApiKey) throws FuturaeAuthnFailedException {

        if (StringUtils.isBlank(serviceHostname)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.CONFIG_HOSTNAME_INVALID);
        }

        if (StringUtils.isBlank(serviceId)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.CONFIG_SERVICE_ID_INVALID);
        }

        if (StringUtils.isBlank(authApiKey)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.CONFIG_AUTH_API_KEY_INVALID);
        }
    }

    /**
     * Return a masked version of the username when log masking is enabled, or the plain username otherwise.
     * Use this method whenever logging a username to avoid exposing PII in log files.
     *
     * @param username Username to mask.
     * @return Masked username if log masking is enabled; otherwise the original username.
     */
    public static String getMaskedUsername(String username) {

        if (LoggerUtils.isLogMaskingEnable) {
            return LoggerUtils.getMaskedContent(username);
        }
        return username;
    }

    /**
     * Check whether Just-In-Time (JIT) provisioning is enabled for the identity provider associated with the given
     * federated user.
     *
     * @param user         Federated {@link AuthenticatedUser}.
     * @param tenantDomain Tenant domain in which to look up the identity provider.
     * @return {@code true} if JIT provisioning is enabled for the user's IdP; {@code false} otherwise.
     * @throws AuthenticationFailedException If the identity provider cannot be retrieved.
     */
    public static boolean isJitProvisioningEnabled(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                    tenantDomain));
            return false;
        }
        return provisioningConfig.isProvisioningEnabled();
    }

    /**
     * Retrieve the {@link IdentityProvider} by name for the given tenant domain.
     *
     * @param idpName      Name of the identity provider.
     * @param tenantDomain Tenant domain in which to look up the identity provider.
     * @return The matching {@link IdentityProvider}.
     * @throws AuthenticationFailedException If the identity provider is not found or cannot be retrieved.
     */
    public static IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = FuturaeDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format(
                                FuturaeAuthenticatorConstants.ErrorMessages.FEDERATED_AUTHENTICATOR_NOT_FOUND
                                        .getMessage(), idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(String.format(
                    FuturaeAuthenticatorConstants.ErrorMessages.FEDERATED_AUTHENTICATOR_NOT_FOUND.getMessage(),
                    idpName, tenantDomain));
        }
    }

    /**
     * Retrieve the user-store domain configured for JIT provisioning on the identity provider associated with the
     * given federated user.
     *
     * @param user         Federated {@link AuthenticatedUser}.
     * @param tenantDomain Tenant domain in which to look up the identity provider.
     * @return The provisioning user-store domain, or {@code null} if no JIT provisioning config is present.
     * @throws AuthenticationFailedException If the identity provider cannot be retrieved.
     */
    public static String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();

        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting userstore: %s as the provisioning userstore for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }
}
