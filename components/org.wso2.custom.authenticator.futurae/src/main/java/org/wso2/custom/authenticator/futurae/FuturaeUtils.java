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
                            throw new FuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.
                                    USER_NOT_FOUND.getCode(),
                                    FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND.getMessage());
                        }
                        if (StringUtils.isBlank(user.toFullQualifiedUsername())) {
                            if (log.isDebugEnabled()) {
                                log.debug("Username cannot be empty.");
                            }
                            throw new FuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.
                                    USER_NOT_FOUND.getCode(),
                                    FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND.getMessage());
                        }
                        return user;
                    }
                }
            }
        }
        // If authenticated user cannot be found from the previous steps.
        throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages
                .NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP);
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
            throw new AuthenticationFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode(),
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_FEDERATED_USER.getMessage());
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

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
            throw new AuthenticationFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION.
                            getCode(), FuturaeAuthenticatorConstants.ErrorMessages
                    .ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION.getMessage());
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
                    FuturaeAuthenticatorConstants.ErrorMessages.RETRIEVING_USER_STORE_FAILURE);
        }
        if (userRealm == null) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.RETRIEVING_USER_REALM_FAILURE);
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
                    FuturaeAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE, e);
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
            throw getFuturaeAuthnFailedException(FuturaeAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND, e);
        }
    }

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

    public static Property getProperty(FuturaeAuthenticatorConstants.ConfigProperties configProperties) {

        Property property = new Property();
        property.setName(configProperties.getName());
        property.setDisplayName(configProperties.getDisplayName());
        property.setDescription(configProperties.getDescription());
        property.setDisplayOrder(configProperties.getDisplayOrder());
        property.setRequired(true);
        return property;
    }

    public static void validateFuturaeConfiguration(String serviceHostname, String serviceId, String authApiKey,
                                                    String adminApiKey) throws FuturaeAuthnFailedException {

        // TODO : Add further validations
        if (StringUtils.isBlank(serviceHostname)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_SERVICE_HOSTNAME_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(serviceId)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_SERVICE_ID_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(authApiKey)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_AUTH_API_KEY_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(adminApiKey)) {
            throw getFuturaeAuthnFailedException(
                    FuturaeAuthenticatorConstants.ErrorMessages.FUTURAE_AUTH_API_KEY_INVALID_FAILURE);
        }
    }

    public static String getMaskedUsername(String username) {

        if (LoggerUtils.isLogMaskingEnable) {
            return LoggerUtils.getMaskedContent(username);
        }
        return username;
    }

    public static boolean isJitProvisioningEnabled(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return false;
        }
        return provisioningConfig.isProvisioningEnabled();
    }

    public static IdentityProvider getIdentityProvider(String idpName, String tenantDomain) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = FuturaeDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format(
                                FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR
                                        .getMessage(), idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(String.format(
                    FuturaeAuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR.getMessage(),
                    idpName, tenantDomain));
        }
    }

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
