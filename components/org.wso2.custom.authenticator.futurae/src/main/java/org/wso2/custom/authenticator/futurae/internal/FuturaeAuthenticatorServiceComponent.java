package org.wso2.custom.authenticator.futurae.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.authenticator.futurae.FuturaeAuthenticator;

/**
 * Service component class for the Futurae Authenticator initialization.
 */
@Component(
        name = "org.wso2.custom.identity.outbound.futurae",
        immediate = true)
public class FuturaeAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(FuturaeAuthenticatorServiceComponent.class);

    /**
     * This method is to register the Futurae authenticator service.
     *
     * @param ctxt The Component Context
     */
    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            FuturaeAuthenticator futuraeAuthenticator = new FuturaeAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    futuraeAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("Futurae Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating Futurae authenticator bundle ", e);
        }
    }

    /**
     * This method is to deactivate the Futurae authenticator the service.
     *
     * @param ctxt The Component Context
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Futurae Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        FuturaeDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        FuturaeDataHolder.setRealmService(null);
    }

    @Reference(
            name = "org.wso2.carbon.idp.mgt.IdpManager",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityProviderManagementService")
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        FuturaeDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        FuturaeDataHolder.setIdpManager(null);
    }

}

