package org.wso2.custom.authenticator.futurae.internal;

import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service holder for Futurae Authenticator.
 */
public class FuturaeDataHolder {

    private static RealmService realmService;
    private static IdpManager idpManager;

    private FuturaeDataHolder() {

    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public static RealmService getRealmService() {

        if (realmService == null) {
            throw new RuntimeException("RealmService was not set during the iProov service component startup");
        }
        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public static void setRealmService(RealmService realmService) {

        FuturaeDataHolder.realmService = realmService;
    }

    /**
     * Get IdpManager.
     *
     * @return IdpManager.
     */
    public static IdpManager getIdpManager() {

        return idpManager;
    }

    /**
     * Set IdpManager.
     *
     * @param idpManager IdpManager.
     */
    public static void setIdpManager(IdpManager idpManager) {

        FuturaeDataHolder.idpManager = idpManager;
    }
}
