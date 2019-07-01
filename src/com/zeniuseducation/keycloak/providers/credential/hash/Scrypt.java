package com.zeniuseducation.keycloak.providers.credential.hash;

import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;

import com.lambdaworks.crypto.SCryptUtil;

public class Scrypt implements PasswordHashProviderFactory, PasswordHashProvider  {

	public static final String ID = "scrypt";

//    public CredentialModel encode(String rawPassword, int iterations, Byte salt) {
//        
//        String encodedPassword = encode(rawPassword, iterations);
//
//        CredentialModel credentials = new CredentialModel();
//        credentials.setAlgorithm(ID);
//        credentials.setType(UserCredentialModel.PASSWORD);
//        credentials.setSalt("".getBytes());
//        credentials.setHashIterations(iterations);
//        credentials.setValue(encodedPassword);
//        return credentials;
//    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        return credential.getHashIterations() == policy.getHashIterations() && ID.equals(credential.getAlgorithm());
    }
    @Override
    public void encode(String rawPassword, int iterations, CredentialModel credential) {
        
        String encodedPassword = encode(rawPassword, iterations);

        credential.setAlgorithm(ID);
        credential.setType(UserCredentialModel.PASSWORD);
        credential.setSalt("".getBytes());
        credential.setHashIterations(iterations);
        credential.setValue(encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credential) {
        return SCryptUtil.check(rawPassword, credential.getValue());
    }

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
    
    @Override
    public String encode(String rawPassword, int iterations) {
        try {
            return SCryptUtil.scrypt(rawPassword, iterations, 16, 1);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

}
