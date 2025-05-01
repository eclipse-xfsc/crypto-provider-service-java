package eu.xfsc.tsa.sign.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;

@Configuration
public class VaultConfig extends AbstractVaultConfiguration {

    @Value("${signer.vault.token}")
    private String vToken;
    @Value("${signer.vault.uri}")
    private String vUri;

    @Override
    public ClientAuthentication clientAuthentication() {
        return new TokenAuthentication(vToken);
    }

    @Override
    public VaultEndpoint vaultEndpoint() {
        return VaultEndpoint.from(vUri);
    }
    
}