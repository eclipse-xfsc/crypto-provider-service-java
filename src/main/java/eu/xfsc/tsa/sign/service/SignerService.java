package eu.xfsc.tsa.sign.service;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.net.URI;
import java.time.OffsetDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.Plaintext;
import org.springframework.vault.support.Signature;
import org.springframework.vault.support.TransitKeyType;
import org.springframework.vault.support.VaultSignRequest;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64;

import eu.xfsc.tsa.sign.generated.controller.ApiUtil;
import eu.xfsc.tsa.sign.generated.controller.SignerApiDelegate;
import eu.xfsc.tsa.sign.generated.model.CreateCredentialRequestBody;
import eu.xfsc.tsa.sign.generated.model.Proof;
import eu.xfsc.tsa.sign.generated.model.ProofCredentialRequestBody;
import eu.xfsc.tsa.sign.generated.model.SignCredentialRequestBody;
import eu.xfsc.tsa.sign.generated.model.SignedCredentials;
import eu.xfsc.tsa.sign.generated.model.VerifiableCredentials;
import eu.xfsc.tsa.sign.generated.model.VerifyResult;
import eu.xfsc.tsa.sign.verify.SignatureVerifier;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class SignerService implements SignerApiDelegate {

    @Value("${signer.sign-with-vault:false}")
    private boolean signWithVault;

    @Autowired
    private VaultTemplate vault;
    @Autowired
    private ObjectMapper jsonMapper;
    @Autowired
    private SignatureVerifier verifier;
    @Autowired
    private DocumentLoader documentLoader;

    private SDSigner signer;

    public SignerService() {
        signer = new SDSigner();
    }

    @Override
    public ResponseEntity<SignedCredentials> createCredentials(String xOrigin, CreateCredentialRequestBody body) {
        log.debug("createCredentials.enter; origin: {}, body: {}", xOrigin, body);
        Map<String, Object> credentials = body.getAdditionalProperties();
        String path = body.getNamespace();
        if (!body.getGroup().isEmpty()) {
            path += "/" + body.getGroup(); 
        }
        String key = body.getKey();
        try {
            String json = jsonMapper.writeValueAsString(credentials);
            VerifiableCredentials vc = jsonMapper.readValue(json, VerifiableCredentials.class);
            cleanCredentials(credentials);
            log.debug("createCredentials; json: {}", json);
            SignedCredentials sc = signedFromVerifiable(vc);
            sc.getAdditionalProperties().putAll(credentials);
            String proof = signCredentials(path, key, json, sc.getIssuer().toString());
            sc.setProof(jsonMapper.readValue(proof, Proof.class));
            ResponseEntity<SignedCredentials> result = ResponseEntity.ok(sc); 
            log.debug("createCredentials.exit; returning: {}", result);
            return result;
        } catch (Exception ex) {
            log.error("createCredentials.error; failed to sign credentials", ex);
            return ResponseEntity.badRequest().build();
        }
    }

    @Override
    public ResponseEntity<SignedCredentials> proofCredentials(ProofCredentialRequestBody body) {
        log.debug("proofCredentials.enter; body: {}", body);
        VerifiableCredentials vc = body.getCredential();
        SignedCredentials sc = signedFromVerifiable(vc);
        String path = body.getNamespace();
        if (!body.getGroup().isEmpty()) {
            path += "/" + body.getGroup(); 
        }
        String key = body.getKey();
        try {
            String json = jsonMapper.writeValueAsString(vc);
            String proof = signCredentials(path, key, json, sc.getIssuer().toString());
            sc.setProof(jsonMapper.readValue(proof, Proof.class));
            ResponseEntity<SignedCredentials> result = ResponseEntity.ok(sc); 
            log.debug("proofCredentials.exit; returning: {}", result);
            return result;
        } catch (Exception ex) {
            log.error("proofCredentials.error; failed to sign credentials", ex);
            return ResponseEntity.badRequest().build();
        }
    }

    private String signCredentials(String path, String key, String json, String issuer) throws Exception {
        String proof;
        VaultTransitOperations transit = vault.opsForTransit(path);
        if (signWithVault) {
            Signature sign = transit.sign(key, VaultSignRequest.builder().plaintext(Plaintext.of(json)).build());
            log.debug("createCredentials; sign for vc: {}", sign);
            // not clear how to use this signature with proof..
            proof = sign.getSignature();
        } else {
            Map<String, String> keys = transit.exportKey(key, TransitKeyType.SIGNING_KEY).getKeys();
            log.debug("createCredentials; got keys: {}", keys.size());  // {1=P+lNhgNSBKlq6vAPZsnIA/pJx/yKu2r+QmvLx8gMbdoNciA2+TUgnRnnWq6rcIKowDOSTvj39uOCV04K3SAO8A==}
            String hash = keys.get("1");
            // now sign it internally..
            proof = signer.proof(json, hash, "pem", "RSA", issuer + "#" + key); //RS256  EdDSA
        }
        return proof;
    }

    @Override
    public ResponseEntity<SignedCredentials> signCredentials(SignCredentialRequestBody body) {
        log.debug("signCredentials.enter; body: {}", body);
        VerifiableCredentials vc = body.getCredential();
        SignedCredentials sc = signedFromVerifiable(vc);
        try {
            String json = jsonMapper.writeValueAsString(vc);
            String jwk = jsonMapper.writeValueAsString(body.getJwk());
            String did = "did:jwk:" + Base64.encode(jwk).toString();
            log.debug("signCredentials; jwk: {}, did: {}", jwk, did);
            // TODO: think how to get algorithm, from param or from jwk?
            String proof = signer.proof(json, jwk, "json", "EdDSA", did); //RS256  EdDSA
            sc.setProof(jsonMapper.readValue(proof, Proof.class));
            ResponseEntity<SignedCredentials> result = ResponseEntity.ok(sc); 
            log.debug("signCredentials.exit; returning: {}", result);
            return result;
        } catch (Exception ex) {
            log.error("signCredentials.error; failed to sign credentials", ex);
            return ResponseEntity.badRequest().build();
        }
    }

    @Override
    public ResponseEntity<VerifyResult> verifyCredentials(SignedCredentials credentials, String xFormat, String xNamespace, String xGroup) {
        log.debug("verifyCredentials.enter; credentials: {}", credentials);
        try {
            String jProof = jsonMapper.writeValueAsString(credentials.getProof());
            LdProof proof = LdProof.fromJson(jProof);
            String jVC = jsonMapper.writeValueAsString(credentials);
            Map<String, Object> mVC = jsonMapper.readValue(jVC, Map.class);
            JsonLDObject vc = JsonLDObject.fromMap(mVC);
            vc.setDocumentLoader(documentLoader);
            boolean result = verifier.checkSignature(vc, proof); 
            log.debug("verifyCredentials.exit; returning: {}", result);
            return ResponseEntity.ok().body(new VerifyResult(result));
        } catch (Exception ex) {
            log.error("verifyCredentials.error; failed to verify credentials", ex);
            return ResponseEntity.badRequest().build();
        }
    }

    private SignedCredentials signedFromVerifiable(VerifiableCredentials vc) {
        return SignedCredentials.builder()
            .atContext(vc.getAtContext())
            .id(vc.getId())
            .issuer(vc.getIssuer())
            .issuanceDate(vc.getIssuanceDate())
            .type(vc.getType())
            .credentialSubject(vc.getCredentialSubject())
            .additionalProperties(vc.getAdditionalProperties() == null ? Collections.emptyMap() : vc.getAdditionalProperties()) 
            .build();
    }

    private void cleanCredentials(Map<String, Object> credentials) {
        credentials.remove("@context");
        credentials.remove("credentialSubject");
        credentials.remove("id");
        credentials.remove("issuanceDate");
        credentials.remove("issuer");
        credentials.remove("type");
    }

}

