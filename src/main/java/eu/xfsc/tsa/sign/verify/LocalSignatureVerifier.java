package eu.xfsc.tsa.sign.verify;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.PublicKeyVerifierFactory;
import com.danubetech.keyformats.jose.JWK;

import eu.xfsc.tsa.sign.exception.VerificationException;
import eu.xfsc.tsa.sign.resolve.HttpDocumentResolver;
import foundation.identity.did.DIDDocument;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.verifier.JsonWebSignature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LocalSignatureVerifier implements SignatureVerifier {

    private static final Set<String> SIGNATURES = Set.of("JsonWebSignature2020"); 
	
	@Autowired
	private HttpDocumentResolver httpResolver;
    
    public LocalSignatureVerifier() {
      Security.addProvider(new BouncyCastleProvider());
    }

	@Override
	public boolean checkSignature(JsonLDObject payload, LdProof proof) {
	  try {
	    log.debug("checkSignature.enter; got payload, proof: {}", proof);
	    boolean result = getVerificationResult(payload, proof);
		log.debug("checkSignature.exit; returning: {}", result);
	    return result;
	  } catch (IOException ex) {
	    throw new VerificationException(ex);
	  }
	}

	private boolean getVerificationResult(JsonLDObject payload, LdProof proof) throws IOException {
	  log.debug("getVerifiedVerifier.enter;");
	    
	  if (!SIGNATURES.contains(proof.getType())) {
	    throw new VerificationException("Signatures error; The proof type is not supported yet: " + proof.getType());
	  }

	  URI uri = proof.getVerificationMethod();
	  if (!uri.getScheme().equals("did")) {
	    throw new VerificationException("Signatures error; Unknown Verification Method: " + uri);
	  }

	  DIDDocument diDoc = getDIDocFromURI(uri);
      Map<String, Object> jwkMap = getRelevantKey(diDoc, uri.toString());
	  if (jwkMap == null) {
    	throw new VerificationException("Signatures error; no proper VerificationMethod found");
	  } 
        
	  boolean result = false;
	  JWK jwk = JWK.fromMap(jwkMap);
	  try {	
	    if (verify(payload, proof, jwk, jwk.getAlg())) { 
		  result = true;
		}
	  } catch (Exception ex) {
	    log.info("getVerifiedVerifier.error: {}", ex.getMessage());
	  }
	  
	  if (!result) {
        throw new VerificationException("Signatures error; " + payload.getClass().getSimpleName() + " does not match with proof");
	  }
	  log.debug("getVerifiedVerifier.exit; returning: {}", result);
	  return result;
	}
	  
	@Override
	public boolean verify(JsonLDObject payload, LdProof proof, JWK jwk, String alg) {
      log.debug("verify; got jwk: {}, alg: {}", jwk, alg);
	  PublicKeyVerifier<?> pkVerifier = PublicKeyVerifierFactory.publicKeyVerifierForJWK(jwk, alg);
	  LdVerifier<?> verifier = new JsonWebSignature2020LdVerifier(pkVerifier);
	  try {
		return verifier.verify(payload);
	  } catch (IOException | GeneralSecurityException | JsonLDException ex) {
		log.info("verify.error: {}", ex.getMessage());
	  }
	  return false;
	}

	private DIDDocument getDIDocFromURI(URI uri) throws IOException { 
	  log.debug("readDIDFromURI.enter; got uri: {}", uri);
	  DIDDocument diDoc;
	  URI  docUri = resolveWebUri(uri);
	  if (docUri == null) {
	    throw new IOException("Couldn't load key. Method not supported");
	  }
	  diDoc = loadDIDocFromURI(docUri);
	  log.debug("readDIDFromURI.exit; returning: {}", diDoc);
	  return diDoc;
	}
	  
	private DIDDocument loadDIDocFromURI(URI docUri) throws IOException {
	  log.debug("loadDIDFromURL; loading DIDDocument from: {}", docUri.toString());
	  return httpResolver.resolveDidDocument(docUri.toString());
	}
	  
	@SuppressWarnings("unchecked")
	private Map<String, Object> getRelevantKey(DIDDocument diDoc, String verificationMethodURI) {
	  // better to get methods from doc using DIDDocument API...
	  List<Map<String, Object>> methods = (List<Map<String, Object>>) diDoc.toMap().get("verificationMethod");
	  log.debug("getRelevantJWK; methods: {}", methods);
	  for (Map<String, Object> method: methods) {
	    String id = (String) method.get("id");
	    if (verificationMethodURI.equals(id)) {
	      // publicKeyMultibase can be used also..  
	      return (Map<String, Object>) method.get("publicKeyJwk");
	    }
	  }
	  return null;
	}

	private URI resolveWebUri(URI uri) throws IOException {
	  String[] uri_parts = uri.getSchemeSpecificPart().split(":");
	  if (uri_parts.length >= 2 && "web".equals(uri_parts[0])) {
	    String url = "https://";
	    url += uri_parts[1];
		if (uri_parts.length == 2) {
		  url += "/.well-known";
		} else {
		  int idx;
		  try {
		      Integer.parseInt(uri_parts[2]);
		      url += ":" + uri_parts[2];
		      idx = 3;
		    } catch (NumberFormatException e) {
			  idx = 2;  
		    }
		    for (int i=idx; i < uri_parts.length; i++) {
			  url += "/" + uri_parts[i];
		    }
		  }
		  url += "/did.json";
		  if (uri.getFragment() != null) {
		    url += "#" + uri.getFragment();
		  }
		  try {
			return new URI(url);
		  } catch (URISyntaxException ex) {
			//log.warn("resolveWebUrl.error: {}, on url: {}", ex.getMessage(), url);
			throw new IOException(ex);
		  } 
	    }
	    return null;  
	}
}
