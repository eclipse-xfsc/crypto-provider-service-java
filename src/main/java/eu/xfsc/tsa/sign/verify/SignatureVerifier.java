package eu.xfsc.tsa.sign.verify;


import com.danubetech.keyformats.jose.JWK;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;

public interface SignatureVerifier {

	  boolean checkSignature(JsonLDObject payload, LdProof proof);
	  boolean verify(JsonLDObject payload, LdProof proof, JWK jwk, String alg);
	
}
