package eu.xfsc.tsa.sign.service;

import com.apicatalog.jsonld.JsonLdError;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.PrivateKeySignerFactory;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.impl.RSA_PS256_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.RSA_PS256_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import com.danubetech.verifiablecredentials.VerifiablePresentation;
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialKeywords;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.suites.JsonWebSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.verifier.JsonWebSignature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import lombok.extern.slf4j.Slf4j;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Slf4j
public class SDSigner {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public String proof(String json, String prk, String type, String algo, String method) throws Exception {
		log.debug("proof.enter; got json: {}, prk: {}, type: {}, algo: {}, method: {}", json, prk.length(), type, algo,
				method);
		JsonLDObject ld = JsonLDObject.fromJson(json);
		if (ld.isType(VerifiableCredentialKeywords.JSONLD_TERM_VERIFIABLE_CREDENTIAL)) {
			VerifiableCredential vc = VerifiableCredential.fromJsonLDObject(ld);
			LdProof vc_proof = sign(vc, prk, type, algo, method);
			log.debug("proof.exit; got proof: {}", vc_proof);
			return vc_proof.toJson();
		}
		return null;
	}

	public LdProof sign(JsonLDObject credential, String prk, String type, String algo, String method)
			throws IOException, GeneralSecurityException, JsonLDException, URISyntaxException, JsonLdError {
		PrivateKeySigner<?> privateKeySigner;
		if ("pem".equals(type)) {
			try (PEMParser pemParser = new PEMParser(new StringReader(prk))) {
				Object inst = pemParser.readObject();
				PrivateKeyInfo privateKeyInfo;
				if (inst instanceof PEMKeyPair) {
					privateKeyInfo = ((PEMKeyPair) inst).getPrivateKeyInfo();
				} else {
					privateKeyInfo = PrivateKeyInfo.getInstance(inst);
				}
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
				PrivateKey pk = converter.getPrivateKey(privateKeyInfo);
				KeyPair kp = new KeyPair(null, pk);
				privateKeySigner = new RSA_PS256_PrivateKeySigner(kp);
			}
		} else if ("json".equals(type)) {
			JWK jwk = JWK.fromJson(prk);
			privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(jwk, algo);
		} else {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(prk.getBytes()); // Base64.getDecoder().decode(prk));
			PrivateKey pk = kf.generatePrivate(keySpecPKCS8);
			KeyPair kp = new KeyPair(null, pk);
			privateKeySigner = new RSA_PS256_PrivateKeySigner(kp);
		}

		LdSigner<JsonWebSignature2020SignatureSuite> signer = new JsonWebSignature2020LdSigner(privateKeySigner);
		signer.setCreated(new Date());
		signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
		signer.setVerificationMethod(URI.create(method));

		LdProof ldProof = signer.sign(credential);
		return ldProof;
	}

}
