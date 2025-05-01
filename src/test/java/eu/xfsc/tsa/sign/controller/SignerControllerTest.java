package eu.xfsc.tsa.sign.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.UUID;

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.xfsc.tsa.sign.generated.model.SignedCredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SignerControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    //key-25519

    //@Test
    public void postCredentialsReturnSuccessResponse() throws Exception {
        String body = """
            {
                "namespace": "transit-ns",
                "key": "key-rsa2048",
                "group": "test-gr",
                "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                "credentialSubject": {
                    "hash": "QmbXgQJ67fawbWTHNQWjxT3KriaTopVXXc1fu9KTJkWPpS",
                    "id": "uuid:2632367287r82729",
                    "trustListURI": "https://tspa.train1.xfsc.dev/tspa-service/tspa/v1/bob.trust.train1.xfsc.dev/trust-list",
                    "trustListType": "XML based Trust List"
                },
                "id": "https://www.example.org/2632367287r82729",
                "issuanceDate": "2024-02-27T12:52:33.168245633Z",
                "issuer": "did:web:essif.iao.fraunhofer.de",
                "type": ["VerifiableCredential"]
            }""";

        mockMvc.perform(MockMvcRequestBuilders.post("/v1/credential")
                        .content(body)
                        //.with(csrf())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-origin", "http://test.org")
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.issuer").value("did:web:essif.iao.fraunhofer.de"))
                .andExpect(jsonPath("$.credentialSubject").exists())
                .andExpect(jsonPath("$.credentialSubject.id").value("uuid:2632367287r82729"))
                .andExpect(jsonPath("$.proof.jws").exists())
                .andExpect(jsonPath("$.proof.proofPurpose").value("assertionMethod"))
                .andExpect(jsonPath("$.proof.type").value("JsonWebSignature2020"))
                .andExpect(jsonPath("$.proof.verificationMethod").value("did:web:essif.iao.fraunhofer.de#key-rsa2048"))
                .andReturn();
    }

    //@Test
    public void postProofCredentialsReturnSuccessResponse() throws Exception {
        String body = """
            {
                "namespace": "transit-ns",
                "key": "key-rsa2048",
                "group": "test-gr",
                "credential": {
                    "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                    "credentialSubject": {
                        "hash": "QmbXgQJ67fawbWTHNQWjxT3KriaTopVXXc1fu9KTJkWPpS",
                        "id": "uuid:2632367287r82729",
                        "trustListURI": "https://tspa.train1.xfsc.dev/tspa-service/tspa/v1/bob.trust.train1.xfsc.dev/trust-list",
                        "trustListType": "XML based Trust List"
                    },
                    "id": "https://www.example.org/2632367287r82729",
                    "issuanceDate": "2024-02-27T12:52:33.168245633Z",
                    "issuer": "did:web:essif.iao.fraunhofer.de",
                    "type": ["VerifiableCredential"]
                }
            }""";

        mockMvc.perform(MockMvcRequestBuilders.post("/v1/credential/proof")
                        .content(body)
                        //.with(csrf())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-origin", "http://test.org")
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.issuer").value("did:web:essif.iao.fraunhofer.de"))
                .andExpect(jsonPath("$.credentialSubject").exists())
                .andExpect(jsonPath("$.credentialSubject.id").value("uuid:2632367287r82729"))
                .andExpect(jsonPath("$.proof.jws").exists())
                .andExpect(jsonPath("$.proof.proofPurpose").value("assertionMethod"))
                .andExpect(jsonPath("$.proof.type").value("JsonWebSignature2020"))
                .andExpect(jsonPath("$.proof.verificationMethod").value("did:web:essif.iao.fraunhofer.de#key-rsa2048"))
                .andReturn();
    }

    @Test
    public void postSignCredentialsReturnSuccessResponse() throws Exception {
        String body = """
            {
                "credential": {
                    "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                    "credentialSubject": {
                        "hash": "QmbXgQJ67fawbWTHNQWjxT3KriaTopVXXc1fu9KTJkWPpS",
                        "id": "uuid:2632367287r82729",
                        "trustListURI": "https://tspa.train1.xfsc.dev/tspa-service/tspa/v1/bob.trust.train1.xfsc.dev/trust-list",
                        "trustListType": "XML based Trust List"
                    },
                    "id": "https://www.example.org/2632367287r82729",
                    "issuanceDate": "2024-02-27T12:52:33.168245633Z",
                    "issuer": "did:web:essif.iao.fraunhofer.de",
                    "type": ["VerifiableCredential"]
                },
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ",
                    "d": "m5N7gTItgWz6udWjuqzJsqX-vksUnxJrNjD5OilScBc"
                }
            }"""; 

        MvcResult result = mockMvc.perform(MockMvcRequestBuilders.post("/v1/credential/sign")
                        .content(body)
                        //.with(csrf())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-origin", "http://test.org")
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.issuer").value("did:web:essif.iao.fraunhofer.de"))
                .andExpect(jsonPath("$.credentialSubject").exists())
                .andExpect(jsonPath("$.credentialSubject.id").value("uuid:2632367287r82729"))
                .andExpect(jsonPath("$.proof.jws").exists())
                .andExpect(jsonPath("$.proof.proofPurpose").value("assertionMethod"))
                .andExpect(jsonPath("$.proof.type").value("JsonWebSignature2020"))
                //.andExpect(jsonPath("$.proof.verificationMethod").value("did:web:essif.iao.fraunhofer.de"))
                .andReturn();
        SignedCredentials creds = objectMapper.readValue(result.getResponse().getContentAsString(), SignedCredentials.class);
        String vm = creds.getProof().getVerificationMethod().toString();
        assertTrue(vm.startsWith("did:jwk:"));
        String jwk = new String(Base64.decode(vm.substring(8)));
        Map<String, String> jwkm = objectMapper.readValue(jwk, Map.class);
        assertEquals("OKP", jwkm.get("kty"));
        assertEquals("Ed25519", jwkm.get("crv"));
        assertEquals("CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ", jwkm.get("x"));
        assertEquals("m5N7gTItgWz6udWjuqzJsqX-vksUnxJrNjD5OilScBc", jwkm.get("d"));
    }

    @Test
    public void postVerifyCredentialsReturnSuccessResponse() throws Exception {
        String body = """
            {
                "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"],
                "credentialSubject": {
                    "hash": "QmbXgQJ67fawbWTHNQWjxT3KriaTopVXXc1fu9KTJkWPpS",
                    "id": "uuid:2632367287r82729",
                    "trustListURI": "https://tspa.train1.xfsc.dev/tspa-service/tspa/v1/bob.trust.train1.xfsc.dev/trust-list",
                    "trustListType": "XML based Trust List"
                },
                "id": "https://www.example.org/2632367287r82729",
                "issuanceDate": "2024-02-27T12:52:33.168245633Z",
                "issuer": "did:web:essif.iao.fraunhofer.de",
                "type": ["VerifiableCredential"],
                "proof": {
                    "type": "JsonWebSignature2020",
                    "created": "2025-01-10T15:37:08Z",
                    "proofPurpose": "assertionMethod",
                    "verificationMethod": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkNWLWFHbGxkM25WZGduaG9aSzBEMzZXay05YUlNbFpqWk9LMlhoUE1ua1EiLCJkIjoibTVON2dUSXRnV3o2dWRXanVxekpzcVgtdmtzVW54SnJOakQ1T2lsU2NCYyJ9",
                    "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..trMiRCab3vXOaBgH9bA_iB1bEX9iKrvjbBPMEPrJ1N0cpYB9lHVA2mDqW7epUBIa9RqphT3lyG0nLf4qKTCpCg"
                }
            }"""; 

        MvcResult result = mockMvc.perform(MockMvcRequestBuilders.post("/v1/credential/verify")
                        .content(body)
                        //.with(csrf())
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                    //    .header("x-origin", "http://test.org")
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.valid").value(true))
                .andReturn();
    }

}
