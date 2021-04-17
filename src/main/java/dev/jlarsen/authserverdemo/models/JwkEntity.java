package dev.jlarsen.authserverdemo.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.*;
import lombok.Data;

import javax.persistence.*;
import java.text.ParseException;

@Data
@Entity
public class JwkEntity {

    @Id
    @JsonIgnore
    private Integer id;
    private String kid;
    private String kty;
    @JsonProperty("use")
    private String _use;
    private String crv;
    private String d;
    private String x;
    private String y;
    private String alg;
    @Transient
    @JsonIgnore
    private ObjectMapper objectMapper = new ObjectMapper();

    public JwkEntity() {
    }

    public JWK toJwk() {
        try {
            return JWK.parse(objectMapper.writeValueAsString(this));
        } catch (ParseException | JsonProcessingException e) {
            return null;
        }
    }
}
