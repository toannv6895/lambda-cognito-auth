package org.toannguyen;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class LoginRequest {
    String username;
    String password;
    String code;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
