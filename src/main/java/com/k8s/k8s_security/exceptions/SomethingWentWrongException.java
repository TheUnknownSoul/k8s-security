package com.k8s.k8s_security.exceptions;

public class SomethingWentWrongException extends RuntimeException {
    public SomethingWentWrongException(String message) {
        super(message);
    }
}
