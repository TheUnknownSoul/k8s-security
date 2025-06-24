package com.k8s.k8s_security.styles;

public enum Color {
    RED("\033[31m"),
    GREEN("\033[32m"),
    PURPLE("\033[35m"),
    BlUE(""),
    RESET("\033[0m");


    private final String color;

    Color(String color) {
        this.color = color;
    }

    public String getColor() {
        return color;
    }

}
