package com.k8s.k8s_security.exceptions;

import org.springframework.shell.command.CommandRegistration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CommandNotFoundException extends RuntimeException {

    private final List<String> words;
    private final Map<String, CommandRegistration> registrations;
    private final String text;

    public CommandNotFoundException(List<String> words) {
        this(words, null, null);
    }

    public CommandNotFoundException(List<String> words, Map<String, CommandRegistration> registrations, String text) {
        this.words = words;
        this.registrations = registrations;
        this.text = text;
    }

    @Override
    public String getMessage() {
        return String.format("No command found for '%s'", String.join(" ", words));
    }

    /**
     * Gets a {@code words} in this exception.
     *
     * @return a words
     */
    public List<String> getWords(){
        return new ArrayList<>(words);
    }
    /**
     * Gets a raw text input.
     *
     * @return raw text input
     */
    public String getText() {
        return text;
    }
}
