package com.k8s.k8s_security.config;

import org.jline.utils.AttributedString;
import org.springframework.context.annotation.Configuration;
import org.springframework.shell.jline.PromptProvider;

@Configuration
public class PromptConfig implements PromptProvider {
    @Override
    public AttributedString getPrompt() {
        return new AttributedString("inspector:>");
    }
}
