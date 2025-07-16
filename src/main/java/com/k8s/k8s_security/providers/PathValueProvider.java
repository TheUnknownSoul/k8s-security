package com.k8s.k8s_security.providers;

import org.springframework.shell.CompletionContext;
import org.springframework.shell.CompletionProposal;
import org.springframework.shell.standard.ValueProvider;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Component
public class PathValueProvider implements ValueProvider {

    @Override
    public List<CompletionProposal> complete(CompletionContext completionContext) {
        List<CompletionProposal> proposals = new ArrayList<>();
        String prefix = completionContext.currentWord() != null ? completionContext.currentWord() : "";
        File dir = new File(prefix.isEmpty() ? "." : prefix);
        File parent = dir.isDirectory() ? dir : dir.getParentFile();
        if (parent == null) {
            parent = new File(".");
        }
        File[] files = parent.listFiles();
        if (files != null) {
            for (File f : files) {
                proposals.add(new CompletionProposal(f.getPath()));
            }
        }
        return proposals;
    }
}
